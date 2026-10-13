#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
vanet_trace_parser_ns3.py
=========================

Parser batch (standard library only) untuk file trace ``.tr`` **NS-3 Native ASCII**
hasil simulasi komparasi AODV vs OLSR pada VANET (jalan lurus multi-hop, desain OFAT).

Fitur utama
-----------
* Ekstraksi metadata skenario dari nama file / path (regex):
  ``Protokol, Kondisi, Kelompok_OFAT, Variabel_Uji, Nilai_Variabel``.
* Format trace: NS-3 ASCII, baik trace MAC/queue (``+ / r / d``) maupun trace PHY Wi-Fi
  (``t / r`` dari ``YansWifiPhyHelper::EnableAscii``); jenis trace dideteksi otomatis.
* Isolasi trafik yang ketat:
    - Data legal  (UDP unicast, payload 512 B)  -> dasar metrik QoS
    - Serangan DoS -> counter terpisah. Paket dianggap DoS HANYA jika SEMUA terpenuhi:
        1. payload dalam [dos_size, dos_size + size_tol] (nominal 1.024 B),
        2. IP tujuan broadcast (255.255.255.255 / *.255),
        3. dos_start <= t <= dos_end (default 5-220 s),
        4. (opsional) sumber = --attacker-node / --attacker-ip.
    - Kontrol routing (UDP port 654 AODV / 698 OLSR) -> dasar metrik Non-QoS (RO/NRL)
* Metrik delay: rata-rata + median, P95, P99, maksimum (tahan terhadap outlier
  saat putus rute / rekonvergensi).
* Pemrosesan batch rekursif + tabel progres di terminal + ekspor CSV (pandas-ready).
* Baris trace korup tidak menghentikan eksekusi (dihitung di ``Lines_Corrupt``).

Catatan interpretasi metrik
---------------------------
* ``DoS_Packets_Detected`` : jumlah paket DoS UNIK yang dipancarkan penyerang.
* ``DoS_Rx_Events``        : total event penerimaan PHY paket DoS di SELURUH receiver
  (1 broadcast yang didengar 5 tetangga = 5 event). Ini ukuran beban kanal, bukan
  jumlah paket unik.
* ``DoS_Unique_Packets_Recv`` : paket DoS unik yang diterima >= 1 node non-penyerang.
* ``Legal_Drop_Events``    : hanya tersedia pada trace MAC/queue (event ``d``). Trace PHY
  Wi-Fi tidak mencatat drop, sehingga kolom ini berisi ``N/A`` (terbaca NaN oleh pandas).
  Kehilangan paket tetap dihitung akurat lewat ``Legal_Lost = Legal_Sent - Legal_Received``
  dan ``PLR_pct``.
* Kunci paket unik = (src, dst, sport, dport, IP-ID, epoch). ``SeqNumber`` MAC 802.11
  TIDAK dipakai karena berubah di setiap hop (counter per-transmitter). Untuk mengatasi
  wrap IP-ID 16-bit, IP-ID yang muncul lagi setelah jeda > ``--id-reuse-window`` detik
  dianggap paket baru (epoch baru).
* Penerimaan legal hanya sah jika ``DA(RA)`` frame = MAC node tujuan. Baris tanpa
  ``DA(RA)`` TIDAK dihitung dan dilaporkan di ``Meta_Warning``.

Konvensi penamaan yang dikenali (case-insensitive, boleh ada di nama file
maupun nama folder; nama file diprioritaskan)
---------------------------------------------------------------------------
    Protokol    : aodv | olsr
    Kondisi     : normal | dos | ddos | attack | flood(ing) | serangan | no_dos ...
    Kepadatan   : n20, node20, 20node, 20nodes, veh20, kepadatan20
    Jarak       : d300, dist300, jarak300, spacing300, 300m
    Kecepatan   : v30, speed30, kec30, 30kmh, 30kmph, 30km_h
    Heterogenitas : hetero, heterogen, acak, 15_25, 15to25, randspeed, speedvar
    Kelompok    : kelompok_A, group_B, klp_C, grp_D (dipakai sebagai petunjuk)
    Run/seed    : seed1, run2, rep3

Contoh nama valid: ``Kelompok_A/aodv_dos_n20_d200_v20.tr``,
``results/OLSR-Normal-jarak400m-20kmh.tr``, ``D/aodv_normal_hetero_run3.tr``.
Pola regex terpusat di ``META_PATTERNS`` sehingga mudah disesuaikan.

Contoh pemakaian
----------------
    python vanet_trace_parser_ns3.py -d ./hasil_simulasi -o metrik_vanet.csv
    python vanet_trace_parser_ns3.py -d ./run1 ./run2 -f extra.tr --duration 222
    python vanet_trace_parser_ns3.py -d ./ns3 --dos-start 5 --dos-end 220 --attacker-node 9
"""

from __future__ import annotations

import argparse
import csv
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Sequence, Set, Tuple

# ---------------------------------------------------------------------------
# Konstanta & konfigurasi
# ---------------------------------------------------------------------------

#: Parameter baseline desain OFAT.
BASELINE = {"nodes": 10, "dist": 200, "speed": 20}

#: Pemetaan variabel -> (Kelompok, Nama Variabel Uji).
GROUP_OF = {
    "nodes": ("A", "Kepadatan"),
    "dist": ("B", "Jarak"),
    "speed": ("C", "Kecepatan"),
}
VAR_OF_GROUP = {"A": "nodes", "B": "dist", "C": "speed"}
GROUP_ORDER = {"Baseline": 0, "A": 1, "B": 2, "C": 3, "D": 4, "Unknown": 9}

#: Port kontrol routing pada NS-3 (AODV=654, OLSR=698).
ROUTING_PORTS = {654: "AODV", 698: "OLSR"}

LEGAL, DOS, OTHER = "legal", "dos", "other"

#: Format CSV 100% identik dengan schema output simulasi NS-3 (17 kolom).
SIM_CSV_FIELDS = [
    "protocol",
    "scenario",
    "totalNodes",
    "legitCount",
    "numAttackers",
    "simTime",
    "attackDataRate",
    "dataTxPackets",
    "dataRxPackets",
    "dataLostPackets",
    "PDR_percent",
    "PLR_percent",
    "avgDelay_ms",
    "throughput_kbps",
    "routingOverhead_packets",
    "NRL",
    "attackPacketsSent",
]

#: Format CSV lengkap (39 kolom, mencakup OFAT metadata, audit trace, dan distribusi delay).
FULL_CSV_FIELDS = [
    "File", "Path",
    "Protokol", "Kondisi", "Kelompok_OFAT", "Variabel_Uji", "Nilai_Variabel",
    "Jumlah_Node", "Jarak_m", "Kecepatan_kmh", "Run",
    "Legal_Sent", "Legal_Received", "Legal_Lost",
    "PDR_pct", "PLR_pct",
    "Avg_Delay_ms", "Median_Delay_ms", "P95_Delay_ms", "P99_Delay_ms", "Max_Delay_ms",
    "Throughput_kbps", "Active_Duration_s",
    "Routing_Packets_Sent", "Routing_Bytes_Sent", "Routing_Overhead", "NRL",
    "DoS_Packets_Detected", "DoS_Rx_Events", "DoS_Unique_Packets_Recv",
    "Legal_Drop_Events", "Unmatched_Legal_Recv", "Duplicate_Events",
    "Lines_Total", "Lines_Ignored", "Lines_Corrupt",
    "Status", "Meta_Warning", "First_Corrupt_Line",
]

CSV_FIELDS = SIM_CSV_FIELDS


@dataclass
class Config:
    """Parameter klasifikasi & perhitungan.

    Attributes:
        legal_size: Ukuran payload UDP data legal (byte).
        dos_size: Ukuran payload UDP paket flooding DoS (byte).
        size_tol: Toleransi (byte) di atas payload nominal, untuk header
            tambahan aplikasi (mis. SeqTsHeader 12 B pada UdpClient).
        ip_offset: ``node_id = oktet_terakhir_IP - ip_offset``
            (default 1: 10.1.1.1 -> node 0).
        duration: Jika diisi, dipakai sebagai "Durasi Aktif" tetap (detik)
            untuk throughput. Jika None, dihitung otomatis dari trace.
        dos_start, dos_end: Jendela waktu serangan (detik). Broadcast ~1.024 B di luar
            jendela ini TIDAK dihitung sebagai DoS.
        attacker_node: (opsional) ID node penyerang; sumber paket DoS harus cocok.
        attacker_ip: (opsional) IP penyerang; sumber paket DoS harus cocok.
        id_reuse_window: Jeda (detik) setelah mana IP-ID yang sama dianggap paket baru
            (mitigasi wrap IP-ID 16-bit).
        extensions: Ekstensi file trace yang dipindai.
    """
    legal_size: int = 512
    dos_size: int = 1024
    size_tol: int = 60
    ip_offset: int = 1
    duration: Optional[float] = None
    dos_start: float = 5.0
    dos_end: float = 220.0
    attacker_node: Optional[int] = None
    attacker_ip: Optional[str] = None
    id_reuse_window: float = 60.0
    extensions: Tuple[str, ...] = (".tr",)


# ---------------------------------------------------------------------------
# 1. Ekstraksi metadata (OFAT mapping)
# ---------------------------------------------------------------------------

META_PATTERNS = {
    "protocol": re.compile(r"(?<![a-z])(aodv|olsr)(?![a-z])"),
    "normal": re.compile(
        r"(?<![a-z])(normal|no[_\-]?dos|non[_\-]?dos|no[_\-]?attack|noattack|"
        r"benign|clean|tanpa[_\-]?serangan|without[_\-]?dos)(?![a-z])"),
    "dos": re.compile(
        r"(?<![a-z])(dos|ddos|attack(?:er|ed)?|flood(?:ing)?|serangan)(?![a-z])"),
    "nodes": [
        re.compile(r"(?<![a-z\d])(?:nodes?|veh|kepadatan|density|nd|n)[_\-=]?(\d+)(?![\d])"),
        re.compile(r"(?<![a-z\d])(\d+)[_\-]?(?:nodes?|veh(?:icles?)?|kendaraan|nd)(?![a-z])"),
    ],
    "dist": [
        re.compile(r"(?<![a-z\d])(?:dist(?:ance)?|jarak|spacing|gap|d)[_\-=]?(\d+)(?:m)?(?![a-z\d])"),
        re.compile(r"(?<![a-z\d.])(\d+)[_\-]?m(?![a-z\d])"),
    ],
    "speed": [
        re.compile(r"(?<![a-z\d])(?:speed|spd|kecepatan|kec|v)[_\-=]?(\d+)(?:kmh|kmph|kmj|kph|km)?(?![\d])"),
        re.compile(r"(?<![a-z\d.])(\d+)[_\-]?(?:km[_/\-]?h|kmph|kmj|kph|km)(?![a-z])"),
    ],
    "hetero": re.compile(
        r"hetero|acak|15[_\-]?(?:to|sd)?[_\-]?25|rand(?:om)?[_\-]?speed|speedvar|mixed[_\-]?speed"),
    "hint": re.compile(r"(?<![a-z])(?:kelompok|klp|group|grp)[_\-\s]?([abcd])(?![a-z])"),
    "run": re.compile(r"(?<![a-z])(?:seed|run|rep|ulangan)[_\-]?(\d+)"),
}


@dataclass
class ScenarioMeta:
    """Metadata skenario hasil ekstraksi nama file/path."""
    protokol: str = "Unknown"
    kondisi: str = "Unknown"
    kelompok: str = "Unknown"
    variabel: str = "Unknown"
    nilai: str = ""
    nodes: Optional[int] = None
    dist: Optional[int] = None
    speed: str = ""
    run: str = ""
    warnings: List[str] = field(default_factory=list)

    def sort_key(self) -> Tuple:
        """Kunci pengurutan baris CSV: kelompok, nilai numerik, protokol, kondisi."""
        num = 0.0
        try:
            if self.kelompok == "A":
                num = float(self.nodes or 0)
            elif self.kelompok == "B":
                num = float(self.dist or 0)
            elif self.kelompok == "C":
                num = float(self.speed or 0)
        except ValueError:
            num = 0.0
        return (GROUP_ORDER.get(self.kelompok, 9), num, self.protokol, self.kondisi)


def _segments(path: Path, root: Optional[Path]) -> List[str]:
    """Daftar segmen teks (huruf kecil) dengan prioritas: nama file > folder terdekat > root."""
    segs = [path.stem.lower()]
    try:
        rel = path.resolve().relative_to(root.resolve()) if root else None
    except ValueError:
        rel = None
    parents = list(rel.parent.parts) if rel is not None else list(path.parent.parts[-3:])
    segs += [p.lower() for p in reversed(parents)]
    if root is not None:
        segs.append(root.name.lower())
    return segs


def _first_numeric(segs: Sequence[str], regexes: Sequence["re.Pattern[str]"]) -> Optional[int]:
    for seg in segs:
        for rx in regexes:
            m = rx.search(seg)
            if m:
                return int(m.group(1))
    return None


def extract_metadata(path: Path, root: Optional[Path] = None) -> ScenarioMeta:
    """Ekstrak metadata OFAT dari nama file dan path.

    Aturan penentuan kelompok:
      1. Terdeteksi heterogenitas kecepatan (atau petunjuk kelompok D) -> ``D``.
      2. Tepat satu parameter menyimpang dari baseline (10 node/200 m/20 km/jam)
         -> A (Kepadatan) / B (Jarak) / C (Kecepatan).
      3. Tidak ada yang menyimpang -> ``Baseline``; kecuali path memuat petunjuk
         ``kelompok_A/B/C`` (titik baseline sebagai bagian deret grup tersebut).
      4. Lebih dari satu menyimpang -> pakai petunjuk jika konsisten, else ``Unknown``.

    Args:
        path: Path file trace.
        root: Folder akar pencarian (agar folder di atas root tidak ikut diparsing).

    Returns:
        ScenarioMeta terisi (``warnings`` berisi bidang yang tidak terdeteksi/ambigu).
    """
    meta = ScenarioMeta()
    segs = _segments(path, root)

    for seg in segs:
        m = META_PATTERNS["protocol"].search(seg)
        if m:
            meta.protokol = m.group(1).upper()
            break
    for seg in segs:
        if META_PATTERNS["normal"].search(seg):
            meta.kondisi = "Normal"
            break
        if META_PATTERNS["dos"].search(seg):
            meta.kondisi = "DoS"
            break

    nodes = _first_numeric(segs, META_PATTERNS["nodes"])
    dist = _first_numeric(segs, META_PATTERNS["dist"])
    speed = _first_numeric(segs, META_PATTERNS["speed"])
    hint = None
    for seg in segs:
        m = META_PATTERNS["hint"].search(seg)
        if m:
            hint = m.group(1).upper()
            break
    hetero = any(META_PATTERNS["hetero"].search(s) for s in segs) or hint == "D"
    for seg in segs:
        m = META_PATTERNS["run"].search(seg)
        if m:
            meta.run = m.group(1)
            break

    if nodes is None and dist is None and speed is None and not hetero and hint is None:
        meta.warnings.append("parameter OFAT tidak terdeteksi (diasumsikan baseline)")

    meta.nodes = nodes if nodes is not None else BASELINE["nodes"]
    meta.dist = dist if dist is not None else BASELINE["dist"]
    values = {"nodes": meta.nodes, "dist": meta.dist,
              "speed": speed if speed is not None else BASELINE["speed"]}

    if hetero:
        meta.kelompok, meta.variabel, meta.nilai = "D", "Heterogenitas", "15-25 km/jam"
        meta.speed = "15-25"
        return _finalize_meta(meta)

    meta.speed = str(values["speed"])
    diffs = [k for k in ("nodes", "dist", "speed") if values[k] != BASELINE[k]]

    if len(diffs) == 1:
        key = diffs[0]
        meta.kelompok, meta.variabel = GROUP_OF[key]
        meta.nilai = str(values[key])
        if hint and hint != meta.kelompok:
            meta.warnings.append(f"petunjuk kelompok {hint} != hasil nilai ({meta.kelompok})")
    elif not diffs:
        if hint in VAR_OF_GROUP:
            key = VAR_OF_GROUP[hint]
            meta.kelompok, meta.variabel = GROUP_OF[key]
            meta.nilai = str(values[key])
        else:
            meta.kelompok, meta.variabel = "Baseline", "Baseline"
            meta.nilai = f"{BASELINE['nodes']} node/{BASELINE['dist']} m/{BASELINE['speed']} km/jam"
    else:
        if hint in VAR_OF_GROUP and VAR_OF_GROUP[hint] in diffs:
            key = VAR_OF_GROUP[hint]
            meta.kelompok, meta.variabel = GROUP_OF[key]
            meta.nilai = str(values[key])
        else:
            meta.kelompok, meta.variabel = "Unknown", "Unknown"
            meta.nilai = "/".join(f"{k}={values[k]}" for k in diffs)
        meta.warnings.append("lebih dari satu parameter menyimpang dari baseline (bukan OFAT)")
    return _finalize_meta(meta)


def _finalize_meta(meta: ScenarioMeta) -> ScenarioMeta:
    if meta.protokol == "Unknown":
        meta.warnings.append("protokol tidak terdeteksi dari nama (fallback ke isi trace)")
    if meta.kondisi == "Unknown":
        meta.warnings.append("kondisi tidak terdeteksi dari nama (fallback ke isi trace)")
    return meta


# ---------------------------------------------------------------------------
# 2. Akumulator metrik
# ---------------------------------------------------------------------------

def is_broadcast_ip(dst: str) -> bool:
    """True untuk broadcast terbatas (255.255.255.255) atau subnet-directed (*.255)."""
    return dst == "255.255.255.255" or dst.endswith(".255")


def ip_to_node(ip: str, cfg: Config) -> int:
    """Konversi IP ke ID node: oktet terakhir - ``ip_offset``."""
    return int(ip.rsplit(".", 1)[1]) - cfg.ip_offset


def in_dos_size(size: int, cfg: Config) -> bool:
    return cfg.dos_size <= size <= cfg.dos_size + cfg.size_tol


def is_attacker_src(src: str, cfg: Config) -> bool:
    """True jika ``src`` cocok dengan filter penyerang (atau tidak ada filter)."""
    if cfg.attacker_ip is not None and src != cfg.attacker_ip:
        return False
    if cfg.attacker_node is not None and ip_to_node(src, cfg) != cfg.attacker_node:
        return False
    return True


def classify_payload(size: int, src: str, dst: str, t: float, cfg: Config) -> str:
    """Klasifikasikan paket data UDP (non-routing) menjadi LEGAL / DOS / OTHER.

    * DOS   : broadcast DAN payload ~1.024 B DAN ``dos_start <= t <= dos_end``
              DAN (jika difilter) sumber = penyerang. Semua syarat wajib.
    * LEGAL : unicast DAN payload ~512 B.
    * OTHER : selain itu (mis. broadcast ~1.024 B di luar jendela serangan,
              broadcast 512 B, unicast 1.024 B) -> tidak dihitung di metrik mana pun.
    """
    if is_broadcast_ip(dst):
        if (in_dos_size(size, cfg) and cfg.dos_start <= t <= cfg.dos_end
                and is_attacker_src(src, cfg)):
            return DOS
        return OTHER
    if cfg.legal_size <= size <= cfg.legal_size + cfg.size_tol:
        return LEGAL
    return OTHER


def percentile(sorted_vals: Sequence[float], p: float) -> Optional[float]:
    """Persentil ke-``p`` (0-100) dengan interpolasi linear antar titik data.

    Metode sama dengan ``numpy.percentile(..., method='linear')`` sehingga hasil
    konsisten jika diverifikasi ulang dengan numpy/pandas.

    Args:
        sorted_vals: data yang SUDAH terurut naik.
        p: persentil 0-100.
    """
    n = len(sorted_vals)
    if n == 0:
        return None
    if n == 1:
        return float(sorted_vals[0])
    k = (n - 1) * p / 100.0
    lo = int(k)
    hi = min(lo + 1, n - 1)
    return sorted_vals[lo] + (sorted_vals[hi] - sorted_vals[lo]) * (k - lo)


class Accumulator:
    """Menyimpan counter terpisah untuk trafik legal, DoS, dan kontrol routing.

    Args:
        cfg: konfigurasi.
        phy_mode: True jika trace PHY Wi-Fi (tanpa event drop) -> ``Legal_Drop_Events = N/A``.
    """

    def __init__(self, cfg: Config, phy_mode: bool = False) -> None:
        self.cfg = cfg
        self.phy_mode = phy_mode
        # legal
        self.legal_send_t: Dict[object, float] = {}
        self.legal_received: Set[object] = set()
        self.delays: List[float] = []          # detik, per paket legal diterima
        self.legal_drop = 0
        self.unmatched_recv = 0
        self.duplicates = 0
        self.missing_da = 0                    # baris terima legal tanpa DA(RA)
        # DoS
        self.dos_keys: Set[object] = set()
        self.dos_unique_recv: Set[object] = set()
        self.dos_rx_events = 0
        self.dos_rejected = 0                  # broadcast ~1.024 B yang gagal kriteria DoS
        # routing
        self.routing_tx_count = 0
        self.routing_bytes = 0
        # lain-lain
        self._epoch: Dict[Tuple, List] = {}    # base-key -> [epoch, t_tx_terakhir]
        self.id_reuse = 0
        self.t_first_send: Optional[float] = None
        self.t_last: Optional[float] = None
        self.protocols: Set[str] = set()

    # -- kunci paket unik (mitigasi wrap IP-ID) -------------------------------
    def resolve_key(self, base: Tuple, t: float, is_tx: bool) -> Tuple:
        """Tambahkan nomor epoch ke kunci dasar ``(src, dst, sport, dport, ip_id)``.

        Pada event TX, jika kunci dasar terakhir terlihat lebih dari
        ``id_reuse_window`` detik lalu, IP-ID dianggap sudah wrap -> epoch baru.
        Transmisi forwarder/retry (jeda singkat) tetap di epoch yang sama.
        Event RX selalu dipetakan ke epoch aktif saat ini.
        """
        ent = self._epoch.get(base)
        if not is_tx:
            return base + ((ent[0] if ent else 0),)
        if ent is None:
            self._epoch[base] = [0, t]
            return base + (0,)
        if t - ent[1] > self.cfg.id_reuse_window:
            ent[0] += 1
            self.id_reuse += 1
        ent[1] = t
        return base + (ent[0],)

    # -- trafik legal ------------------------------------------------------
    def legal_send(self, key: object, t: float) -> None:
        if key in self.legal_send_t:
            self.duplicates += 1
            return
        self.legal_send_t[key] = t
        if self.t_first_send is None or t < self.t_first_send:
            self.t_first_send = t
        if self.t_last is None or t > self.t_last:
            self.t_last = t

    def legal_recv_evt(self, key: object, t: float) -> None:
        t0 = self.legal_send_t.get(key)
        if t0 is None:
            self.unmatched_recv += 1
            return
        if key in self.legal_received:
            self.duplicates += 1
            return
        if t < t0:
            raise ValueError("waktu terima < waktu kirim (baris korup)")
        self.legal_received.add(key)
        self.delays.append(t - t0)
        if self.t_last is None or t > self.t_last:
            self.t_last = t

    def legal_drop_if_known(self, key: object) -> None:
        if key in self.legal_send_t:
            self.legal_drop += 1

    # -- trafik DoS (terisolasi) ---------------------------------------------
    def dos_send(self, key: object) -> None:
        if key not in self.dos_keys:
            self.dos_keys.add(key)

    def dos_rx_evt(self, key: object, rx_node: int, src_node: int) -> None:
        """Catat SATU event penerimaan PHY paket DoS (bisa banyak per paket broadcast).

        Paket juga dicatat sebagai "unik diterima" jika receiver bukan pengirim dan
        bukan node penyerang yang dikonfigurasi.
        """
        self.dos_rx_events += 1
        if rx_node != src_node and rx_node != self.cfg.attacker_node:
            self.dos_unique_recv.add(key)

    # -- kontrol routing ---------------------------------------------------
    def routing_tx(self, size: int) -> None:
        self.routing_tx_count += 1
        self.routing_bytes += max(size, 0)

    # -- hasil akhir -------------------------------------------------------
    def metrics(self) -> Dict[str, object]:
        """Hitung seluruh metrik QoS & Non-QoS. Rasio dengan penyebut 0 -> ``None``."""
        sent, recv = len(self.legal_send_t), len(self.legal_received)
        if self.cfg.duration:
            duration: Optional[float] = float(self.cfg.duration)
        elif self.t_first_send is not None and self.t_last is not None:
            duration = self.t_last - self.t_first_send
        else:
            duration = None
        d_ms = sorted(d * 1000.0 for d in self.delays)
        pdr = recv / sent * 100.0 if sent else None
        plr = (sent - recv) / sent * 100.0 if sent else None
        thr = (recv * self.cfg.legal_size * 8.0) / (duration * 1000.0) if duration and duration > 0 else None
        ro = self.routing_tx_count / sent if sent else None
        nrl = self.routing_tx_count / recv if recv else None
        return {
            "Legal_Sent": sent, "Legal_Received": recv, "Legal_Lost": sent - recv,
            "PDR_pct": pdr, "PLR_pct": plr,
            "Avg_Delay_ms": sum(d_ms) / len(d_ms) if d_ms else None,
            "Median_Delay_ms": percentile(d_ms, 50),
            "P95_Delay_ms": percentile(d_ms, 95),
            "P99_Delay_ms": percentile(d_ms, 99),
            "Max_Delay_ms": d_ms[-1] if d_ms else None,
            "Throughput_kbps": thr, "Active_Duration_s": duration,
            "Routing_Packets_Sent": self.routing_tx_count,
            "Routing_Bytes_Sent": self.routing_bytes,
            "Routing_Overhead": ro, "NRL": nrl,
            "DoS_Packets_Detected": len(self.dos_keys),
            "DoS_Rx_Events": self.dos_rx_events,
            "DoS_Unique_Packets_Recv": len(self.dos_unique_recv),
            "Legal_Drop_Events": "N/A" if self.phy_mode else self.legal_drop,
            "Unmatched_Legal_Recv": self.unmatched_recv,
            "Duplicate_Events": self.duplicates,
        }


# ---------------------------------------------------------------------------
# 3. Parser NS-3 Native ASCII Trace
# ---------------------------------------------------------------------------

#: Header event NS-3. Mendukung dua varian:
#:   MAC/queue trace : ``+ 1.23 /NodeList/0/...``
#:   PHY Wi-Fi trace : ``t 1.23 /NodeList/0/.../Phy/State/Tx OfdmRate6Mbps ...``
#:                     ``r 1.23 OfdmRate6Mbps /NodeList/1/.../Phy/State/RxOk ...``
#: (pada baris ``r`` PHY, token rate muncul SEBELUM path ``/NodeList``).
_NS3_HEAD = re.compile(r"^([+\-rdt])\s+(\S+)\s+(?:[^/\s]\S*\s+)?/NodeList/(\d+)/")
_NS3_DA = re.compile(r"DA\(RA\)=([0-9a-fA-F:]{17})")
_NS3_RETRY = re.compile(r"Retry=1")
_NS3_IPV4 = re.compile(
    r"ns3::Ipv4Header\s*\((.*?)length:\s*(\d+)\s+(\d+\.\d+\.\d+\.\d+)\s*>\s*(\d+\.\d+\.\d+\.\d+)\)")
_NS3_PROTO = re.compile(r"protocol\s+(\d+)")
_NS3_ID = re.compile(r"\bid\s+(\d+)")
_NS3_UDP = re.compile(r"ns3::UdpHeader\s*\(length:\s*(\d+)\s+(\d+)\s*>\s*(\d+)\)")
_NS3_PAYLOAD = re.compile(r"Payload\s*\((?:size=)?(\d+)\)")


def _parse_ns3_time(tok: str) -> float:
    """Parse waktu NS-3: ``2.5``, ``+2.5s``, ``+2.5e+09ns`` -> detik."""
    tok = tok.lstrip("+")
    for suffix, mul in (("ns", 1e-9), ("us", 1e-6), ("ms", 1e-3), ("s", 1.0)):
        if tok.endswith(suffix):
            return float(tok[:-len(suffix)]) * mul
    return float(tok)


def _mac_to_int(mac: str) -> int:
    return int(mac.replace(":", ""), 16)


class Ns3Parser:
    """Parser NS-3 ASCII trace (MAC/queue ``+``/``r``/``d`` atau PHY Wi-Fi ``t``/``r``).

    Semantik:
      * Kirim  : event TX pertama (``+`` atau ``t``) untuk paket unik
                 (kunci: src,dst,sport,dport,IP-id,epoch); transmisi forwarder & retry diabaikan.
      * Terima : event ``r`` di node tujuan akhir (node = oktet terakhir IP tujuan - ip_offset)
                 DAN ``DA(RA)`` frame = MAC node tersebut. Ini mengeliminasi overhearing di
                 trace PHY (RxOk tercatat di semua node yang mendengar). Baris tanpa
                 ``DA(RA)`` ditolak dan dihitung di ``Accumulator.missing_da``.
      * Kontrol: setiap event TX dengan port UDP 654 (AODV) / 698 (OLSR) per hop,
                 tidak termasuk retransmisi MAC (``Retry=1``).
      * DoS    : lihat :func:`classify_payload`. Setiap ``r`` paket DoS = 1 ``DoS_Rx_Events``.

    Args:
        cfg: konfigurasi.
        tx_event: ``'+'`` (trace MAC/queue) atau ``'t'`` (trace PHY). Dipilih otomatis
            oleh :func:`check_ns3_format` agar paket tidak terhitung dua kali.
    """

    def __init__(self, cfg: Config, tx_event: str = "+") -> None:
        self.cfg = cfg
        self.tx_event = tx_event

    def _addressed_to(self, mac_part: str, node: int, acc: Accumulator) -> bool:
        """True HANYA jika ``DA(RA)`` ada dan sama dengan MAC ``node``.

        Jika ``DA(RA)`` tidak ditemukan, frame TIDAK diasumsikan valid; kejadian ini
        dicatat di ``acc.missing_da`` dan dilaporkan sebagai peringatan.
        """
        da = _NS3_DA.search(mac_part)
        if not da:
            acc.missing_da += 1
            return False
        return _mac_to_int(da.group(1)) - self.cfg.ip_offset == node

    def feed(self, line: str, acc: Accumulator) -> bool:
        """Proses satu baris. Return False jika baris tak relevan; raise jika korup."""
        m = _NS3_HEAD.match(line)
        if not m:
            if "/NodeList/" in line:
                raise ValueError("header NS-3 tidak valid")
            return False
        ev, ts, node = m.group(1), m.group(2), int(m.group(3))
        t = _parse_ns3_time(ts)
        if t < 0:
            raise ValueError("waktu negatif")
        if ev == self.tx_event:
            ev = "tx"
        elif ev not in ("r", "d"):
            return False                       # mis. '-' (dequeue) atau 't' di trace MAC
        rest = line[m.end():]

        ip = _NS3_IPV4.search(rest)
        if not ip:
            return False                       # ARP, ACK MAC, frame MAC-only, dsb.
        mac_part = rest[:ip.start()]           # WifiMacHeader (DA, Retry, SeqNumber)
        body, ip_len = ip.group(1), int(ip.group(2))
        src, dst = ip.group(3), ip.group(4)
        pm = _NS3_PROTO.search(body)
        if not pm or int(pm.group(1)) != 17:
            return False                       # bukan UDP
        udp = _NS3_UDP.search(rest, ip.end())
        if not udp:
            raise ValueError("Ipv4 UDP tanpa UdpHeader")
        udp_len, sport, dport = int(udp.group(1)), int(udp.group(2)), int(udp.group(3))

        # --- kontrol routing (Non-QoS) ---
        ctl = ROUTING_PORTS.get(sport) or ROUTING_PORTS.get(dport)
        if ctl:
            acc.protocols.add(ctl)
            if ev == "tx" and not _NS3_RETRY.search(mac_part):
                acc.routing_tx(ip_len)
            return True

        # --- trafik data: legal vs DoS ---
        pl = _NS3_PAYLOAD.search(rest, udp.end())
        size = int(pl.group(1)) if pl else max(udp_len - 8, 0)
        idm = _NS3_ID.search(body)
        base = (src, dst, sport, dport, idm.group(1) if idm else "0")
        cls = classify_payload(size, src, dst, t, self.cfg)

        if cls == OTHER:
            if ev == "tx" and is_broadcast_ip(dst) and in_dos_size(size, self.cfg):
                acc.dos_rejected += 1          # kandidat DoS yang gagal kriteria waktu/attacker
            return True

        key = acc.resolve_key(base, t, ev == "tx")
        if ev == "tx":
            if cls == LEGAL:
                if key in acc.legal_send_t:
                    return True                # forwarder / retry: bukan pengiriman baru
                acc.legal_send(key, t)
            else:
                acc.dos_send(key)
        elif ev == "r":
            if cls == LEGAL:
                if (node == ip_to_node(dst, self.cfg)
                        and self._addressed_to(mac_part, node, acc)):
                    acc.legal_recv_evt(key, t)
            else:
                acc.dos_rx_evt(key, node, ip_to_node(src, self.cfg))
        elif ev == "d" and cls == LEGAL:
            acc.legal_drop_if_known(key)
        return True


# ---------------------------------------------------------------------------
# 4. Pemrosesan file & batch
# ---------------------------------------------------------------------------

def check_ns3_format(path: Path) -> str:
    """Pastikan file adalah NS-3 ASCII trace dan tentukan event TX yang dipakai.

    Returns:
        ``'+'`` jika trace memuat event enqueue (trace MAC/queue), selain itu ``'t'``
        (trace PHY Wi-Fi dari ``YansWifiPhyHelper::EnableAscii``).

    Raises:
        ValueError: jika tidak ditemukan satu pun baris berformat NS-3.
    """
    scanned = 0
    events: Set[str] = set()
    with path.open("r", encoding="utf-8", errors="replace") as fh:
        for raw in fh:
            s = raw.strip()
            if not s or s[0] == "#":
                continue
            m = _NS3_HEAD.match(s)
            if m:
                events.add(m.group(1))
            scanned += 1
            if scanned >= 20000:
                break
    if not events:
        raise ValueError("bukan NS-3 ASCII trace (tidak ada baris '/NodeList/...')")
    return "+" if "+" in events else "t"


def process_trace(path: Path, cfg: Config, root: Optional[Path] = None) -> Dict[str, object]:
    """Proses satu file trace menjadi satu baris hasil (dict sesuai ``CSV_FIELDS``).

    Pengecualian dari parsing per-baris ditangkap sehingga satu baris korup
    tidak menggagalkan seluruh file. Error fatal (mis. file tak terbaca) di-raise.
    """
    meta = extract_metadata(path, root)
    tx_event = check_ns3_format(path)
    phy_mode = tx_event == "t"
    parser = Ns3Parser(cfg, tx_event)
    acc = Accumulator(cfg, phy_mode=phy_mode)
    total = ignored = corrupt = 0
    first_error = ""

    with path.open("r", encoding="utf-8", errors="replace") as fh:
        for raw in fh:
            line = raw.strip()
            if not line or line[0] == "#":
                continue
            total += 1
            try:
                if not parser.feed(line, acc):
                    ignored += 1
            except Exception as exc:           # noqa: BLE001 - toleran terhadap baris korup
                corrupt += 1
                if not first_error:
                    first_error = f"{type(exc).__name__}: {exc} @ '{line[:50]}'"

    # Fallback metadata dari isi trace
    n_dos = len(acc.dos_keys)
    if meta.protokol == "Unknown" and len(acc.protocols) == 1:
        meta.protokol = next(iter(acc.protocols))
    if meta.kondisi == "Unknown":
        meta.kondisi = "DoS" if n_dos > 0 else "Normal"
    if meta.kondisi == "Normal" and n_dos > 0:
        meta.warnings.append(f"kondisi Normal tetapi {n_dos} paket DoS terdeteksi")
    if meta.kondisi == "DoS" and n_dos == 0:
        meta.warnings.append("kondisi DoS tetapi tidak ada paket DoS terdeteksi")
    if meta.protokol in ("AODV", "OLSR") and acc.protocols and meta.protokol not in acc.protocols:
        meta.warnings.append(f"protokol nama file {meta.protokol} != isi trace {sorted(acc.protocols)}")

    # Peringatan integritas klasifikasi
    if acc.dos_rejected:
        meta.warnings.append(
            f"{acc.dos_rejected} paket broadcast ~{cfg.dos_size} B ditolak sebagai DoS "
            f"(di luar jendela {cfg.dos_start:g}-{cfg.dos_end:g} s atau bukan penyerang)")
    if acc.missing_da:
        meta.warnings.append(
            f"{acc.missing_da} event terima legal tanpa DA(RA) tidak dihitung (tidak bisa "
            f"diverifikasi bukan overhearing)")
    if acc.id_reuse:
        meta.warnings.append(
            f"{acc.id_reuse} IP-ID dipakai ulang setelah > {cfg.id_reuse_window:g} s "
            f"(dipisahkan sebagai paket baru)")

    status = "OK"
    lost = len(acc.legal_send_t) - len(acc.legal_received)
    if len(acc.legal_send_t) == 0:
        status = "WARN: tidak ada paket legal terdeteksi (cek --ip-offset / --legal-size)"
    elif total and corrupt / total > 0.5:
        status = "WARN: >50% baris korup"
    elif corrupt:
        status = f"OK ({corrupt} baris korup diabaikan)"
    if phy_mode and lost > 0 and not status.startswith("WARN"):
        status += " [PHY: tanpa event drop, loss = Sent - Received]"

    row: Dict[str, object] = {
        "File": path.name, "Path": str(path),
        "Protokol": meta.protokol, "Kondisi": meta.kondisi,
        "Kelompok_OFAT": meta.kelompok, "Variabel_Uji": meta.variabel,
        "Nilai_Variabel": meta.nilai, "Jumlah_Node": meta.nodes,
        "Jarak_m": meta.dist, "Kecepatan_kmh": meta.speed, "Run": meta.run,
        "Lines_Total": total, "Lines_Ignored": ignored, "Lines_Corrupt": corrupt,
        "Status": status, "Meta_Warning": "; ".join(meta.warnings),
        "First_Corrupt_Line": first_error,
    }
    row.update(acc.metrics())
    row["_sort"] = meta.sort_key()
    return row


def discover_files(dirs: Iterable[str], files: Iterable[str],
                   extensions: Sequence[str]) -> List[Tuple[Path, Optional[Path]]]:
    """Kumpulkan file trace (rekursif untuk folder). Return list ``(file, root)`` unik & terurut."""
    found: Dict[Path, Optional[Path]] = {}
    exts = tuple(e.lower() for e in extensions)
    for d in dirs:
        root = Path(d)
        if not root.is_dir():
            print(f"[!] Folder tidak ditemukan: {root}", file=sys.stderr)
            continue
        for p in root.rglob("*"):
            if p.is_file() and p.suffix.lower() in exts:
                found.setdefault(p.resolve(), root)
    for f in files:
        p = Path(f)
        if p.is_file():
            found.setdefault(p.resolve(), None)
        else:
            print(f"[!] File tidak ditemukan: {p}", file=sys.stderr)
    return sorted(found.items(), key=lambda kv: str(kv[0]).lower())


def _fmt(v: object, nd: int = 2) -> str:
    if v is None or v == "":
        return "-"
    if isinstance(v, float):
        return f"{v:.{nd}f}"
    return str(v)


_TABLE_HEAD = (f"{'#':>7} {'File':<30} {'Proto':<5} {'Kond':<6} {'Grp':<8} {'Nilai':<12} "
               f"{'Sent':>7} {'Recv':>7} {'PDR%':>7} {'Avg(ms)':>8} {'Med(ms)':>8} {'P95(ms)':>8} "
               f"{'Thr(kbps)':>9} {'NRL':>7} {'DoS':>7}  Status")


def _print_row(idx: int, total: int, row: Dict[str, object]) -> None:
    name = str(row["File"])
    name = name if len(name) <= 30 else "..." + name[-27:]
    nilai = str(row["Nilai_Variabel"])
    nilai = nilai if len(nilai) <= 12 else nilai[:11] + "~"
    print(f"{f'{idx}/{total}':>7} {name:<30} {str(row['Protokol']):<5} {str(row['Kondisi']):<6} "
          f"{str(row['Kelompok_OFAT']):<8} {nilai:<12} "
          f"{_fmt(row.get('Legal_Sent')):>7} {_fmt(row.get('Legal_Received')):>7} "
          f"{_fmt(row.get('PDR_pct')):>7} {_fmt(row.get('Avg_Delay_ms')):>8} "
          f"{_fmt(row.get('Median_Delay_ms')):>8} {_fmt(row.get('P95_Delay_ms')):>8} "
          f"{_fmt(row.get('Throughput_kbps')):>9} {_fmt(row.get('NRL')):>7} "
          f"{_fmt(row.get('DoS_Packets_Detected')):>7}  {row['Status']}")
    sys.stdout.flush()


def to_sim_row(r: Dict[str, object], cfg: Optional[Config] = None) -> Dict[str, object]:
    """Konversi dictionary metrik internal ke format 100% persis output CSV simulasi NS-3."""
    meta_cond = str(r.get("Kondisi", "Normal"))
    is_dos = meta_cond.upper() == "DOS"

    total_nodes = r.get("Jumlah_Node")
    if total_nodes is None or total_nodes == "":
        total_nodes = BASELINE["nodes"]
    else:
        try:
            total_nodes = int(total_nodes)
        except ValueError:
            total_nodes = BASELINE["nodes"]

    num_attackers = 1 if is_dos else 0
    legit_count = max(total_nodes - num_attackers, 0)

    sim_time = None
    if cfg is not None and cfg.duration is not None:
        sim_time = cfg.duration
    elif r.get("Active_Duration_s") is not None and r.get("Active_Duration_s") != "":
        sim_time = r.get("Active_Duration_s")

    if sim_time is not None:
        try:
            st_f = float(sim_time)
            sim_time = int(st_f) if abs(st_f - round(st_f)) < 1e-4 else round(st_f, 2)
        except (ValueError, TypeError):
            pass
    else:
        sim_time = 222

    attack_rate = "2Mbps" if is_dos else "0Mbps"
    scenario_str = f"Multi-hop {meta_cond}"

    return {
        "protocol": r.get("Protokol"),
        "scenario": scenario_str,
        "totalNodes": total_nodes,
        "legitCount": legit_count,
        "numAttackers": num_attackers,
        "simTime": sim_time,
        "attackDataRate": attack_rate,
        "dataTxPackets": r.get("Legal_Sent"),
        "dataRxPackets": r.get("Legal_Received"),
        "dataLostPackets": r.get("Legal_Lost"),
        "PDR_percent": r.get("PDR_pct"),
        "PLR_percent": r.get("PLR_pct"),
        "avgDelay_ms": r.get("Avg_Delay_ms"),
        "throughput_kbps": r.get("Throughput_kbps"),
        "routingOverhead_packets": r.get("Routing_Packets_Sent"),
        "NRL": r.get("NRL"),
        "attackPacketsSent": r.get("DoS_Packets_Detected"),
    }


def write_csv(rows: List[Dict[str, object]], out_path: Path, csv_format: str = "sim",
              cfg: Optional[Config] = None) -> None:
    """Tulis hasil ke CSV (UTF-8).

    Args:
        rows: Data hasil pemrosesan file trace.
        out_path: Path tujuan file CSV.
        csv_format: 'sim' (17 kolom persis output NS-3) atau 'full' (39 kolom lengkap).
        cfg: Konfigurasi parser (digunakan untuk fallback simTime, dsb.).
    """
    out_path.parent.mkdir(parents=True, exist_ok=True)
    fields = SIM_CSV_FIELDS if csv_format == "sim" else FULL_CSV_FIELDS

    with out_path.open("w", encoding="utf-8", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=fields, extrasaction="ignore")
        w.writeheader()
        for r in rows:
            src = to_sim_row(r, cfg) if csv_format == "sim" else r
            clean = {}
            for k in fields:
                v = src.get(k)
                if v is None:
                    v = ""
                elif isinstance(v, float):
                    v = round(v, 4)
                clean[k] = v
            w.writerow(clean)


# ---------------------------------------------------------------------------
# 5. CLI
# ---------------------------------------------------------------------------

def build_arg_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="Parser trace NS-3 ASCII untuk komparasi AODV vs OLSR (Normal vs DoS) pada VANET.")
    p.add_argument("-d", "--dir", nargs="+", default=[], metavar="DIR",
                   help="folder simulasi (diproses rekursif); boleh lebih dari satu")
    p.add_argument("-f", "--file", action="append", default=[], metavar="FILE",
                   help="file trace tunggal (boleh diulang)")
    p.add_argument("-o", "--output", default="vanet_metrics_ns3.csv", metavar="CSV",
                   help="path CSV keluaran (default: vanet_metrics_ns3.csv)")
    p.add_argument("--format", choices=["sim", "full"], default="sim",
                   help="format kolom CSV: 'sim' (default, 100%% sama dengan skrip NS-3) "
                        "atau 'full' (format lengkap dengan OFAT dan persentil delay)")
    p.add_argument("--ext", nargs="+", default=[".tr"], metavar="EXT",
                   help="ekstensi file trace yang dipindai (default: .tr)")
    p.add_argument("--legal-size", type=int, default=512, help="payload data legal, byte (default 512)")
    p.add_argument("--dos-size", type=int, default=1024, help="payload paket DoS, byte (default 1024)")
    p.add_argument("--size-tol", type=int, default=60,
                   help="toleransi di atas payload nominal, byte (default 60)")
    p.add_argument("--ip-offset", type=int, default=1,
                   help="node_id = oktet terakhir IP - offset (default 1)")
    p.add_argument("--duration", type=float, default=None,
                   help="Durasi Aktif tetap (detik) untuk throughput; default: otomatis dari trace")
    p.add_argument("--dos-start", type=float, default=5.0,
                   help="awal jendela serangan DoS, detik (default 5.0)")
    p.add_argument("--dos-end", type=float, default=220.0,
                   help="akhir jendela serangan DoS, detik (default 220.0)")
    p.add_argument("--attacker-node", type=int, default=None,
                   help="(opsional) ID node penyerang; hanya broadcast dari node ini yang dihitung DoS")
    p.add_argument("--attacker-ip", type=str, default=None,
                   help="(opsional) IP penyerang, mis. 10.1.1.10")
    p.add_argument("--id-reuse-window", type=float, default=60.0,
                   help="jeda (detik) setelah mana IP-ID yang sama dianggap paket baru (default 60)")
    return p


def main(argv: Optional[Sequence[str]] = None) -> int:
    """Entry point CLI. Return exit code (0 sukses, 1 ada file error, 2 tidak ada input)."""
    args = build_arg_parser().parse_args(argv)
    ext = tuple(e if e.startswith(".") else "." + e for e in args.ext)
    cfg = Config(legal_size=args.legal_size, dos_size=args.dos_size, size_tol=args.size_tol,
                 ip_offset=args.ip_offset, duration=args.duration,
                 dos_start=args.dos_start, dos_end=args.dos_end,
                 attacker_node=args.attacker_node, attacker_ip=args.attacker_ip,
                 id_reuse_window=args.id_reuse_window, extensions=ext)
    if cfg.dos_start > cfg.dos_end:
        print("--dos-start harus <= --dos-end", file=sys.stderr)
        return 2

    targets = discover_files(args.dir, args.file, cfg.extensions)
    if not targets:
        print("Tidak ada file trace untuk diproses. Gunakan -d <folder> atau -f <file>.", file=sys.stderr)
        return 2

    print(f"Memproses {len(targets)} file trace NS-3 ...\n")
    print(_TABLE_HEAD)
    print("-" * len(_TABLE_HEAD))

    rows: List[Dict[str, object]] = []
    n_err = 0
    for i, (path, root) in enumerate(targets, 1):
        try:
            row = process_trace(path, cfg, root)
        except Exception as exc:               # noqa: BLE001 - batch tidak boleh berhenti
            n_err += 1
            meta = extract_metadata(path, root)
            row = {"File": path.name, "Path": str(path),
                   "Protokol": meta.protokol, "Kondisi": meta.kondisi,
                   "Kelompok_OFAT": meta.kelompok, "Variabel_Uji": meta.variabel,
                   "Nilai_Variabel": meta.nilai, "Jumlah_Node": meta.nodes,
                   "Jarak_m": meta.dist, "Kecepatan_kmh": meta.speed, "Run": meta.run,
                   "Status": f"ERROR: {exc}", "Meta_Warning": "; ".join(meta.warnings),
                   "_sort": meta.sort_key()}
        rows.append(row)
        _print_row(i, len(targets), row)

    rows.sort(key=lambda r: r["_sort"])
    out = Path(args.output)
    write_csv(rows, out, csv_format=args.format, cfg=cfg)

    n_warn = sum(1 for r in rows if str(r["Status"]).startswith("WARN") or r.get("Meta_Warning"))
    print("-" * len(_TABLE_HEAD))
    print(f"Selesai: {len(rows) - n_err} sukses, {n_err} error, {n_warn} dengan peringatan.")
    print(f"CSV     : {out.resolve()} (Format: {args.format.upper()})")
    for r in rows:
        if r.get("Meta_Warning"):
            print(f"  [!] {r['File']}: {r['Meta_Warning']}")
    return 0 if n_err == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
