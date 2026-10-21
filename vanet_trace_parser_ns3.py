#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
vanet_trace_parser_ns3.py
=========================

Parser batch (standard library only, single-pass) untuk file trace ``.tr``
**NS-3 Native ASCII** hasil simulasi komparasi AODV vs OLSR pada VANET
(jalan lurus multi-hop IEEE 802.11p, desain OFAT).

Catatan Kolom Kosong / NaN & Fallback Deterministik
---------------------------------------------------
Parser tidak pernah mengarang nilai:
* ``Legal_Sent_App`` : dibaca dari ``--flowmon-xml`` bila tersedia; bila tidak ada
  file FlowMonitor XML pada trace PHY Wi-Fi, diestimasi secara deterministik dari
  jadwal trafik aplikasi CBR 100 kbps (payload 512 B = 24,4140625 paket/detik)
  selama ``t_sim_traffic = max(Active_Duration_s, Trace_Last_Time_s - 7.0)``,
  sehingga ``Layer3_Queue_Dropped = max(0, Legal_Sent_App - Legal_Sent)`` dan
  ``PDR_App_pct = Legal_Received / Legal_Sent_App * 100`` selalu terisi.
* ``HELLO_Msgs``, ``TC_Msgs`` : kosong (NaN) jika protokol adalah AODV, atau
  jika trace sintetis OLSR hanya menulis ``PacketHeader`` tanpa ``MessageHeader``.
* ``RREQ_Msgs``, ``RREP_Msgs``, ``RERR_Msgs``, ``Hello_Msgs`` : kosong (NaN)
  jika protokol adalah OLSR, atau jika paket port 654 pada trace tidak memuat
  header pesan AODV yang dikenali.
* ``DoS_Rate_Observed_Mbps`` : ``0.0`` pada kondisi Normal (0 paket DoS); kosong
  (NaN) jika hanya 1 paket DoS terdeteksi sehingga rentang waktu = 0.
* ``Attacker_Node``, ``DoS_Id_Gap`` : kosong (NaN) jika tidak ada paket DoS
  yang terdeteksi (``DoS_Packets_Detected == 0``).
* ``Avg_Delay_ms``, ``Median_Delay_ms``, ``P95_Delay_ms``, ``P99_Delay_ms``,
  ``Max_Delay_ms``, ``NRL``, ``Hop_Count_Mean`` : kosong (NaN) jika
  ``Legal_Received == 0``.
* Jika ``Legal_Sent == 0`` (gagal rute total di Layer-3 seperti ``olsr-b-j400-normal.tr``),
  ``PDR_pct = 0.0``, ``PLR_pct = 100.0``, ``MAC_Retry_Ratio = 0.0``, dan
  ``Longest_Outage_s = t_sim_traffic`` agar tidak menghasilkan ``NaN`` pada CSV/grafik.

Contoh pemakaian
----------------
    python vanet_trace_parser_ns3.py -d ./hasil_simulasi -o metrik_vanet.csv
    python vanet_trace_parser_ns3.py -f tester/olsr-mh-normal.tr --duration 222
    python vanet_trace_parser_ns3.py -d ./traces --strict --detail-json detail.json
"""

from __future__ import annotations

import argparse
import csv
import json
import math
import re
import sys
import xml.etree.ElementTree as ET
from collections import Counter, defaultdict
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

#: Format CSV ringkasan 17 kolom bawaan skrip C++ NS-3 (--format cc).
CC_CSV_FIELDS = [
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

#: Laju paket aplikasi CBR legal default (100 kbps dengan payload 512 B = 24.4140625 pkt/s).
DEFAULT_CBR_RATE_BPS = 100000.0

#: Format CSV utama simulasi PHY (--format sim, default): 68 kolom tanpa Legal_Drop_Events.
SIM_CSV_FIELDS = [
    # Identitas (16)
    "File", "Path",
    "Protokol", "Kondisi", "Kelompok_OFAT", "Variabel_Uji", "Nilai_Variabel",
    "Jumlah_Node", "Jarak_m", "Kecepatan_kmh",
    "Mode_Kecepatan", "Kecepatan_Min", "Kecepatan_Max", "Is_Baseline",
    "Run", "Seed",
    # QoS & Pemisahan Layer-3 / Multi-Hop (20)
    "Legal_Sent_App", "Legal_Sent", "Layer3_Queue_Dropped",
    "Legal_Received", "MultiHop_Received", "OneHop_PileUp_Received", "MultiHop_Ratio_pct",
    "Legal_Lost",
    "PDR_pct", "PLR_pct", "PDR_App_pct", "PLR_App_pct",
    "Avg_Delay_ms", "Median_Delay_ms", "P95_Delay_ms", "P99_Delay_ms", "Max_Delay_ms",
    "Throughput_kbps", "Throughput_active_kbps", "Active_Duration_s",
    # Non-QoS (10)
    "Routing_Packets_Sent", "Routing_Bytes_Sent", "Routing_Overhead", "NRL",
    "HELLO_Msgs", "TC_Msgs",
    "RREQ_Msgs", "RREP_Msgs", "RERR_Msgs", "Hello_Msgs",
    # DoS (6)
    "DoS_Packets_Detected", "DoS_Rx_Events", "DoS_Unique_Packets_Recv",
    "DoS_Rate_Observed_Mbps", "Attacker_Node", "DoS_Id_Gap",
    # Diagnostik (8)
    "MAC_Retry_Count", "MAC_Retry_Ratio",
    "Hop_Count_Mean", "Route_Change_Count",
    "Num_Loss_Windows", "Longest_Outage_s",
    "Num_Legal_Flows", "Trace_Last_Time_s",
    # Audit & Integritas (8)
    "Unmatched_Legal_Recv", "Duplicate_Events",
    "Lines_Total", "Lines_Ignored", "Lines_Corrupt",
    "Status", "Meta_Warning", "First_Corrupt_Line",
]

#: Format CSV lengkap (--format full): menyertakan Legal_Drop_Events untuk trace MAC/queue.
FULL_CSV_FIELDS = (
    SIM_CSV_FIELDS[:SIM_CSV_FIELDS.index("Unmatched_Legal_Recv")]
    + ["Legal_Drop_Events"]
    + SIM_CSV_FIELDS[SIM_CSV_FIELDS.index("Unmatched_Legal_Recv"):]
)

CSV_FIELDS = SIM_CSV_FIELDS

# Pola default pesan AODV dari src/aodv/model/aodv-packet.cc & aodv-routing-protocol.cc NS-3.
# TODO: Jika format cetakan ASCII AODV pada versi NS-3 kustom berbeda dari
# ns3::aodv::TypeHeader / RreqHeader / RrepHeader / RerrHeader standar, sesuaikan
# pola regex di bawah ini atau lewat argumen CLI (--aodv-*-regex).
DEFAULT_AODV_PATTERNS = {
    "rreq": r"ns3::aodv::TypeHeader\s*\(\s*RREQ\s*\)|ns3::aodv::RreqHeader|\btype[:=]\s*RREQ\b",
    "rrep": r"ns3::aodv::TypeHeader\s*\(\s*RREP\s*\)|ns3::aodv::RrepHeader|\btype[:=]\s*RREP\b",
    "rerr": r"ns3::aodv::TypeHeader\s*\(\s*RERR\s*\)|ns3::aodv::RerrHeader|\btype[:=]\s*RERR\b",
    "hello_explicit": r"ns3::aodv::TypeHeader\s*\(\s*HELLO\s*\)|\btype[:=]\s*HELLO\b",
    # Pada NS-3 standar (RFC 3561 Sec 6.9, aodv-routing-protocol.cc:1647 & 1988),
    # pesan Hello AODV adalah RrepHeader dengan destination == source (origin) dan TTL=1.
    "rrep_addrs": (
        r"ns3::aodv::RrepHeader\s*\([^)]*?destination:\s*ipv4\s+(\d+\.\d+\.\d+\.\d+)"
        r"[^)]*?source(?:\s*:\s*|\s+)ipv4\s+(\d+\.\d+\.\d+\.\d+)"
    ),
}


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
        duration: Durasi simulasi tetap (detik) untuk ``Throughput_kbps``
            (default 222.0). Jika <= 0 atau None, fallback ke ``Active_Duration_s``.
        dos_start, dos_end: Jendela waktu serangan (detik). Broadcast ~1.024 B di luar
            jendela ini TIDAK dihitung sebagai DoS.
        attacker_node: (opsional) ID node penyerang; sumber paket DoS harus cocok.
        attacker_ip: (opsional) IP penyerang; sumber paket DoS harus cocok.
        id_reuse_window: Jeda (detik) setelah mana IP-ID yang sama dianggap paket baru
            (mitigasi wrap IP-ID 16-bit).
        strict: Jika True, file tanpa token OFAT tidak diasumsikan Baseline dan
            diberi ``Status = "WARN: metadata tidak terdeteksi"``.
        flowmon_xml: (opsional) Path file FlowMonitor XML atau folder berisi file XML
            untuk mengisi ``Legal_Sent_App``.
        legal_port: Port UDP trafik data legal (default 9) untuk pencocokan FlowMonitor.
        loss_window_gap: Gap maksimum (detik tanpa loss) yang digabung ke dalam satu
            jendela loss pada ``Num_Loss_Windows`` (default 1 detik).
        aodv_patterns: Kamus regex konfigurabel untuk klasifikasi pesan AODV.
        extensions: Ekstensi file trace yang dipindai.
    """
    legal_size: int = 512
    dos_size: int = 1024
    size_tol: int = 60
    ip_offset: int = 1
    duration: Optional[float] = 222.0
    dos_start: float = 5.0
    dos_end: float = float("inf")
    attacker_node: Optional[int] = None
    attacker_ip: Optional[str] = None
    id_reuse_window: float = 60.0
    strict: bool = False
    flowmon_xml: Optional[str] = None
    legal_port: int = 9
    loss_window_gap: int = 1
    aodv_patterns: Dict[str, str] = field(default_factory=lambda: dict(DEFAULT_AODV_PATTERNS))
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
        re.compile(r"(?<![a-z\d])(?:dist(?:ance)?|jarak|spacing|gap|d|j)[_\-=]?(\d+)(?:m)?(?![a-z\d])"),
        re.compile(r"(?<![a-z\d.])(\d+)[_\-]?m(?![a-z\d])"),
    ],
    "speed": [
        # Hindari mencocokkan v15_25 / v15-25 sebagai kecepatan tunggal 15
        re.compile(
            r"(?<![a-z\d])(?:speed|spd|kecepatan|kec|v|k)[_\-=]?(\d+)"
            r"(?![_\-](?:to[_\-]?)?25\b)(?:kmh|kmph|kmj|kph|km)?(?![a-z\d])"
        ),
        re.compile(r"(?<![a-z\d.])(?<!15[_\-])(\d+)[_\-]?(?:km[_/\-]?h|kmph|kmj|kph|km)(?![a-z])"),
    ],
    "hetero": re.compile(
        r"hetero|acak|15[_\-](?:to[_\-]?)?25|v15[_\-]25|rand(?:om)?[_\-]?speed|speedvar|mixed[_\-]?speed"),
    "baseline": re.compile(r"(?<![a-z\d])(?:baseline|b0)(?![a-z\d])"),
    "hint": re.compile(
        r"(?<![a-z\d])(?:kelompok|klp|group|grp)[_\-\s]?([abcd])(?![a-z\d])"
        r"|(?<=[_\-])([abcd])(?=[_\-](?!\d)|$)"
    ),
    "run": re.compile(r"(?<![a-z])(?:seed|run|rep|ulangan|rngrun|rng)[_\-=]?(\d+)(?![\d])"),
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
    mode_kecepatan: str = "seragam"
    kec_min: Optional[int] = None
    kec_max: Optional[int] = None
    is_baseline: int = 0
    run: str = "1"
    seed: int = 1
    ofat_detected: bool = False
    seed_detected: bool = False
    warnings: List[str] = field(default_factory=list)

    def sort_key(self) -> Tuple:
        """Kunci pengurutan baris CSV: kelompok, nilai numerik, protokol, kondisi, seed."""
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
        return (GROUP_ORDER.get(self.kelompok, 9), num, self.protokol, self.kondisi, self.seed)


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


def extract_metadata(path: Path, root: Optional[Path] = None, strict: bool = False) -> ScenarioMeta:
    """Ekstrak metadata OFAT dari nama file dan path.

    Aturan penentuan kelompok:
      1. Terdeteksi heterogenitas kecepatan (atau petunjuk kelompok D) -> ``D``.
      2. Tepat satu parameter menyimpang dari baseline (10 node/200 m/20 km/jam)
         -> A (Kepadatan) / B (Jarak) / C (Kecepatan).
      3. Tidak ada yang menyimpang -> ``Baseline``; kecuali path memuat petunjuk
         ``kelompok_A/B/C`` (titik baseline sebagai bagian deret grup tersebut).
      4. Bila tidak ada satu pun token OFAT dan ``strict=True``, kelompok tetap
         ``Unknown`` dan tidak diasumsikan Baseline.

    Args:
        path: Path file trace.
        root: Folder akar pencarian (agar folder di atas root tidak ikut diparsing).
        strict: Jika True, jangan asumsikan Baseline saat token OFAT absen.

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
            hint = (m.group(1) or m.group(2)).upper()
            break
    hetero = any(META_PATTERNS["hetero"].search(s) for s in segs) or hint == "D"
    explicit_base = any(META_PATTERNS["baseline"].search(s) for s in segs)

    for seg in segs:
        m = META_PATTERNS["run"].search(seg)
        if m:
            meta.run = m.group(1)
            meta.seed = int(m.group(1))
            meta.seed_detected = True
            break
    if not meta.seed_detected:
        meta.run = "1"
        meta.seed = 1

    meta.ofat_detected = (
        nodes is not None
        or dist is not None
        or speed is not None
        or hetero
        or hint is not None
        or explicit_base
    )

    if not meta.ofat_detected:
        if strict:
            meta.warnings.append("parameter OFAT tidak terdeteksi (mode --strict)")
            meta.kelompok = "Unknown"
            meta.variabel = "Unknown"
            meta.nilai = ""
            meta.nodes = None
            meta.dist = None
            meta.speed = ""
            meta.mode_kecepatan = "seragam"
            meta.kec_min = None
            meta.kec_max = None
            meta.is_baseline = 0
            return _finalize_meta(meta)
        meta.warnings.append("parameter OFAT tidak terdeteksi (diasumsikan baseline)")

    meta.nodes = nodes if nodes is not None else BASELINE["nodes"]
    meta.dist = dist if dist is not None else BASELINE["dist"]
    spd_val = speed if speed is not None else BASELINE["speed"]
    values = {"nodes": meta.nodes, "dist": meta.dist, "speed": spd_val}

    if hetero:
        meta.kelompok, meta.variabel, meta.nilai = "D", "Heterogenitas", "15-25 km/jam"
        meta.speed = "15-25"
        meta.mode_kecepatan = "acak"
        meta.kec_min = 15
        meta.kec_max = 25
        meta.is_baseline = 0
        return _finalize_meta(meta)

    meta.speed = str(spd_val)
    meta.mode_kecepatan = "seragam"
    meta.kec_min = spd_val
    meta.kec_max = spd_val
    meta.is_baseline = 1 if (
        meta.nodes == BASELINE["nodes"]
        and meta.dist == BASELINE["dist"]
        and spd_val == BASELINE["speed"]
    ) else 0

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
# 2. Pembacaan opsional FlowMonitor XML untuk Legal_Sent_App
# ---------------------------------------------------------------------------

def read_flowmon_legal_sent_app(
    trace_path: Path,
    flowmon_arg: Optional[str],
    legal_port: int = 9,
) -> Optional[int]:
    """Baca jumlah paket aplikasi legal (``txPackets``) dari file FlowMonitor XML.

    Pencarian file XML:
      1. Jika ``flowmon_arg`` adalah file XML valid, langsung gunakan file tersebut.
      2. Jika ``flowmon_arg`` adalah direktori, cari ``<stem>-flowmon-results.xml``
         atau ``<stem>_flowmon.xml`` atau ``<stem>.xml`` di dalamnya.
      3. Jika tidak ditemukan atau ``flowmon_arg`` None, return ``None`` (NaN).
    """
    if not flowmon_arg:
        return None
    cand = Path(flowmon_arg)
    xml_path: Optional[Path] = None
    if cand.is_file():
        xml_path = cand
    elif cand.is_dir():
        stem = trace_path.stem
        for name in (
            f"{stem}-flowmon-results.xml",
            f"{stem}_flowmon.xml",
            f"{stem}-flowmon.xml",
            f"{stem}.xml",
        ):
            p = cand / name
            if p.is_file():
                xml_path = p
                break
    if xml_path is None or not xml_path.is_file():
        return None

    try:
        tree = ET.parse(xml_path)
        root = tree.getroot()
        legal_flow_ids: Set[str] = set()
        for clf in root.findall(".//Ipv4FlowClassifier/Flow"):
            dport = clf.attrib.get("destinationPort", "")
            dst = clf.attrib.get("destinationAddress", "")
            fid = clf.attrib.get("flowId", "")
            if dport == str(legal_port) and not is_broadcast_ip(dst) and fid:
                legal_flow_ids.add(fid)
        if not legal_flow_ids:
            return None
        total_tx = 0
        matched = False
        for fst in root.findall("./FlowStats/Flow"):
            fid = fst.attrib.get("flowId", "")
            if fid in legal_flow_ids and "txPackets" in fst.attrib:
                total_tx += int(fst.attrib["txPackets"])
                matched = True
        return total_tx if matched else None
    except Exception:  # noqa: BLE001
        return None


# ---------------------------------------------------------------------------
# 3. Akumulator metrik
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
    * OTHER : selain itu -> tidak dihitung di metrik mana pun.
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
    """Persentil ke-``p`` (0-100) dengan interpolasi linear antar titik data."""
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
    """Menyimpan counter terpisah untuk trafik legal, DoS, kontrol routing, dan diagnostik.

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
        self.legal_recv_times: List[float] = []
        self.delays: List[float] = []          # detik, per paket legal diterima
        self.legal_drop = 0
        self.unmatched_recv = 0
        self.duplicates = 0
        self.missing_da = 0                    # baris terima legal tanpa DA(RA)
        # diagnostik legal
        self.legal_tx_total = 0                # seluruh event TX legal di semua hop (termasuk retry)
        self.mac_retry_count = 0               # frame legal dengan Retry=1 di semua hop
        self.retry_by_node: Counter = Counter()
        self.tx_nodes: Dict[object, List[int]] = defaultdict(list)
        self.last_src_da: Dict[Tuple[str, str], str] = {}
        self.route_change_count = 0
        self.legal_flows: Set[Tuple[str, str, int]] = set()
        # DoS
        self.dos_keys: Set[object] = set()
        self.dos_unique_recv: Set[object] = set()
        self.dos_rx_events = 0
        self.dos_rejected = 0                  # broadcast ~1.024 B yang gagal kriteria DoS
        self.dos_t_first: Optional[float] = None
        self.dos_t_last: Optional[float] = None
        self.dos_payload_bits: int = 0
        self.dos_attacker_nodes: Counter = Counter()
        self.dos_last_ipid: Optional[int] = None
        self.dos_id_gap: int = 0
        # routing (paket & per-pesan)
        self.routing_tx_count = 0
        self.routing_bytes = 0
        self.olsr_hello_msgs = 0
        self.olsr_tc_msgs = 0
        self.olsr_msg_parsed = False
        self.olsr_hello_by_node: Counter = Counter()
        self.olsr_tc_by_node: Counter = Counter()
        self.aodv_rreq_msgs = 0
        self.aodv_rrep_msgs = 0
        self.aodv_rerr_msgs = 0
        self.aodv_hello_msgs = 0
        self.aodv_msg_parsed = False
        self.aodv_msgs_by_node: Dict[str, Counter] = {
            "RREQ": Counter(), "RREP": Counter(), "RERR": Counter(), "HELLO": Counter()
        }
        # lain-lain
        self._epoch: Dict[Tuple, List] = {}    # base-key -> [epoch, t_tx_terakhir]
        self.id_reuse = 0
        self.t_first_send: Optional[float] = None
        self.t_last: Optional[float] = None
        self.t_last_send: Optional[float] = None
        self.trace_last_time: Optional[float] = None
        self.protocols: Set[str] = set()

    def touch_trace_time(self, t: float) -> None:
        if self.trace_last_time is None or t > self.trace_last_time:
            self.trace_last_time = t

    # -- kunci paket unik (mitigasi wrap IP-ID) -------------------------------
    def resolve_key(self, base: Tuple, t: float, is_tx: bool) -> Tuple:
        """Tambahkan nomor epoch ke kunci dasar ``(src, dst, sport, dport, ip_id)``."""
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
    def legal_tx_attempt(
        self,
        key: object,
        t: float,
        node: int,
        src: str,
        dst: str,
        dport: int,
        da_mac: Optional[str],
        is_retry: bool,
    ) -> None:
        """Catat setiap percobaan TX frame legal (semua hop, termasuk forwarder & retry)."""
        self.legal_tx_total += 1
        self.legal_flows.add((src, dst, dport))
        if is_retry:
            self.mac_retry_count += 1
            self.retry_by_node[node] += 1

        nodes_list = self.tx_nodes[key]
        if node not in nodes_list:
            nodes_list.append(node)

        if key in self.legal_send_t:
            return                             # forwarder / retry: bukan pengiriman baru

        # Pengiriman awal paket unik
        self.legal_send_t[key] = t
        if self.t_first_send is None or t < self.t_first_send:
            self.t_first_send = t
        if self.t_last is None or t > self.t_last:
            self.t_last = t
        if self.t_last_send is None or t > self.t_last_send:
            self.t_last_send = t

        # Pergantian DA hop pertama di node sumber
        src_node = ip_to_node(src, self.cfg)
        if node == src_node and da_mac:
            flow_pair = (src, dst)
            prev_da = self.last_src_da.get(flow_pair)
            if prev_da is not None and prev_da != da_mac:
                self.route_change_count += 1
            self.last_src_da[flow_pair] = da_mac

    def legal_send(self, key: object, t: float) -> None:
        if key in self.legal_send_t:
            self.duplicates += 1
            return
        self.legal_send_t[key] = t
        if self.t_first_send is None or t < self.t_first_send:
            self.t_first_send = t
        if self.t_last is None or t > self.t_last:
            self.t_last = t
        if self.t_last_send is None or t > self.t_last_send:
            self.t_last_send = t

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
        self.legal_recv_times.append(t)
        self.delays.append(t - t0)
        if self.t_last is None or t > self.t_last:
            self.t_last = t

    def legal_drop_if_known(self, key: object) -> None:
        if key in self.legal_send_t:
            self.legal_drop += 1

    # -- trafik DoS (terisolasi) ---------------------------------------------
    def dos_send(
        self,
        key: object,
        t: Optional[float] = None,
        size: Optional[int] = None,
        src_node: Optional[int] = None,
        ipid: Optional[int] = None,
    ) -> None:
        if key not in self.dos_keys:
            self.dos_keys.add(key)
            pkt_size = size if size is not None else self.cfg.dos_size
            self.dos_payload_bits += pkt_size * 8
            if t is not None:
                if self.dos_t_first is None or t < self.dos_t_first:
                    self.dos_t_first = t
                if self.dos_t_last is None or t > self.dos_t_last:
                    self.dos_t_last = t
            if src_node is not None:
                self.dos_attacker_nodes[src_node] += 1
            if ipid is not None:
                if self.dos_last_ipid is not None:
                    diff = (ipid - self.dos_last_ipid) % 65536
                    if 1 < diff < 32768:
                        self.dos_id_gap += diff - 1
                self.dos_last_ipid = ipid

    def dos_rx_evt(self, key: object, rx_node: int, src_node: int) -> None:
        """Catat SATU event penerimaan PHY paket DoS (bisa banyak per paket broadcast)."""
        self.dos_rx_events += 1
        if rx_node != src_node and rx_node != self.cfg.attacker_node:
            self.dos_unique_recv.add(key)

    # -- kontrol routing ---------------------------------------------------
    def routing_tx(self, size: int) -> None:
        self.routing_tx_count += 1
        self.routing_bytes += max(size, 0)

    def _compute_loss_windows(self) -> List[Dict[str, int]]:
        """Hitung daftar jendela detik berurutan dengan loss > 0 (gap <= loss_window_gap digabung)."""
        lost_by_sec: Counter = Counter()
        for k, t_send in self.legal_send_t.items():
            if k not in self.legal_received:
                lost_by_sec[int(math.floor(t_send))] += 1
        if not lost_by_sec:
            return []
        secs = sorted(lost_by_sec.keys())
        max_step = self.cfg.loss_window_gap + 1   # gap <= 1 s -> selisih indeks detik <= 2
        windows: List[Dict[str, int]] = []
        for s in secs:
            if not windows or s - windows[-1]["end_s"] > max_step:
                windows.append({
                    "start_s": s,
                    "end_s": s,
                    "duration_s": 1,
                    "lost_packets": lost_by_sec[s],
                })
            else:
                w = windows[-1]
                w["end_s"] = s
                w["duration_s"] = s - w["start_s"] + 1
                w["lost_packets"] += lost_by_sec[s]
        return windows

    def _compute_longest_outage(self) -> Optional[float]:
        """Selang waktu terpanjang (detik) tanpa penerimaan paket legal di tujuan."""
        if not self.legal_send_t:
            return None
        t0 = self.t_first_send if self.t_first_send is not None else 0.0
        t_end = self.t_last if self.t_last is not None else t0
        if not self.legal_recv_times:
            return max(t_end - t0, 0.0)
        rx = sorted(self.legal_recv_times)
        gaps: List[float] = [max(rx[0] - t0, 0.0)]
        for i in range(1, len(rx)):
            gaps.append(max(rx[i] - rx[i - 1], 0.0))
        if t_end > rx[-1]:
            gaps.append(t_end - rx[-1])
        return max(gaps) if gaps else 0.0

    def detail_summary(self) -> Dict[str, object]:
        """Ringkasan diagnostik rinci untuk opsi ``--detail-json``."""
        relay_dist: Counter = Counter()
        for k in self.legal_received:
            path_nodes = self.tx_nodes.get(k, [])
            if path_nodes:
                relay_dist["->".join(str(n) for n in path_nodes)] += 1
        return {
            "retry_per_node": {str(k): v for k, v in sorted(self.retry_by_node.items())},
            "relay_path_distribution": dict(relay_dist.most_common()),
            "loss_windows": self._compute_loss_windows(),
            "olsr_hello_per_node": {str(k): v for k, v in sorted(self.olsr_hello_by_node.items())},
            "olsr_tc_per_node": {str(k): v for k, v in sorted(self.olsr_tc_by_node.items())},
            "aodv_msgs_per_node": {
                mtype: {str(k): v for k, v in sorted(cnt.items())}
                for mtype, cnt in self.aodv_msgs_by_node.items()
                if cnt
            },
        }

    # -- hasil akhir -------------------------------------------------------
    def metrics(
        self,
        proto_hint: str = "Unknown",
        legal_sent_app_override: Optional[int] = None,
    ) -> Dict[str, object]:
        """Hitung seluruh metrik QoS, Non-QoS, DoS, dan Diagnostik."""
        sent, recv = len(self.legal_send_t), len(self.legal_received)
        active_dur: Optional[float] = None
        if self.t_first_send is not None and self.t_last is not None and self.t_last >= self.t_first_send:
            active_dur = self.t_last - self.t_first_send

        if self.cfg.duration is not None and self.cfg.duration > 0:
            # Sesuai Proposal Hal. 14 ("Durasi simulasi: Sampai semua node mencapai titik akhir"),
            # bila durasi default 222.0 s digunakan pada trace SUMO yang durasinya berbeda jauh
            # (mis. 190 s pada k40 atau 378..738 s pada baseline/n20/n30), sesuaikan otomatis
            # ke jendela trafik aktual skenario tersebut (max(active_dur, trace_last_time - 7.0)).
            if (
                self.cfg.duration == 222.0
                and self.trace_last_time is not None
                and (100.0 <= self.trace_last_time < 205.0 or self.trace_last_time > 225.0)
            ):
                sched_dur = max(self.trace_last_time - 7.0, 1.0)
                sim_dur: Optional[float] = max(active_dur or 0.0, sched_dur)
            else:
                sim_dur = float(self.cfg.duration)
        else:
            if self.trace_last_time is not None and self.trace_last_time > 10.0:
                sim_dur = max(active_dur or 0.0, self.trace_last_time - 7.0)
            else:
                sim_dur = active_dur

        # 1. Estimasi deterministik Legal_Sent_App & Layer3_Queue_Dropped (Patch 1 Referensi)
        cbr_pkt_rate = DEFAULT_CBR_RATE_BPS / (self.cfg.legal_size * 8.0)
        if legal_sent_app_override is not None:
            legal_sent_app: Optional[int] = legal_sent_app_override
        elif sim_dur is not None and sim_dur > 0:
            legal_sent_app = int(round(sim_dur * cbr_pkt_rate))
        else:
            legal_sent_app = None

        l3_queue_dropped: Optional[int] = (
            max(0, legal_sent_app - sent) if legal_sent_app is not None else None
        )

        # 2. Pemisahan paket Multi-Hop vs 1-Hop Pile-Up di ujung jalan (Patch 1 Referensi)
        one_hop_received = 0
        for k in self.legal_received:
            path_nodes = self.tx_nodes.get(k, [])
            if path_nodes == [0]:
                one_hop_received += 1
        multihop_received = recv - one_hop_received
        multihop_ratio_pct = (multihop_received / recv * 100.0) if recv > 0 else 0.0

        # 3. Tangani pembagian 0 pada skenario gagal rute total (mis. olsr-b-j400-normal.tr)
        d_ms = sorted(d * 1000.0 for d in self.delays)
        if sent == 0:
            pdr: Optional[float] = 0.0
            plr: Optional[float] = 100.0
            thr: Optional[float] = 0.0
            thr_active: Optional[float] = 0.0
            mac_retry_ratio: Optional[float] = 0.0
            longest_outage: Optional[float] = sim_dur
        else:
            pdr = (recv / sent) * 100.0
            plr = 100.0 - pdr
            thr = (
                (recv * self.cfg.legal_size * 8.0) / (sim_dur * 1000.0)
                if sim_dur and sim_dur > 0
                else None
            )
            thr_active = (
                (recv * self.cfg.legal_size * 8.0) / (active_dur * 1000.0)
                if active_dur and active_dur > 0
                else None
            )
            mac_retry_ratio = (
                self.mac_retry_count / self.legal_tx_total
                if self.legal_tx_total > 0
                else 0.0
            )
            longest_outage = self._compute_longest_outage()

        # 4. PDR_App_pct & PLR_App_pct (Application-level End-to-End PDR/PLR)
        pdr_app_pct: Optional[float] = (
            (recv / legal_sent_app * 100.0)
            if (legal_sent_app is not None and legal_sent_app > 0)
            else 0.0
        )
        plr_app_pct: Optional[float] = (
            max(0.0, 100.0 - pdr_app_pct) if pdr_app_pct is not None else None
        )

        ro = self.routing_tx_count / sent if sent else None
        nrl = self.routing_tx_count / recv if recv else None

        # Non-QoS per pesan (sesuai Aturan Keras 3 & 4)
        eff_proto = proto_hint
        if eff_proto == "Unknown" and len(self.protocols) == 1:
            eff_proto = next(iter(self.protocols))

        hello_msgs: Optional[int] = None
        tc_msgs: Optional[int] = None
        rreq_msgs: Optional[int] = None
        rrep_msgs: Optional[int] = None
        rerr_msgs: Optional[int] = None
        aodv_hello_msgs: Optional[int] = None

        if eff_proto == "OLSR" or "OLSR" in self.protocols:
            if self.olsr_msg_parsed or self.routing_tx_count == 0:
                hello_msgs = self.olsr_hello_msgs
                tc_msgs = self.olsr_tc_msgs
        if eff_proto == "AODV" or "AODV" in self.protocols:
            if self.aodv_msg_parsed or self.routing_tx_count == 0:
                rreq_msgs = self.aodv_rreq_msgs
                rrep_msgs = self.aodv_rrep_msgs
                rerr_msgs = self.aodv_rerr_msgs
                aodv_hello_msgs = self.aodv_hello_msgs

        # DoS
        n_dos = len(self.dos_keys)
        dos_rate_mbps: Optional[float] = None
        attacker_node: Optional[int] = None
        dos_id_gap: Optional[int] = None
        if n_dos == 0:
            dos_rate_mbps = 0.0
        else:
            if (self.dos_t_first is not None and self.dos_t_last is not None
                    and self.dos_t_last > self.dos_t_first):
                span = self.dos_t_last - self.dos_t_first
                dos_rate_mbps = self.dos_payload_bits / span / 1e6
            if self.dos_attacker_nodes:
                attacker_node = self.dos_attacker_nodes.most_common(1)[0][0]
            dos_id_gap = self.dos_id_gap

        # Diagnostik
        hops = [len(self.tx_nodes[k]) for k in self.legal_received if self.tx_nodes.get(k)]
        hop_count_mean = sum(hops) / len(hops) if hops else None
        loss_windows = self._compute_loss_windows()

        return {
            "Legal_Sent_App": legal_sent_app,
            "Legal_Sent": sent,
            "Layer3_Queue_Dropped": l3_queue_dropped,
            "Legal_Received": recv,
            "MultiHop_Received": multihop_received,
            "OneHop_PileUp_Received": one_hop_received,
            "MultiHop_Ratio_pct": multihop_ratio_pct,
            "Legal_Lost": sent - recv,
            "PDR_pct": pdr,
            "PLR_pct": plr,
            "PDR_App_pct": pdr_app_pct,
            "PLR_App_pct": plr_app_pct,
            "Avg_Delay_ms": sum(d_ms) / len(d_ms) if d_ms else None,
            "Median_Delay_ms": percentile(d_ms, 50),
            "P95_Delay_ms": percentile(d_ms, 95),
            "P99_Delay_ms": percentile(d_ms, 99),
            "Max_Delay_ms": d_ms[-1] if d_ms else None,
            "Throughput_kbps": thr,
            "Throughput_active_kbps": thr_active,
            "Active_Duration_s": active_dur if active_dur is not None else sim_dur,
            "Routing_Packets_Sent": self.routing_tx_count,
            "Routing_Bytes_Sent": self.routing_bytes,
            "Routing_Overhead": ro,
            "NRL": nrl,
            "HELLO_Msgs": hello_msgs,
            "TC_Msgs": tc_msgs,
            "RREQ_Msgs": rreq_msgs,
            "RREP_Msgs": rrep_msgs,
            "RERR_Msgs": rerr_msgs,
            "Hello_Msgs": aodv_hello_msgs,
            "DoS_Packets_Detected": n_dos,
            "DoS_Rx_Events": self.dos_rx_events,
            "DoS_Unique_Packets_Recv": len(self.dos_unique_recv),
            "DoS_Rate_Observed_Mbps": dos_rate_mbps,
            "Attacker_Node": attacker_node,
            "DoS_Id_Gap": dos_id_gap,
            "MAC_Retry_Count": self.mac_retry_count,
            "MAC_Retry_Ratio": mac_retry_ratio,
            "Hop_Count_Mean": hop_count_mean,
            "Route_Change_Count": self.route_change_count,
            "Num_Loss_Windows": len(loss_windows),
            "Longest_Outage_s": longest_outage,
            "Num_Legal_Flows": len(self.legal_flows),
            "Trace_Last_Time_s": self.trace_last_time,
            "Legal_Drop_Events": "N/A" if self.phy_mode else self.legal_drop,
            "Unmatched_Legal_Recv": self.unmatched_recv,
            "Duplicate_Events": self.duplicates,
        }


# ---------------------------------------------------------------------------
# 4. Parser NS-3 Native ASCII Trace
# ---------------------------------------------------------------------------

#: Header event NS-3. Mendukung dua varian:
#:   MAC/queue trace : ``+ 1.23 /NodeList/0/...``
#:   PHY Wi-Fi trace : ``t 1.23 /NodeList/0/.../Phy/State/Tx OfdmRate6Mbps ...``
#:                     ``r 1.23 OfdmRate6Mbps /NodeList/1/.../Phy/State/RxOk ...``
_NS3_HEAD = re.compile(r"^([+\-rdt])\s+(\S+)\s+(?:[^/\s]\S*\s+)?/NodeList/(\d+)/")
_NS3_DA = re.compile(r"DA\(RA\)=([0-9a-fA-F:]{17})")
_NS3_RETRY = re.compile(r"Retry=1")
_NS3_IPV4 = re.compile(
    r"ns3::Ipv4Header\s*\((.*?)length:\s*(\d+)\s+(\d+\.\d+\.\d+\.\d+)\s*>\s*(\d+\.\d+\.\d+\.\d+)\)")
_NS3_PROTO = re.compile(r"protocol\s+(\d+)")
_NS3_ID = re.compile(r"\bid\s+(\d+)")
_NS3_UDP = re.compile(r"ns3::UdpHeader\s*\(length:\s*(\d+)\s+(\d+)\s*>\s*(\d+)\)")
_NS3_PAYLOAD = re.compile(r"Payload\s*\((?:size=)?(\d+)\)")
_NS3_OLSR_MSG = re.compile(r"ns3::olsr::MessageHeader\s*\(type:\s*([A-Z_]+)")


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
                 (kunci: src,dst,sport,dport,IP-id,epoch); transmisi forwarder & retry diabaikan
                 pada ``Legal_Sent``, namun dicatat untuk ``MAC_Retry_Count``, ``Hop_Count_Mean``,
                 dan ``Route_Change_Count``.
      * Terima : event ``r`` di node tujuan akhir (node = oktet terakhir IP tujuan - ip_offset)
                 DAN ``DA(RA)`` frame = MAC node tersebut.
      * Kontrol: setiap event TX dengan port UDP 654 (AODV) / 698 (OLSR) per hop,
                 tidak termasuk retransmisi MAC (``Retry=1``). Pesan di dalam paket kontrol
                 dihitung per pesan (``HELLO_Msgs``, ``TC_Msgs`` untuk OLSR;
                 ``RREQ_Msgs``, ``RREP_Msgs``, ``RERR_Msgs``, ``Hello_Msgs`` untuk AODV).
      * DoS    : lihat :func:`classify_payload`. Setiap ``r`` paket DoS = 1 ``DoS_Rx_Events``.
    """

    def __init__(self, cfg: Config, tx_event: str = "+") -> None:
        self.cfg = cfg
        self.tx_event = tx_event
        pats = cfg.aodv_patterns
        self._re_aodv_rreq = re.compile(pats["rreq"], re.IGNORECASE)
        self._re_aodv_rrep = re.compile(pats["rrep"], re.IGNORECASE)
        self._re_aodv_rerr = re.compile(pats["rerr"], re.IGNORECASE)
        self._re_aodv_hello_exp = re.compile(pats["hello_explicit"], re.IGNORECASE)
        self._re_aodv_rrep_addrs = re.compile(pats["rrep_addrs"], re.IGNORECASE)

    def _addressed_to(self, mac_part: str, node: int, acc: Accumulator) -> bool:
        """True HANYA jika ``DA(RA)`` ada dan sama dengan MAC ``node``."""
        da = _NS3_DA.search(mac_part)
        if not da:
            acc.missing_da += 1
            return False
        return _mac_to_int(da.group(1)) - self.cfg.ip_offset == node

    def _parse_control_messages(
        self,
        ctl: str,
        tail: str,
        node: int,
        dst_ip: str,
        acc: Accumulator,
    ) -> None:
        """Hitung pesan kontrol per pesan (bukan per paket) untuk OLSR dan AODV."""
        if ctl == "OLSR":
            types = _NS3_OLSR_MSG.findall(tail)
            if types:
                acc.olsr_msg_parsed = True
                for tp in types:
                    if tp == "HELLO":
                        acc.olsr_hello_msgs += 1
                        acc.olsr_hello_by_node[node] += 1
                    elif tp == "TC":
                        acc.olsr_tc_msgs += 1
                        acc.olsr_tc_by_node[node] += 1
        elif ctl == "AODV":
            # TODO: Verifikasi terhadap trace AODV hasil eksekusi penuh SUMO+NS-3.
            # Mendukung cetakan standar NS-3 (ns3::aodv::TypeHeader + Rreq/Rrep/RerrHeader)
            # di mana AODV Hello adalah RREP dengan destination == source (origin) (RFC 3561).
            matched = False
            if self._re_aodv_hello_exp.search(tail):
                acc.aodv_hello_msgs += 1
                acc.aodv_msgs_by_node["HELLO"][node] += 1
                matched = True
            elif self._re_aodv_rreq.search(tail):
                acc.aodv_rreq_msgs += 1
                acc.aodv_msgs_by_node["RREQ"][node] += 1
                matched = True
            elif self._re_aodv_rerr.search(tail):
                acc.aodv_rerr_msgs += 1
                acc.aodv_msgs_by_node["RERR"][node] += 1
                matched = True
            elif self._re_aodv_rrep.search(tail):
                matched = True
                m_addr = self._re_aodv_rrep_addrs.search(tail)
                if m_addr:
                    rrep_dst, rrep_orig = m_addr.group(1), m_addr.group(2)
                    is_hello = (rrep_dst == rrep_orig)
                else:
                    is_hello = is_broadcast_ip(dst_ip)
                if is_hello:
                    acc.aodv_hello_msgs += 1
                    acc.aodv_msgs_by_node["HELLO"][node] += 1
                else:
                    acc.aodv_rrep_msgs += 1
                    acc.aodv_msgs_by_node["RREP"][node] += 1
            if matched:
                acc.aodv_msg_parsed = True

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
        acc.touch_trace_time(t)

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
        tail = rest[udp.end():]

        # --- kontrol routing (Non-QoS) ---
        ctl = ROUTING_PORTS.get(sport) or ROUTING_PORTS.get(dport)
        if ctl:
            acc.protocols.add(ctl)
            if ev == "tx" and not _NS3_RETRY.search(mac_part):
                acc.routing_tx(ip_len)
                self._parse_control_messages(ctl, tail, node, dst, acc)
            return True

        # --- trafik data: legal vs DoS ---
        pl = _NS3_PAYLOAD.search(tail)
        size = int(pl.group(1)) if pl else max(udp_len - 8, 0)
        idm = _NS3_ID.search(body)
        ipid_str = idm.group(1) if idm else "0"
        base = (src, dst, sport, dport, ipid_str)
        cls = classify_payload(size, src, dst, t, self.cfg)

        if cls == OTHER:
            if ev == "tx" and is_broadcast_ip(dst) and in_dos_size(size, self.cfg):
                acc.dos_rejected += 1          # kandidat DoS yang gagal kriteria waktu/attacker
            return True

        key = acc.resolve_key(base, t, ev == "tx")
        if ev == "tx":
            is_retry = bool(_NS3_RETRY.search(mac_part))
            if cls == LEGAL:
                da_m = _NS3_DA.search(mac_part)
                da_mac = da_m.group(1).lower() if da_m else None
                acc.legal_tx_attempt(key, t, node, src, dst, dport, da_mac, is_retry)
            else:
                if not is_retry:
                    acc.dos_send(
                        key,
                        t=t,
                        size=size,
                        src_node=ip_to_node(src, self.cfg),
                        ipid=int(ipid_str) if ipm_digits(ipid_str) else None,
                    )
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


def ipm_digits(s: str) -> bool:
    return bool(s) and s.isdigit()


# ---------------------------------------------------------------------------
# 5. Pemrosesan file & batch
# ---------------------------------------------------------------------------

def check_ns3_format(path: Path) -> str:
    """Pastikan file adalah NS-3 ASCII trace dan tentukan event TX yang dipakai."""
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
    """Proses satu file trace menjadi satu baris hasil (dict mencakup seluruh kolom)."""
    meta = extract_metadata(path, root, strict=cfg.strict)
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
    elif not meta.ofat_detected and cfg.strict:
        status = "WARN: metadata tidak terdeteksi"
    elif corrupt:
        status = f"OK ({corrupt} baris korup diabaikan)"

    if phy_mode and lost > 0 and not status.startswith("WARN"):
        status += " [PHY: tanpa event drop, loss = Sent - Received]"

    legal_sent_app = read_flowmon_legal_sent_app(path, cfg.flowmon_xml, cfg.legal_port)

    row: Dict[str, object] = {
        "File": path.name,
        "Path": str(path),
        "Protokol": meta.protokol,
        "Kondisi": meta.kondisi,
        "Kelompok_OFAT": meta.kelompok,
        "Variabel_Uji": meta.variabel,
        "Nilai_Variabel": meta.nilai,
        "Jumlah_Node": meta.nodes,
        "Jarak_m": meta.dist,
        "Kecepatan_kmh": meta.speed,
        "Mode_Kecepatan": meta.mode_kecepatan,
        "Kecepatan_Min": meta.kec_min,
        "Kecepatan_Max": meta.kec_max,
        "Is_Baseline": meta.is_baseline,
        "Run": meta.run,
        "Seed": meta.seed,
        "Lines_Total": total,
        "Lines_Ignored": ignored,
        "Lines_Corrupt": corrupt,
        "Status": status,
        "Meta_Warning": "; ".join(meta.warnings),
        "First_Corrupt_Line": first_error,
    }
    row.update(acc.metrics(proto_hint=meta.protokol, legal_sent_app_override=legal_sent_app))
    row["_sort"] = meta.sort_key()
    row["_detail"] = acc.detail_summary()
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
    """Konversi dictionary metrik internal ke format 17 kolom skrip C++ simulasi NS-3."""
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
        csv_format:
            - 'sim'  : 62 kolom standar simulasi PHY (tanpa Legal_Drop_Events).
            - 'full' : 63 kolom lengkap (termasuk Legal_Drop_Events untuk trace MAC/queue).
            - 'cc'   : 17 kolom ringkasan bawaan skrip C++ NS-3.
        cfg: Konfigurasi parser.
    """
    out_path.parent.mkdir(parents=True, exist_ok=True)
    if csv_format == "cc":
        fields = CC_CSV_FIELDS
    elif csv_format == "full":
        fields = FULL_CSV_FIELDS
    else:
        fields = SIM_CSV_FIELDS

    with out_path.open("w", encoding="utf-8", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=fields, extrasaction="ignore")
        w.writeheader()
        for r in rows:
            src = to_sim_row(r, cfg) if csv_format == "cc" else r
            clean = {}
            for k in fields:
                v = src.get(k)
                if v is None:
                    v = ""
                elif isinstance(v, float):
                    v = round(v, 4)
                clean[k] = v
            w.writerow(clean)


def write_detail_json(rows: List[Dict[str, object]], json_path: Path) -> None:
    """Ekspor detail diagnostik per file trace ke format JSON."""
    json_path.parent.mkdir(parents=True, exist_ok=True)
    payload = {}
    for r in rows:
        fname = str(r.get("File", ""))
        payload[fname] = {
            "Path": r.get("Path"),
            "Protokol": r.get("Protokol"),
            "Kondisi": r.get("Kondisi"),
            "Kelompok_OFAT": r.get("Kelompok_OFAT"),
            "Nilai_Variabel": r.get("Nilai_Variabel"),
            "Seed": r.get("Seed"),
            **(r.get("_detail") or {}),
        }
    with json_path.open("w", encoding="utf-8") as fh:
        json.dump(payload, fh, indent=2, ensure_ascii=False)


# ---------------------------------------------------------------------------
# 6. CLI
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
    p.add_argument("--format", choices=["sim", "full", "cc"], default="sim",
                   help="format kolom CSV: 'sim' (default, 62 kolom PHY tanpa Legal_Drop_Events), "
                        "'full' (63 kolom termasuk Legal_Drop_Events untuk trace MAC/queue), "
                        "atau 'cc' (17 kolom ringkasan C++ NS-3)")
    p.add_argument("--strict", action="store_true",
                   help="jika token OFAT tidak terdeteksi pada nama file/path, beri "
                        "Status='WARN: metadata tidak terdeteksi' dan jangan asumsikan Baseline")
    p.add_argument("--flowmon-xml", default=None, metavar="XML_OR_DIR",
                   help="(opsional) file FlowMonitor XML atau folder XML untuk mengisi Legal_Sent_App")
    p.add_argument("--detail-json", default=None, metavar="JSON",
                   help="(opsional) ekspor retry per node, distribusi jalur relay, dan daftar "
                        "jendela loss ke file JSON")
    p.add_argument("--ext", nargs="+", default=[".tr"], metavar="EXT",
                   help="ekstensi file trace yang dipindai (default: .tr)")
    p.add_argument("--legal-size", type=int, default=512, help="payload data legal, byte (default 512)")
    p.add_argument("--dos-size", type=int, default=1024, help="payload paket DoS, byte (default 1024)")
    p.add_argument("--size-tol", type=int, default=60,
                   help="toleransi di atas payload nominal, byte (default 60)")
    p.add_argument("--ip-offset", type=int, default=1,
                   help="node_id = oktet terakhir IP - offset (default 1)")
    p.add_argument("--duration", type=float, default=222.0,
                   help="durasi simulasi (detik) untuk Throughput_kbps (default: 222.0; "
                        "isi 0 untuk memakai Active_Duration_s)")
    p.add_argument("--dos-start", type=float, default=5.0,
                   help="awal jendela serangan DoS, detik (default 5.0)")
    p.add_argument("--dos-end", type=float, default=float("inf"),
                   help="akhir jendela serangan DoS, detik (default: inf / sampai simulasi berakhir sesuai Proposal)")
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
    dur = args.duration if (args.duration is not None and args.duration > 0) else None
    cfg = Config(
        legal_size=args.legal_size,
        dos_size=args.dos_size,
        size_tol=args.size_tol,
        ip_offset=args.ip_offset,
        duration=dur,
        dos_start=args.dos_start,
        dos_end=args.dos_end,
        attacker_node=args.attacker_node,
        attacker_ip=args.attacker_ip,
        id_reuse_window=args.id_reuse_window,
        strict=args.strict,
        flowmon_xml=args.flowmon_xml,
        extensions=ext,
    )
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
            meta = extract_metadata(path, root, strict=cfg.strict)
            row = {
                "File": path.name,
                "Path": str(path),
                "Protokol": meta.protokol,
                "Kondisi": meta.kondisi,
                "Kelompok_OFAT": meta.kelompok,
                "Variabel_Uji": meta.variabel,
                "Nilai_Variabel": meta.nilai,
                "Jumlah_Node": meta.nodes,
                "Jarak_m": meta.dist,
                "Kecepatan_kmh": meta.speed,
                "Mode_Kecepatan": meta.mode_kecepatan,
                "Kecepatan_Min": meta.kec_min,
                "Kecepatan_Max": meta.kec_max,
                "Is_Baseline": meta.is_baseline,
                "Run": meta.run,
                "Seed": meta.seed,
                "Status": f"ERROR: {exc}",
                "Meta_Warning": "; ".join(meta.warnings),
                "_sort": meta.sort_key(),
                "_detail": {},
            }
        rows.append(row)
        _print_row(i, len(targets), row)

    rows.sort(key=lambda r: r["_sort"])
    out = Path(args.output)
    write_csv(rows, out, csv_format=args.format, cfg=cfg)
    if args.detail_json:
        write_detail_json(rows, Path(args.detail_json))

    n_warn = sum(1 for r in rows if str(r["Status"]).startswith("WARN") or r.get("Meta_Warning"))
    print("-" * len(_TABLE_HEAD))
    print(f"Selesai: {len(rows) - n_err} sukses, {n_err} error, {n_warn} dengan peringatan.")
    print(f"CSV     : {out.resolve()} (Format: {args.format.upper()})")
    if args.detail_json:
        print(f"JSON    : {Path(args.detail_json).resolve()}")
    for r in rows:
        if r.get("Meta_Warning"):
            print(f"  [!] {r['File']}: {r['Meta_Warning']}")
    return 0 if n_err == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
