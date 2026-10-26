#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
vanet_trace_parser_ns3.py
=========================
Parser single-pass streaming (100% Python Standard Library) untuk 40 file trace (.tr)
VANET NS-3 dengan pemotongan jendela fase multi-hop (T_direct) guna mengeliminasi bias
penumpukan kendaraan di ujung jalan (End-of-Road 1-Hop Pile-Up), sesuai spesifikasi Proposal PBL.
"""

from __future__ import annotations

import argparse
import csv
import importlib
import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

# Regex tunggal terkompilasi untuk ekstraksi cepat 1 baris trace PHY/MAC NS-3 (IPv4 + UDP + TTL)
LINE_RE = re.compile(
    r"^([t+r])\s+([+\d.eE\-]+)(?:ns|us|ms|s)?\s+.*?/NodeList/(\d+)/.*?"
    r"(?:Retry=(\d).*?)?(?:DA\(RA\)=([0-9a-fA-F:]{17}).*?)?"
    r"ns3::Ipv4Header\s*\(.*?ttl\s+(\d+)\s+id\s+(\d+)\s+protocol\s+17\s+.*?length:\s*\d+\s+"
    r"(\d+\.\d+\.\d+\.\d+)\s*>\s*(\d+\.\d+\.\d+\.\d+)\)\s*"
    r"ns3::UdpHeader\s*\(length:\s*(\d+)\s+(\d+)\s*>\s*(\d+)\)"
)

FILE_RE = re.compile(
    r"^(aodv|olsr)-(baseline|a-n(?:20|30)|b-j(?:100|200|300|400)|c-k(?:30|40)|d)-(normal|dos)$",
    re.IGNORECASE,
)

# Matriks 10 skenario (40 file .tr):
# token -> (Kelompok, Variabel, Nilai, Nodes, Dist_m, Speed_kmh, T_direct_s)
# T_direct_s adalah detik pertama saat jarak node0 ke penerima (node N-2) <= maxRange
# (250 m untuk Baseline/A/C/D, 350 m untuk Kelompok B). Nilainya identik untuk AODV & OLSR, Normal & DoS.
SCENARIO_MAP: Dict[str, Tuple[str, str, str, int, int, str, Optional[float]]] = {
    "baseline": ("Baseline", "Baseline",      "Baseline", 10, 200, "20",    None),
    "a-n20":    ("A",        "Kepadatan",     "20",       20, 200, "20",    512.992),
    "a-n30":    ("A",        "Kepadatan",     "30",       30, 200, "20",    692.972),
    "b-j100":   ("B",        "Jarak",         "100",      10, 100, "20",    243.022),
    "b-j200":   ("B",        "Jarak",         "200",      10, 200, "20",    314.989),
    "b-j300":   ("B",        "Jarak",         "300",      10, 300, "20",    386.916),
    "b-j400":   ("B",        "Jarak",         "400",      10, 400, "20",    459.137),
    "c-k30":    ("C",        "Kecepatan",     "30",       10, 200, "30",    223.068),
    "c-k40":    ("C",        "Kecepatan",     "40",       10, 200, "40",    167.532),
    "d":        ("D",        "Heterogenitas", "15-25",    10, 200, "15-25", 312.040),
}

CSV_COLUMNS = [
    "File",
    "Protokol",
    "Kondisi",
    "Kelompok_OFAT",
    "Variabel_Uji",
    "Nilai_Variabel",
    "Jumlah_Node",
    "Jarak_m",
    "Kecepatan_kmh",
    "T_direct_s",
    "Window_Duration_s",
    "Tx_Packets",
    "Rx_Packets",
    "Lost_Packets",
    "OneHop_PileUp_Received",
    "Throughput_kbps",
    "PDR_pct",
    "PLR_pct",
    "Avg_Delay_ms",
    "Avg_Hop_Count",
    "Routing_Overhead_Pkts",
    "RO_per_Sec",
    "NRL_Ratio",
]

SERIES_STYLE = [
    ("AODV", "Normal", "AODV-Normal", "#1f77b4", "-", "o"),
    ("AODV", "DoS",    "AODV-DoS",    "#d62728", "--", "s"),
    ("OLSR", "Normal", "OLSR-Normal", "#2ca02c", "-", "^"),
    ("OLSR", "DoS",    "OLSR-DoS",    "#ff7f0e", "--", "D"),
]


# ------------------------------------------------------------------------------
# 1. FUNGSI UNIVERSAL PARSING (Single-Pass Streaming dengan Pemotongan T_direct)
# ------------------------------------------------------------------------------
def parse_trace(
    filepath: Path,
    t_direct: Optional[float] = None,
    app_start: float = 5.0,
    legal_port: int = 9,
    legal_size: int = 512,
    id_wrap_window: float = 60.0,
) -> Dict[str, Any]:
    """
    Baca satu file trace .tr secara streaming (single-pass) dan hitung metrik QoS & Non-QoS
    pada jendela fase multi-hop [app_start, T_direct).
    - Paket data yang dikirim node0 sebelum T_direct (t_tx < T_direct) dihitung sebagai Tx_Packets,
      dan jika tiba di penerima (meskipun sedikit sesudah T_direct) tetap dicocokkan lewat UID sebagai Rx_Packets.
    - Paket data yang dikirim pada/sesudah T_direct (fase menumpuk di ujung jalan) dicatat terpisah
      pada kolom OneHop_PileUp_Received.
    """
    tx_times: Dict[Tuple[str, str, int, int], float] = {}
    rx_seen: set[Tuple[str, str, int, int]] = set()
    pileup_seen: set[Tuple[str, str, int, int]] = set()
    epochs: Dict[Tuple[str, str, int], List[float]] = {}

    t_last_trace: float = 0.0
    t_last_tx: float = 0.0
    delay_sum_s: float = 0.0
    hop_sum: int = 0
    ro_packets: int = 0

    with filepath.open("r", encoding="utf-8", errors="replace") as fh:
        for line in fh:
            # Fast C-level gate: lewati baris non-event atau frame MAC/ARP tanpa IPv4Header
            if not line or line[0] not in ("t", "+", "r") or "Ipv4Header" not in line:
                continue

            m = LINE_RE.match(line)
            if not m:
                continue

            ev, ts_s, node_s, retry_s, da_mac, ttl_s, ipid_s, src, dst, ulen_s, sport_s, dport_s = m.groups()
            t = float(ts_s)
            if t > t_last_trace:
                t_last_trace = t

            node = int(node_s)
            is_retry = retry_s == "1"
            dport = int(dport_s)
            sport = int(sport_s)

            # 1. Paket Kontrol Routing (AODV=654, OLSR=698): hitung sampai T_direct (bukan retry MAC)
            if sport in (654, 698) or dport in (654, 698):
                if ev in ("t", "+") and not is_retry and (t_direct is None or t < t_direct):
                    ro_packets += 1
                continue

            # 2. Filter Traffic DoS: abaikan seluruh paket UDP broadcast (255.255.255.255 / *.255)
            if dst == "255.255.255.255" or dst.endswith(".255"):
                continue

            # 3. Validasi Aliran Paket V2V CBR Legal (Unicast, Port 9, Payload ~512 B)
            payload_size = int(ulen_s) - 8
            if dport != legal_port or not (legal_size <= payload_size <= legal_size + 60):
                continue

            src_node = int(src.rsplit(".", 1)[1]) - 1
            dst_node = int(dst.rsplit(".", 1)[1]) - 1
            ipid = int(ipid_s)
            base_key = (src, dst, ipid)

            # Kunci Tx End-to-End hanya pada node pengirim awal (node 0 di barisan paling depan)
            if ev in ("t", "+"):
                if is_retry or node != src_node:
                    continue
                ent = epochs.get(base_key)
                if ent is None:
                    epochs[base_key] = [0.0, t]
                    ep = 0
                else:
                    if t - ent[1] > id_wrap_window:
                        ent[0] += 1.0
                    ent[1] = t
                    ep = int(ent[0])

                uid = (src, dst, ipid, ep)
                if uid not in tx_times:
                    tx_times[uid] = t
                    if t > t_last_tx:
                        t_last_tx = t

            # Kunci Rx End-to-End hanya pada node tujuan akhir (node N-2) + validasi MAC DA(RA)
            elif ev == "r" and node == dst_node:
                if not da_mac or (int(da_mac[-2:], 16) - 1) != dst_node:
                    continue
                ent = epochs.get(base_key)
                ep = int(ent[0]) if ent is not None else 0
                uid = (src, dst, ipid, ep)
                t0 = tx_times.get(uid)
                if t0 is not None and t >= t0:
                    # Potong berdasarkan waktu kirim paket (t0 < T_direct)
                    if t_direct is None or t0 < t_direct:
                        if uid not in rx_seen:
                            rx_seen.add(uid)
                            delay_sum_s += (t - t0)
                            ttl_val = int(ttl_s)
                            hop_sum += max(1, 64 - ttl_val + 1) if ttl_val <= 64 else 1
                    else:
                        pileup_seen.add(uid)

    # Hitung hanya paket yang dikirim sebelum T_direct
    tx_count = sum(1 for t0 in tx_times.values() if t_direct is None or t0 < t_direct)
    rx_count = len(rx_seen)
    lost_count = tx_count - rx_count
    pileup_count = len(pileup_seen)

    # Panjang jendela waktu multi-hop: (T_direct - 5.0), atau (t_end_cbr - 5.0) bila tidak pernah pile-up
    effective_end = t_direct if t_direct is not None else (t_last_tx if t_last_tx > app_start else max(t_last_trace - 2.0, app_start))
    window_dur = max(0.0, effective_end - app_start)

    # Guard clauses defensif terhadap ZeroDivisionError (mis. jarak 400 m di luar jangkauan 350 m)
    pdr_pct = (rx_count / tx_count * 100.0) if tx_count > 0 else 0.0
    plr_pct = (lost_count / tx_count * 100.0) if tx_count > 0 else 100.0
    avg_delay_ms = (delay_sum_s / rx_count * 1000.0) if rx_count > 0 else 0.0
    avg_hop = (hop_sum / rx_count) if rx_count > 0 else 0.0
    throughput_kbps = (
        (rx_count * legal_size * 8.0) / (window_dur * 1000.0)
        if (rx_count > 0 and window_dur > 0.0)
        else 0.0
    )
    ro_per_sec = (ro_packets / window_dur) if window_dur > 0.0 else 0.0
    nrl = (ro_packets / rx_count) if rx_count > 0 else 0.0

    return {
        "T_direct_s": round(t_direct, 3) if t_direct is not None else "Full_Run",
        "Window_Duration_s": round(window_dur, 3),
        "Tx_Packets": tx_count,
        "Rx_Packets": rx_count,
        "Lost_Packets": lost_count,
        "OneHop_PileUp_Received": pileup_count,
        "Throughput_kbps": round(throughput_kbps, 4),
        "PDR_pct": round(pdr_pct, 4),
        "PLR_pct": round(plr_pct, 4),
        "Avg_Delay_ms": round(avg_delay_ms, 4),
        "Avg_Hop_Count": round(avg_hop, 4),
        "Routing_Overhead_Pkts": ro_packets,
        "RO_per_Sec": round(ro_per_sec, 4),
        "NRL_Ratio": round(nrl, 4),
    }


# ------------------------------------------------------------------------------
# 2. FUNGSI EKSPOR MASTER DATASET CSV (Seluruh 40 File Trace)
# ------------------------------------------------------------------------------
def export_master_csv(trace_dir: Path, csv_path: Path) -> List[Dict[str, Any]]:
    """Parse seluruh 40 file trace (.tr) pada jendela multi-hop T_direct dan ekspor ke Master CSV."""
    files: List[Tuple[str, str, str, Path]] = []

    for p in sorted(trace_dir.rglob("*.tr")):
        m = FILE_RE.match(p.stem)
        if not m:
            continue
        proto, tok, cond = m.group(1).upper(), m.group(2).lower(), m.group(3).lower()
        cond_label = "DoS" if cond == "dos" else "Normal"
        files.append((proto, cond_label, tok, p))

    rows: List[Dict[str, Any]] = []
    total = len(files)
    for idx, (proto, cond, tok, path) in enumerate(files, 1):
        grp, var_name, val_str, nodes, dist, speed, t_direct = SCENARIO_MAP[tok]
        metrics = parse_trace(path, t_direct=t_direct)
        row: Dict[str, Any] = {
            "File": path.name,
            "Protokol": proto,
            "Kondisi": cond,
            "Kelompok_OFAT": grp,
            "Variabel_Uji": var_name,
            "Nilai_Variabel": val_str,
            "Jumlah_Node": nodes,
            "Jarak_m": dist,
            "Kecepatan_kmh": speed,
            **metrics,
        }
        rows.append(row)
        print(
            f"[{idx:02d}/{total:02d}] {path.name:<26} | T_dir={str(metrics['T_direct_s']):<8} Win={metrics['Window_Duration_s']:>6.1f}s | "
            f"Tx={metrics['Tx_Packets']:>5} Rx={metrics['Rx_Packets']:>5} PileUp={metrics['OneHop_PileUp_Received']:>4} | "
            f"PDR={metrics['PDR_pct']:>6.2f}% Delay={metrics['Avg_Delay_ms']:>6.2f}ms "
            f"Tput={metrics['Throughput_kbps']:>6.2f}kbps RO/s={metrics['RO_per_Sec']:>5.2f}"
        )

    csv_path.parent.mkdir(parents=True, exist_ok=True)
    with csv_path.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=CSV_COLUMNS, quoting=csv.QUOTE_MINIMAL)
        writer.writeheader()
        writer.writerows(rows)

    print(f"\n[+] Master Dataset CSV tersimpan: {csv_path.resolve()} ({len(rows)} file skenario)")
    return rows


# ------------------------------------------------------------------------------
# 3. FUNGSI MODULAR VISUALISASI GRAFIK PER KELOMPOK UJI (A, B, C, D)
# ------------------------------------------------------------------------------
def generate_plots(rows: List[Dict[str, Any]], out_dir: Path) -> List[Path]:
    """
    Buat 4 grafik PNG komparasi (AODV vs OLSR | Normal vs DoS):
    - Kelompok A (10*, 20, 30 node) & C (20*, 30, 40 km/jam): memakai Baseline* (maxRange=250m)
    - Kelompok B (100, 200, 300, 400 m): memakai langsung b-j100..b-j400 (konsisten maxRange=350m)
    - Kelompok D (15-25 km/jam acak): dibandingkan terhadap Baseline* (20 km/jam seragam)
    """
    matplotlib = importlib.import_module("matplotlib")
    matplotlib.use("Agg")
    plt = importlib.import_module("matplotlib.pyplot")

    out_dir.mkdir(parents=True, exist_ok=True)
    saved: List[Path] = []
    base_rows = [r for r in rows if r["Kelompok_OFAT"] == "Baseline"]

    # (Judul, Label X, Nilai Baseline yang di-inject bila perlu, Ticks Sumbu-X)
    line_groups: Dict[str, Tuple[str, str, Optional[str], List[int]]] = {
        "A": ("Kelompok A - Variasi Kepadatan Kendaraan (Fase Multi-Hop)", "Jumlah Node Kendaraan", "10", [10, 20, 30]),
        "B": ("Kelompok B - Variasi Jarak Antar Barisan (Fase Multi-Hop)", "Jarak Antar Barisan (m)", None, [100, 200, 300, 400]),
        "C": ("Kelompok C - Variasi Kecepatan Seragam (Fase Multi-Hop)", "Kecepatan Kendaraan (km/jam)", "20", [20, 30, 40]),
    }

    panel_specs = [
        ("PDR_pct",         "Packet Delivery Ratio (PDR)",          "PDR (%)",                 False),
        ("PLR_pct",         "Packet Loss Ratio (PLR)",              "PLR (%)",                 False),
        ("Avg_Delay_ms",    "Average End-to-End Delay",             "Delay (ms)",              False),
        ("Throughput_kbps", "Throughput Jendela Multi-Hop (kbps)",  "Throughput (kbps)",       False),
        ("RO_per_Sec",      "Routing Overhead per Detik (RO/s)",    "Paket Kontrol / s (log)", True),
        ("NRL_Ratio",       "Normalized Routing Load (NRL)",        "NRL (rasio, log)",        True),
    ]

    for grp, (title, xlabel, base_val, x_ticks) in line_groups.items():
        sub = [r for r in rows if r["Kelompok_OFAT"] == grp]
        if base_val is not None:
            sub = [{**r, "Kelompok_OFAT": grp, "Nilai_Variabel": base_val} for r in base_rows] + sub

        fig, axes = plt.subplots(2, 3, figsize=(18, 9.5), dpi=150)
        fig.suptitle(title, fontsize=14, fontweight="bold")

        for ax, (col, ptitle, ylabel, use_log) in zip(axes.flat, panel_specs):
            has_pos = False
            for proto, cond, label, color, ls, marker in SERIES_STYLE:
                pts = sorted(
                    (float(r["Nilai_Variabel"]), float(r[col]))
                    for r in sub
                    if r["Protokol"] == proto and r["Kondisi"] == cond
                )
                if use_log:
                    pts = [(x, y) for x, y in pts if y > 0]
                    if pts:
                        has_pos = True
                if not pts:
                    continue
                xs = [p[0] for p in pts]
                ys = [p[1] for p in pts]
                ax.plot(xs, ys, label=label, color=color, linestyle=ls, marker=marker, linewidth=1.8, markersize=6)

            if use_log and has_pos:
                ax.set_yscale("log")
            elif col in ("PDR_pct", "PLR_pct"):
                ax.set_ylim(-5, 105)

            ax.set_title(ptitle, fontsize=11, fontweight="bold")
            ax.set_xlabel(xlabel)
            ax.set_ylabel(ylabel)
            ax.set_xticks(x_ticks)
            ax.grid(True, which="both" if use_log else "major", linestyle=":", alpha=0.6)
            ax.legend(fontsize=8.5)

        fig.tight_layout(rect=[0, 0, 1, 0.96])
        out_png = out_dir / f"grafik_kelompok_{grp}.png"
        fig.savefig(out_png)
        plt.close(fig)
        saved.append(out_png)

    # Kelompok D: Grafik Batang Terkelompok (Baseline 20 km/jam Seragam vs D 15-25 km/jam Acak)
    sub_d = base_rows + [r for r in rows if r["Kelompok_OFAT"] == "D"]
    if sub_d:
        fig, axes = plt.subplots(2, 3, figsize=(18, 9.5), dpi=150)
        fig.suptitle(
            "Kelompok D - Kecepatan Heterogen (15-25 km/jam) vs Baseline (20 km/jam Seragam) [Fase Multi-Hop]",
            fontsize=14, fontweight="bold",
        )
        cats = ["Baseline", "D"]
        cat_labels = ["Baseline\n(20 km/jam Seragam)", "Kelompok D\n(15-25 km/jam Acak)"]
        width = 0.18

        for ax, (col, ptitle, ylabel, use_log) in zip(axes.flat, panel_specs):
            has_pos = False
            for idx, (proto, cond, label, color, _, _) in enumerate(SERIES_STYLE):
                vals: List[float] = []
                for c in cats:
                    match = [
                        float(r[col])
                        for r in sub_d
                        if r["Kelompok_OFAT"] == c and r["Protokol"] == proto and r["Kondisi"] == cond
                    ]
                    v = match[0] if match else 0.0
                    if v > 0:
                        has_pos = True
                    vals.append(v)
                xs = [i + (idx - 1.5) * width for i in range(len(cats))]
                ax.bar(xs, vals, width, label=label, color=color, alpha=0.88)

            if use_log and has_pos:
                ax.set_yscale("log")
            elif col in ("PDR_pct", "PLR_pct"):
                ax.set_ylim(0, 108)

            ax.set_title(ptitle, fontsize=11, fontweight="bold")
            ax.set_xticks(list(range(len(cats))))
            ax.set_xticklabels(cat_labels)
            ax.set_ylabel(ylabel)
            ax.grid(True, axis="y", which="both" if use_log else "major", linestyle=":", alpha=0.6)
            ax.legend(fontsize=8.5)

        fig.tight_layout(rect=[0, 0, 1, 0.96])
        out_png = out_dir / "grafik_kelompok_D.png"
        fig.savefig(out_png)
        plt.close(fig)
        saved.append(out_png)

    return saved


def main() -> int:
    ap = argparse.ArgumentParser(description="Parser & Visualisasi 40 Skenario VANET NS-3 (T_direct Multi-Hop Cut).")
    ap.add_argument("-d", "--dir", default=r"c:\Perkuliahan\PBL\hasil_Simulasi", help="Folder file trace .tr")
    ap.add_argument("-o", "--output", default="master_vanet_40_skenario.csv", help="File Master CSV keluaran")
    ap.add_argument("--plot-dir", default="hasil_agregasi_40_skenario", help="Folder keluaran grafik PNG")
    args = ap.parse_args()

    rows = export_master_csv(Path(args.dir), Path(args.output))
    if rows:
        plots = generate_plots(rows, Path(args.plot_dir))
        for p in plots:
            print(f"[+] Grafik tersimpan: {p.resolve()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
