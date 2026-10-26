#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
vanet_trace_parser_ns3.py
=========================
Parser single-pass streaming (100% Python Standard Library) untuk seluruh 40 file trace (.tr)
simulasi VANET NS-3 (AODV vs OLSR | Normal vs DoS) dengan pemotongan jendela fase multi-hop
(T_direct) guna memisahkan efek penumpukan akhir jalan (OneHop_PileUp_Received).
"""

from __future__ import annotations

import argparse
import csv
import importlib
import math
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
# token -> (Kelompok_OFAT, Variabel_Uji, Nilai_Variabel, Nodes, Dist_m, Speed_kmh, MaxRange_m, Default_T_direct_s)
SCENARIO_MAP: Dict[str, Tuple[str, str, str, int, int, str, float, Optional[float]]] = {
    "baseline": ("Baseline", "Baseline",      "Baseline", 10, 200, "20",    250.0, None),
    "a-n20":    ("A",        "Kepadatan",     "20",       20, 200, "20",    250.0, 513.0),
    "a-n30":    ("A",        "Kepadatan",     "30",       30, 200, "20",    250.0, 694.0),
    "b-j100":   ("B",        "Jarak",         "100",      10, 100, "20",    350.0, 243.0),
    "b-j200":   ("B",        "Jarak",         "200",      10, 200, "20",    350.0, 315.0),
    "b-j300":   ("B",        "Jarak",         "300",      10, 300, "20",    350.0, 387.0),
    "b-j400":   ("B",        "Jarak",         "400",      10, 400, "20",    350.0, 459.0),
    "c-k30":    ("C",        "Kecepatan",     "30",       10, 200, "30",    250.0, 223.0),
    "c-k40":    ("C",        "Kecepatan",     "40",       10, 200, "40",    250.0, 168.0),
    "d":        ("D",        "Heterogenitas", "15-25",    10, 200, "15-25", 250.0, 312.0),
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
    "MaxRange_m",
    "T_direct_s",
    "Window_Duration_s",
    "Tx_Packets",
    "Rx_Packets",
    "Lost_Packets",
    "OneHop_PileUp_Received",
    "Hop_Count_Mean",
    "Throughput_kbps",
    "PDR_pct",
    "PLR_pct",
    "Avg_Delay_ms",
    "Routing_Overhead_Pkts",
    "RO_per_s",
    "NRL_Ratio",
]

SERIES_STYLE = [
    ("AODV", "Normal", "AODV-Normal", "#1f77b4", "-", "o"),
    ("AODV", "DoS",    "AODV-DoS",    "#d62728", "--", "s"),
    ("OLSR", "Normal", "OLSR-Normal", "#2ca02c", "-", "^"),
    ("OLSR", "DoS",    "OLSR-DoS",    "#ff7f0e", "--", "D"),
]


# ------------------------------------------------------------------------------
# KALKULASI T_direct DARI FILE MOBILITAS .tcl (JIKA TERSEDIA)
# ------------------------------------------------------------------------------
def compute_t_direct_from_tcl(tcl_path: Path, n_nodes: int, max_range: float) -> Optional[float]:
    """Hitung detik pertama saat jarak Euclidean node_(0) ke node_(N-2) <= max_range dari file .tcl."""
    if not tcl_path.is_file():
        return None

    init_re = re.compile(r"^\$node_\((\d+)\)\s+set\s+([XYZ])_\s+([+\-\d.eE]+)")
    dest_re = re.compile(
        r'^\$ns_\s+at\s+([+\-\d.eE]+)\s+"\$node_\((\d+)\)\s+setdest\s+([+\-\d.eE]+)\s+([+\-\d.eE]+)\s+([+\-\d.eE]+)"'
    )
    target_nodes = {0, n_nodes - 2}
    pos: Dict[int, List[float]] = {0: [0.0, 0.0], n_nodes - 2: [0.0, 0.0]}
    segs: Dict[int, List[Tuple[float, float, float, float, float, float]]] = {0: [], n_nodes - 2: []}
    max_t = 0.0

    with tcl_path.open("r", encoding="utf-8", errors="replace") as fh:
        for line in fh:
            line = line.strip()
            m1 = init_re.match(line)
            if m1:
                nid, axis, val = int(m1.group(1)), m1.group(2), float(m1.group(3))
                if nid in target_nodes and axis in ("X", "Y"):
                    pos[nid][0 if axis == "X" else 1] = val
                continue
            m2 = dest_re.match(line)
            if m2:
                t0, nid, dx, dy, spd = (
                    float(m2.group(1)),
                    int(m2.group(2)),
                    float(m2.group(3)),
                    float(m2.group(4)),
                    float(m2.group(5)),
                )
                if nid in target_nodes:
                    x0, y0 = pos[nid] if not segs[nid] else (segs[nid][-1][3], segs[nid][-1][4])
                    dist = math.hypot(dx - x0, dy - y0)
                    t1 = t0 + (dist / spd) if spd > 0 else t0
                    segs[nid].append((t0, x0, y0, dx, dy, t1))
                    if t1 > max_t:
                        max_t = t1

    def interp(nid: int, t: float) -> Tuple[float, float]:
        if not segs[nid]:
            return pos[nid][0], pos[nid][1]
        for t0, x0, y0, dx, dy, t1 in segs[nid]:
            if t <= t0:
                return x0, y0
            if t <= t1:
                if t1 <= t0:
                    return dx, dy
                r = (t - t0) / (t1 - t0)
                return x0 + r * (dx - x0), y0 + r * (dy - y0)
        return segs[nid][-1][3], segs[nid][-1][4]

    t_cur = 0.0
    while t_cur <= max_t + 1.0:
        x0, y0 = interp(0, t_cur)
        x1, y1 = interp(n_nodes - 2, t_cur)
        if math.hypot(x1 - x0, y1 - y0) <= max_range:
            return round(t_cur, 4)
        t_cur += 0.1
    return None


# ------------------------------------------------------------------------------
# 1. FUNGSI UNIVERSAL PARSING (Single-Pass Streaming dengan Pemotongan T_direct)
# ------------------------------------------------------------------------------
def parse_trace(
    filepath: Path,
    t_direct: Optional[float] = None,
    app_start_s: float = 5.0,
    legal_port: int = 9,
    legal_size: int = 512,
    id_wrap_window: float = 60.0,
) -> Dict[str, Any]:
    """
    Baca satu file trace .tr secara streaming (single-pass) dan hitung metrik pada jendela
    fase multi-hop (t_tx < T_direct). Paket 1-hop di fase tumpukan akhir disimpan terpisah
    pada kolom OneHop_PileUp_Received.
    """
    cutoff = t_direct if t_direct is not None else float("inf")
    tx_times: Dict[Tuple[str, str, int, int], float] = {}
    rx_seen: set[Tuple[str, str, int, int]] = set()
    pileup_seen: set[Tuple[str, str, int, int]] = set()
    epochs: Dict[Tuple[str, str, int], List[float]] = {}

    delay_sum_s: float = 0.0
    hop_sum: int = 0
    ro_packets: int = 0
    last_trace_t: float = 0.0

    with filepath.open("r", encoding="utf-8", errors="replace") as fh:
        for line in fh:
            if not line or line[0] not in ("t", "+", "r") or "Ipv4Header" not in line:
                continue

            m = LINE_RE.match(line)
            if not m:
                continue

            ev, ts_s, node_s, retry_s, da_mac, ttl_s, ipid_s, src, dst, ulen_s, sport_s, dport_s = m.groups()
            t = float(ts_s)
            if t > last_trace_t:
                last_trace_t = t

            node = int(node_s)
            is_retry = retry_s == "1"
            dport = int(dport_s)
            sport = int(sport_s)

            # 1. Paket Kontrol Routing (AODV=654, OLSR=698): dipotong sampai T_direct
            if sport in (654, 698) or dport in (654, 698):
                if ev in ("t", "+") and not is_retry and t < cutoff:
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

            # Kunci Tx End-to-End pada node0: hanya paket yang dikirim sebelum T_direct masuk jendela evaluasi
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
                if t < cutoff and uid not in tx_times:
                    tx_times[uid] = t

            # Kunci Rx End-to-End pada node penerima akhir (node N-2) + validasi MAC DA(RA)
            elif ev == "r" and node == dst_node:
                if not da_mac or (int(da_mac[-2:], 16) - 1) != dst_node:
                    continue
                ent = epochs.get(base_key)
                ep = int(ent[0]) if ent is not None else 0
                uid = (src, dst, ipid, ep)
                hop = 64 - int(ttl_s) + 1

                # Dokumentasikan paket fase pile-up 1-hop secara terpisah
                if hop == 1 and uid not in pileup_seen:
                    pileup_seen.add(uid)

                # Paket yang dikirim sebelum T_direct (termasuk yang tiba sedikit sesudah T_direct) tetap dihitung
                t0 = tx_times.get(uid)
                if t0 is not None and uid not in rx_seen and t >= t0:
                    rx_seen.add(uid)
                    delay_sum_s += (t - t0)
                    hop_sum += hop

    tx_count = len(tx_times)
    rx_count = len(rx_seen)
    lost_count = tx_count - rx_count
    pileup_count = len(pileup_seen)

    # Panjang jendela evaluasi = (T_direct - 5.0), atau (waktu akhir trace - 5.0) bila tidak pernah masuk 1-hop
    effective_end = t_direct if t_direct is not None else last_trace_t
    window_dur = max(0.0, effective_end - app_start_s)

    # Guard clauses defensif terhadap ZeroDivisionError (mis. jarak 400 m di luar jangkauan radio)
    pdr_pct = (rx_count / tx_count * 100.0) if tx_count > 0 else 0.0
    plr_pct = (lost_count / tx_count * 100.0) if tx_count > 0 else 100.0
    avg_delay_ms = (delay_sum_s / rx_count * 1000.0) if rx_count > 0 else 0.0
    hop_mean = (hop_sum / rx_count) if rx_count > 0 else 0.0
    throughput_kbps = (
        (rx_count * legal_size * 8.0) / (window_dur * 1000.0)
        if (rx_count > 0 and window_dur > 0.0)
        else 0.0
    )
    ro_per_s = (ro_packets / window_dur) if window_dur > 0.0 else 0.0
    nrl = (ro_packets / rx_count) if rx_count > 0 else 0.0

    return {
        "T_direct_s": round(t_direct, 2) if t_direct is not None else "FullRun",
        "Window_Duration_s": round(window_dur, 4),
        "Tx_Packets": tx_count,
        "Rx_Packets": rx_count,
        "Lost_Packets": lost_count,
        "OneHop_PileUp_Received": pileup_count,
        "Hop_Count_Mean": round(hop_mean, 4),
        "Throughput_kbps": round(throughput_kbps, 4),
        "PDR_pct": round(pdr_pct, 4),
        "PLR_pct": round(plr_pct, 4),
        "Avg_Delay_ms": round(avg_delay_ms, 4),
        "Routing_Overhead_Pkts": ro_packets,
        "RO_per_s": round(ro_per_s, 4),
        "NRL_Ratio": round(nrl, 4),
    }


# ------------------------------------------------------------------------------
# 2. FUNGSI EKSPOR MASTER DATASET CSV (Seluruh 40 File Trace)
# ------------------------------------------------------------------------------
def export_master_csv(
    trace_dir: Path,
    csv_path: Path,
    tcl_dir: Optional[Path] = None,
) -> List[Dict[str, Any]]:
    """Parse seluruh 40 file trace .tr dengan batas T_direct per skenario dan simpan ke Master CSV."""
    matched_files: List[Tuple[str, str, str, Path]] = []

    for p in sorted(trace_dir.rglob("*.tr")):
        m = FILE_RE.match(p.stem)
        if not m:
            continue
        proto, tok, cond = m.group(1).upper(), m.group(2).lower(), m.group(3).lower()
        cond_label = "DoS" if cond == "dos" else "Normal"
        matched_files.append((proto, cond_label, tok, p))

    rows: List[Dict[str, Any]] = []
    total = len(matched_files)

    for idx, (proto, cond, tok, path) in enumerate(matched_files, 1):
        grp, var_name, val_str, nodes, dist, speed, max_range, default_tdirect = SCENARIO_MAP[tok]

        # Jika direktori .tcl diberikan dan ada file .tcl skenario terkait, hitung T_direct dari .tcl
        t_direct = default_tdirect
        if tcl_dir is not None:
            tcl_candidate = tcl_dir / f"{tok}.tcl"
            if tcl_candidate.is_file():
                t_direct = compute_t_direct_from_tcl(tcl_candidate, nodes, max_range)

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
            "MaxRange_m": int(max_range),
            **metrics,
        }
        rows.append(row)
        print(
            f"[{idx:02d}/{total:02d}] {path.name:<26} | {proto:<4} {cond:<6} | "
            f"Grp={grp:<8} Val={val_str:<8} T_dir={str(metrics['T_direct_s']):<7} | "
            f"Tx={metrics['Tx_Packets']:>6} Rx={metrics['Rx_Packets']:>6} PileUp={metrics['OneHop_PileUp_Received']:>4} "
            f"PDR={metrics['PDR_pct']:>6.2f}% Delay={metrics['Avg_Delay_ms']:>6.2f}ms "
            f"Tput={metrics['Throughput_kbps']:>6.2f}kbps RO/s={metrics['RO_per_s']:>6.2f} NRL={metrics['NRL_Ratio']:>8.2f}"
        )

    csv_path.parent.mkdir(parents=True, exist_ok=True)
    with csv_path.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=CSV_COLUMNS, quoting=csv.QUOTE_MINIMAL)
        writer.writeheader()
        writer.writerows(rows)

    print(f"\n[+] Master Dataset CSV tersimpan: {csv_path.resolve()} ({len(rows)} baris skenario)")
    return rows


# ------------------------------------------------------------------------------
# 3. FUNGSI MODULAR VISUALISASI GRAFIK PER KELOMPOK UJI (A, B, C, D)
# ------------------------------------------------------------------------------
def generate_plots(rows: List[Dict[str, Any]], out_dir: Path) -> List[Path]:
    """
    Buat 4 grafik PNG (Kelompok A, B, C, D).
    - Kelompok A (10*, 20, 30), C (20*, 30, 40), dan D menggunakan referensi Baseline (maxRange=250m).
    - Kelompok B (100, 200*, 300, 400) menggunakan 4 file Kelompok B termasuk b-j200 (maxRange=350m).
    """
    matplotlib = importlib.import_module("matplotlib")
    matplotlib.use("Agg")
    plt = importlib.import_module("matplotlib.pyplot")

    out_dir.mkdir(parents=True, exist_ok=True)
    saved: List[Path] = []
    base_rows = [r for r in rows if r["Kelompok_OFAT"] == "Baseline"]

    # (Judul, Label_X, Nilai_Baseline_Jika_Direuse, Daftar_Ticks_X)
    line_groups: Dict[str, Tuple[str, str, Optional[str], List[int]]] = {
        "A": ("Kelompok A - Variasi Kepadatan Kendaraan (Fase Multi-Hop)", "Jumlah Node Kendaraan", "10", [10, 20, 30]),
        "B": ("Kelompok B - Variasi Jarak Antar Barisan (Fase Multi-Hop)", "Jarak Antar Barisan (m)", None, [100, 200, 300, 400]),
        "C": ("Kelompok C - Variasi Kecepatan Seragam (Fase Multi-Hop)",   "Kecepatan Kendaraan (km/jam)", "20", [20, 30, 40]),
    }

    panel_specs = [
        ("PDR_pct",         "Packet Delivery Ratio (PDR)",          "PDR (%)",                 False),
        ("PLR_pct",         "Packet Loss Ratio (PLR)",              "PLR (%)",                 False),
        ("Avg_Delay_ms",    "Average End-to-End Delay",             "Delay (ms)",              False),
        ("Throughput_kbps", "Throughput Fase Multi-Hop (kbps)",     "Throughput (kbps)",       False),
        ("RO_per_s",        "Routing Overhead per Detik (RO/s)",    "Paket Kontrol / s (log)", True),
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
    ap = argparse.ArgumentParser(description="Parser & Visualisasi VANET NS-3 (40 File + Pemotongan T_direct).")
    ap.add_argument("-d", "--dir", default=r"c:\Perkuliahan\PBL\hasil_Simulasi", help="Folder 40 file trace .tr")
    ap.add_argument("-o", "--output", default="master_vanet_40_skenario.csv", help="File Master CSV keluaran")
    ap.add_argument("--plot-dir", default="hasil_agregasi_40_skenario", help="Folder keluaran grafik PNG")
    ap.add_argument("--tcl-dir", default=None, help="Folder opsional file mobilitas .tcl untuk hitung T_direct")
    args = ap.parse_args()

    tcl_dir = Path(args.tcl_dir) if args.tcl_dir else None
    rows = export_master_csv(Path(args.dir), Path(args.output), tcl_dir=tcl_dir)
    if rows:
        plots = generate_plots(rows, Path(args.plot_dir))
        for p in plots:
            print(f"[+] Grafik tersimpan: {p.resolve()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
