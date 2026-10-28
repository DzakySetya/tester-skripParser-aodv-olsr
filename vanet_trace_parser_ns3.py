#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
vanet_trace_parser_ns3.py
=========================
Skrip parser trace file (.tr) simulasi VANET NS-3 (AODV vs OLSR | Normal vs DoS)
dengan deteksi otomatis batas waktu fase multi-hop (T_direct) berdasarkan kemunculan
pertama paket 1-hop (TTL = 64) di node penerima akhir.
Hasil diekspor ke CSV untuk pembuatan grafik di Spreadsheet/Excel.
"""

import argparse
import csv
import re
from pathlib import Path

# Pola regex untuk membaca 1 baris paket IPv4/UDP dari file trace (.tr) NS-3
LINE_RE = re.compile(
    r"^([t+r])\s+([+\d.eE\-]+)(?:ns|us|ms|s)?\s+.*?/NodeList/(\d+)/.*?"
    r"(?:Retry=(\d).*?)?(?:DA\(RA\)=([0-9a-fA-F:]{17}).*?)?"
    r"ns3::Ipv4Header\s*\(.*?ttl\s+(\d+)\s+id\s+(\d+)\s+protocol\s+17\s+.*?length:\s*\d+\s+"
    r"(\d+\.\d+\.\d+\.\d+)\s*>\s*(\d+\.\d+\.\d+\.\d+)\)\s*"
    r"ns3::UdpHeader\s*\(length:\s*(\d+)\s+(\d+)\s*>\s*(\d+)\)"
)

# Pola nama file: mendukung 40 nama file skenario maupun nama default output .cc (*-mh-normal/dos.tr)
FILE_RE = re.compile(
    r"^(aodv|olsr)-(baseline|mh|a-n(?:20|30)|b-j(?:100|200|300|400)|c-k(?:30|40)|d)-(normal|dos)$",
    re.IGNORECASE,
)

# Metadata eksperimen OFAT sesuai Proposal PBL (tanpa hardcode T_direct):
# kode -> (Kelompok_OFAT, Variabel_Uji, Nilai_Variabel, Jumlah_Node, Jarak_m, Kecepatan_kmh, MaxRange_m)
SCENARIO_MAP = {
    "baseline": ("Baseline", "Baseline",      "Baseline", 10, 200, "20",    250),
    "a-n20":    ("A",        "Kepadatan",     "20",       20, 200, "20",    250),
    "a-n30":    ("A",        "Kepadatan",     "30",       30, 200, "20",    250),
    "b-j100":   ("B",        "Jarak",         "100",      10, 100, "20",    350),
    "b-j200":   ("B",        "Jarak",         "200",      10, 200, "20",    350),
    "b-j300":   ("B",        "Jarak",         "300",      10, 300, "20",    350),
    "b-j400":   ("B",        "Jarak",         "400",      10, 400, "20",    350),
    "c-k30":    ("C",        "Kecepatan",     "30",       10, 200, "30",    250),
    "c-k40":    ("C",        "Kecepatan",     "40",       10, 200, "40",    250),
    "d":        ("D",        "Heterogenitas", "15-25",    10, 200, "15-25", 250),
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


def parse_trace(filepath, t_direct=None, app_start_s=5.0, legal_port=9, legal_size=512, id_wrap_window=60.0):
    """
    Membaca satu file .tr secara single-pass dan menghitung metrik QoS serta Routing Overhead.
    Jika t_direct=None, batas waktu T_direct dideteksi otomatis dari detik pertama paket
    1-hop (TTL = 64) diterima oleh node tujuan akhir (node N-2).
    """
    cutoff = t_direct if t_direct is not None else float("inf")
    tx_times = {}
    rx_records = {}
    pileup_seen = set()
    epochs = {}
    ro_times = []
    last_trace_t = 0.0

    with Path(filepath).open("r", encoding="utf-8", errors="replace") as fh:
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

            # 1. Paket kontrol routing (AODV port 654, OLSR port 698) sebelum T_direct
            if sport in (654, 698) or dport in (654, 698):
                if ev in ("t", "+") and not is_retry and t < cutoff:
                    ro_times.append(t)
                continue

            # 2. Abaikan paket serangan DoS UDP broadcast (10.1.1.255 / 255.255.255.255, port 4000, 1024 byte)
            if dst == "255.255.255.255" or dst.endswith(".255"):
                continue

            # 3. Filter hanya paket data V2V legal (UDP port 9, payload 512 byte)
            payload_size = int(ulen_s) - 8
            if dport != legal_port or not (legal_size <= payload_size <= legal_size + 60):
                continue

            src_node = int(src.rsplit(".", 1)[1]) - 1
            dst_node = int(dst.rsplit(".", 1)[1]) - 1
            ipid = int(ipid_s)
            base_key = (src, dst, ipid)

            # Catat waktu kirim (Tx) dari node0 sebelum batas T_direct
            if ev in ("t", "+"):
                if is_retry or node != src_node:
                    continue
                ent = epochs.get(base_key)
                if ent is None:
                    epochs[base_key] = [0, t]
                    ep = 0
                else:
                    if t - ent[1] > id_wrap_window:
                        ent[0] += 1
                    ent[1] = t
                    ep = ent[0]

                uid = (src, dst, ipid, ep)
                if t < cutoff and uid not in tx_times:
                    tx_times[uid] = t

            # Catat waktu terima (Rx) di node tujuan akhir (node N-2)
            elif ev == "r" and node == dst_node:
                if not da_mac or (int(da_mac[-2:], 16) - 1) != dst_node:
                    continue
                ent = epochs.get(base_key)
                ep = ent[0] if ent is not None else 0
                uid = (src, dst, ipid, ep)
                hop = 64 - int(ttl_s) + 1

                # Deteksi otomatis T_direct saat paket 1-hop (TTL = 64) pertama kali tiba di penerima
                if hop == 1:
                    if uid not in pileup_seen:
                        pileup_seen.add(uid)
                    if t_direct is None:
                        t_direct = float(int(t))
                        cutoff = t_direct

                t0 = tx_times.get(uid)
                if t0 is not None and t0 < cutoff and uid not in rx_records and t >= t0:
                    rx_records[uid] = (t - t0, hop)

    # Pastikan hanya paket yang dikirim sebelum cutoff (T_direct) yang dihitung di jendela multi-hop
    if t_direct is not None:
        tx_times = {uid: t0 for uid, t0 in tx_times.items() if t0 < cutoff}
        rx_records = {uid: val for uid, val in rx_records.items() if uid in tx_times}
        ro_packets = sum(1 for t_ro in ro_times if t_ro < cutoff)
    else:
        ro_packets = len(ro_times)

    tx_count = len(tx_times)
    rx_count = len(rx_records)
    lost_count = tx_count - rx_count
    pileup_count = len(pileup_seen)

    delay_sum_s = sum(d for d, _ in rx_records.values())
    hop_sum = sum(h for _, h in rx_records.values())

    effective_end = t_direct if t_direct is not None else last_trace_t
    window_dur = max(0.0, effective_end - app_start_s)

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


def export_master_csv(trace_dir, csv_path):
    """
    Memproses seluruh file .tr di dalam folder secara single-pass.
    Untuk setiap skenario, file AODV-Normal diproses lebih dulu guna mendeteksi T_direct
    secara otomatis dari paket TTL = 64 pertama, lalu nilai T_direct tersebut dipakai
    bersama untuk kondisi DoS dan protokol OLSR pada skenario yang sama.
    """
    matched_files = []

    for p in sorted(Path(trace_dir).rglob("*.tr")):
        m = FILE_RE.match(p.stem)
        if not m:
            continue
        proto, raw_tok, cond = m.group(1).upper(), m.group(2).lower(), m.group(3).lower()
        tok = "baseline" if raw_tok == "mh" else raw_tok
        cond_label = "DoS" if cond == "dos" else "Normal"
        matched_files.append((proto, cond_label, tok, p))

    # Urutkan agar per skenario, kondisi Normal (khususnya AODV-Normal) dibaca lebih dulu
    # supaya T_direct terdeteksi otomatis dari file Normal sebelum memproses file DoS/OLSR.
    ordered_for_parse = sorted(
        matched_files,
        key=lambda item: (item[2], 0 if item[1] == "Normal" else 1, 0 if item[0] == "AODV" else 1, item[3].name),
    )

    detected_tdirect = {}
    parsed_by_path = {}

    for proto, cond, tok, path in ordered_for_parse:
        t_dir_in = detected_tdirect.get(tok)
        metrics = parse_trace(path, t_direct=t_dir_in)
        if tok not in detected_tdirect:
            val_t = metrics["T_direct_s"]
            detected_tdirect[tok] = float(val_t) if isinstance(val_t, (int, float)) else None
        parsed_by_path[path] = metrics

    rows = []
    total = len(matched_files)

    for idx, (proto, cond, tok, path) in enumerate(matched_files, 1):
        grp, var_name, val_str, nodes, dist, speed, max_range = SCENARIO_MAP[tok]
        metrics = parsed_by_path[path]
        row = {
            "File": path.name,
            "Protokol": proto,
            "Kondisi": cond,
            "Kelompok_OFAT": grp,
            "Variabel_Uji": var_name,
            "Nilai_Variabel": val_str,
            "Jumlah_Node": nodes,
            "Jarak_m": dist,
            "Kecepatan_kmh": speed,
            "MaxRange_m": max_range,
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

    out_file = Path(csv_path)
    out_file.parent.mkdir(parents=True, exist_ok=True)
    with out_file.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=CSV_COLUMNS, quoting=csv.QUOTE_MINIMAL)
        writer.writeheader()
        writer.writerows(rows)

    print(f"\n[+] Dataset CSV tersimpan: {out_file.resolve()} ({len(rows)} baris)")
    return rows


def main():
    ap = argparse.ArgumentParser(description="Parser Trace File (.tr) VANET NS-3 ke CSV (Auto-Detect T_direct).")
    ap.add_argument("-d", "--dir", required=True, help="Folder tempat file .tr berada")
    ap.add_argument("-o", "--output", required=True, help="Nama file CSV keluaran")
    args = ap.parse_args()

    export_master_csv(args.dir, args.output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
