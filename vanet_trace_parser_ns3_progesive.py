#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import csv
import re
from pathlib import Path

# membaca pola file .tr NS-3 untuk membaca 1 baris paket IPv4/UDP
LINE_RE = re.compile(
    r"^([tr])\s+([+\d.eE\-]+)(?:ns|us|ms|s)?\s+.*?/NodeList/(\d+)/.*?"
    r"(?:Retry=(\d).*?)?(?:DA\(RA\)=([0-9a-fA-F:]{17}).*?)?"
    r"ns3::Ipv4Header\s*\(.*?ttl\s+(\d+)\s+id\s+(\d+)\s+protocol\s+17\s+.*?length:\s*\d+\s+"
    r"(\d+\.\d+\.\d+\.\d+)\s*>\s*(\d+\.\d+\.\d+\.\d+)\)\s*"
    r"ns3::UdpHeader\s*\(length:\s*(\d+)\s+(\d+)\s*>\s*(\d+)\)"
)

# membaca nama file (mendukung 1x run, format Windows "(2)".."(10)", maupun "-run1".."-run10")
FILE_RE = re.compile(
    r"^(aodv|olsr)-(baseline|mh|a-n(?:20|30)|b-j(?:100|200|300|400)|c-k(?:30|40)|d)-(normal|dos)"
    r"(?:\s*\((\d+)\)|[-_](?:run|rep|seed)?(\d+))?$",
    re.IGNORECASE,
)

# (Kelompok_OFAT, Variabel_Uji, Nilai_Variabel, Jumlah_Node, Jarak_m, Kecepatan_kmh, MaxRange_m)
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
    "RO_Ratio",
    "RO_Bytes",
    "RO_Bytes_per_s",
    "NRL_Bytes_Ratio",
    "olsrHelloMsgs",
    "olsrTcMsgs",
    "aodvRreq",
    "aodvRrep",
    "aodvRerr",
    "aodvHello",
    "Run_Ke",
    "ProgMean_Throughput_kbps",
    "ProgMean_PDR_pct",
    "ProgMean_PLR_pct",
    "ProgMean_Avg_Delay_ms",
    "ProgMean_RO_Pkts",
    "ProgMean_RO_per_s",
    "ProgMean_NRL_Ratio",
    "ProgMean_RO_Ratio",
    "ProgMean_RO_Bytes",
    "ProgMean_RO_Bytes_per_s",
    "ProgMean_NRL_Bytes_Ratio",
    "ProgMean_olsrHelloMsgs",
    "ProgMean_olsrTcMsgs",
    "ProgMean_aodvRreq",
    "ProgMean_aodvRrep",
    "ProgMean_aodvRerr",
    "ProgMean_aodvHello",
]

# Pasangan (Nama_Kolom_Progressive_Mean, Nama_Kolom_Metrik_Asal)
PROG_MEAN_SPECS = [
    ("ProgMean_Throughput_kbps", "Throughput_kbps"),
    ("ProgMean_PDR_pct",         "PDR_pct"),
    ("ProgMean_PLR_pct",         "PLR_pct"),
    ("ProgMean_Avg_Delay_ms",    "Avg_Delay_ms"),
    ("ProgMean_RO_Pkts",         "Routing_Overhead_Pkts"),
    ("ProgMean_RO_per_s",        "RO_per_s"),
    ("ProgMean_NRL_Ratio",       "NRL_Ratio"),
    ("ProgMean_RO_Ratio",        "RO_Ratio"),
    ("ProgMean_RO_Bytes",        "RO_Bytes"),
    ("ProgMean_RO_Bytes_per_s",  "RO_Bytes_per_s"),
    ("ProgMean_NRL_Bytes_Ratio", "NRL_Bytes_Ratio"),
    ("ProgMean_olsrHelloMsgs",   "olsrHelloMsgs"),
    ("ProgMean_olsrTcMsgs",      "olsrTcMsgs"),
    ("ProgMean_aodvRreq",        "aodvRreq"),
    ("ProgMean_aodvRrep",        "aodvRrep"),
    ("ProgMean_aodvRerr",        "aodvRerr"),
    ("ProgMean_aodvHello",       "aodvHello"),
]


def parse_trace(filepath, t_direct=None, app_start_s=5.0, legal_port=9, legal_size=512):
    cutoff = t_direct if t_direct is not None else float("inf")
    tx_times = {}
    rx_records = {}
    pileup_seen = set()
    ro_records = []
    last_trace_t = 0.0
    is_olsr = Path(filepath).name.lower().startswith("olsr")

    with Path(filepath).open("r", encoding="utf-8", errors="replace") as fh:
        for line in fh:
            if not line or line[0] not in ("t", "r") or "Ipv4Header" not in line:
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
                if ev == "t" and not is_retry and t < cutoff:
                    ctrl_bytes = max(0, int(ulen_s) - 8)
                    if sport == 698 or dport == 698:
                        oh = line.count("ns3::olsr::MessageHeader (type: HELLO")
                        ot = line.count("ns3::olsr::MessageHeader (type: TC")
                        ro_records.append((t, ctrl_bytes, oh, ot, 0, 0, 0, 0))
                    else:
                        rq = 1 if "ns3::aodv::TypeHeader (RREQ)" in line else 0
                        rr = 0
                        ah = 0
                        if "ns3::aodv::TypeHeader (RREP)" in line:
                            if dst == "255.255.255.255" or dst.endswith(".255"):
                                ah = 1
                            else:
                                rr = 1
                        re_cnt = 1 if "ns3::aodv::TypeHeader (RERR)" in line else 0
                        ro_records.append((t, ctrl_bytes, 0, 0, rq, rr, re_cnt, ah))
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

            # Catat waktu kirim (Tx) dari node0 sebelum batas T_direct
            if ev == "t":
                if is_retry or node != src_node:
                    continue
                uid = (src, dst, ipid)
                if t < cutoff and uid not in tx_times:
                    tx_times[uid] = t

            # Catat waktu terima (Rx) di node tujuan akhir (node N-2)
            elif ev == "r" and node == dst_node:
                if not da_mac or (int(da_mac[-2:], 16) - 1) != dst_node:
                    continue
                uid = (src, dst, ipid)
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
        ro_records = [rec for rec in ro_records if rec[0] < cutoff]

    ro_packets = len(ro_records)
    ro_bytes = sum(rec[1] for rec in ro_records)
    olsr_hello = sum(rec[2] for rec in ro_records)
    olsr_tc = sum(rec[3] for rec in ro_records)
    aodv_rreq = sum(rec[4] for rec in ro_records)
    aodv_rrep = sum(rec[5] for rec in ro_records)
    aodv_rerr = sum(rec[6] for rec in ro_records)
    aodv_hello = sum(rec[7] for rec in ro_records)

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
    ro_bytes_per_s = (ro_bytes / window_dur) if window_dur > 0.0 else 0.0
    ro_ratio = (ro_packets / tx_count) if tx_count > 0 else 0.0
    nrl = round(ro_packets / rx_count, 4) if rx_count > 0 else "N/A"
    nrl_bytes = (
        round(ro_bytes / (rx_count * legal_size), 4)
        if (rx_count > 0 and legal_size > 0)
        else "N/A"
    )

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
        "NRL_Ratio": nrl,
        "RO_Ratio": round(ro_ratio, 4),
        "RO_Bytes": ro_bytes,
        "RO_Bytes_per_s": round(ro_bytes_per_s, 4),
        "NRL_Bytes_Ratio": nrl_bytes,
        "olsrHelloMsgs": olsr_hello if is_olsr else "-",
        "olsrTcMsgs": olsr_tc if is_olsr else "-",
        "aodvRreq": "-" if is_olsr else aodv_rreq,
        "aodvRrep": "-" if is_olsr else aodv_rrep,
        "aodvRerr": "-" if is_olsr else aodv_rerr,
        "aodvHello": "-" if is_olsr else aodv_hello,
    }


def export_master_csv(trace_dir, csv_path):
    matched_files = []
    skipped_files = []
    seen_keys = {}

    for p in sorted(Path(trace_dir).rglob("*.tr")):
        m = FILE_RE.match(p.stem)
        if not m:
            skipped_files.append(p)
            continue
        proto, raw_tok, cond, paren_run, dash_run = (
            m.group(1).upper(),
            m.group(2).lower(),
            m.group(3).lower(),
            m.group(4),
            m.group(5),
        )
        run_str = paren_run or dash_run
        run_num = int(run_str) if run_str is not None else 1
        tok = "baseline" if raw_tok == "mh" else raw_tok
        cond_label = "DoS" if cond == "dos" else "Normal"

        dup_key = (proto, cond_label, tok, run_num)
        if dup_key in seen_keys:
            print(
                f"[!] PERINGATAN: Duplikat terdeteksi untuk {proto} {cond_label} {tok} Run={run_num}:\n"
                f"    - {seen_keys[dup_key]}\n"
                f"    - {p}\n"
                f"    Pastikan penamaan kondisi (normal/dos) atau nomor run sudah benar!"
            )
        else:
            seen_keys[dup_key] = p

        matched_files.append((proto, cond_label, tok, run_num, p))

    if skipped_files:
        print(f"[!] Info: {len(skipped_files)} file .tr dilewati karena nama file tidak cocok pola FILE_RE:")
        for sp in skipped_files:
            print(f"    - {sp.name} ({sp})")

    # Urutkan baris keluaran berdasarkan (Protokol, Kondisi, Skenario, Run_Ke)
    # agar Run 1..10 berurutan rapi untuk perhitungan Progressive Mean.
    matched_files.sort(key=lambda item: (item[0], item[1], item[2], item[3], str(item[4])))

    # Urutkan khusus pembacaan trace agar per (skenario, run), kondisi Normal (khususnya AODV-Normal)
    # dibaca lebih dulu supaya T_direct terdeteksi otomatis dari Normal sebelum memproses DoS/OLSR.
    ordered_for_parse = sorted(
        matched_files,
        key=lambda item: (
            item[2],                              # tok
            item[3],                              # run_num
            0 if item[1] == "Normal" else 1,      # Normal lebih dulu
            0 if item[0] == "AODV" else 1,        # AODV lebih dulu
            str(item[4]),
        ),
    )

    detected_tdirect_run = {}
    detected_tdirect_tok = {}
    parsed_by_path = {}

    for proto, cond, tok, run_num, path in ordered_for_parse:
        if (tok, run_num) in detected_tdirect_run:
            t_dir_in = detected_tdirect_run[(tok, run_num)]
        elif cond == "DoS" and tok in detected_tdirect_tok:
            t_dir_in = detected_tdirect_tok[tok]
        else:
            t_dir_in = None

        metrics = parse_trace(path, t_direct=t_dir_in)
        val_t = metrics["T_direct_s"]
        t_float = float(val_t) if isinstance(val_t, (int, float)) else None

        if (tok, run_num) not in detected_tdirect_run:
            detected_tdirect_run[(tok, run_num)] = t_float
        if tok not in detected_tdirect_tok:
            detected_tdirect_tok[tok] = t_float

        parsed_by_path[path] = metrics

    rows = []
    total = len(matched_files)
    prog_counts = {}
    prog_sums = {}
    prog_valid_counts = {}

    for idx, (proto, cond, tok, run_num, path) in enumerate(matched_files, 1):
        grp, var_name, val_str, nodes, dist, speed, max_range = SCENARIO_MAP[tok]
        metrics = parsed_by_path[path]

        # Hitung Progressive Mean (rata-rata kumulatif dari Run ke-1 s.d. Run saat ini per grup skenario)
        group_key = (proto, cond, tok)
        k = prog_counts.get(group_key, 0) + 1
        prog_counts[group_key] = k
        if group_key not in prog_sums:
            prog_sums[group_key] = {src_col: 0.0 for _, src_col in PROG_MEAN_SPECS}
            prog_valid_counts[group_key] = {src_col: 0 for _, src_col in PROG_MEAN_SPECS}

        prog_values = {}
        for dst_col, src_col in PROG_MEAN_SPECS:
            raw_val = metrics[src_col]
            if raw_val == "-":
                prog_values[dst_col] = "-"
            elif raw_val == "N/A":
                valid_k = prog_valid_counts[group_key][src_col]
                prog_values[dst_col] = (
                    round(prog_sums[group_key][src_col] / valid_k, 4)
                    if valid_k > 0
                    else "N/A"
                )
            else:
                prog_sums[group_key][src_col] += float(raw_val)
                prog_valid_counts[group_key][src_col] += 1
                valid_k = prog_valid_counts[group_key][src_col]
                prog_values[dst_col] = round(prog_sums[group_key][src_col] / valid_k, 4)

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
            "Run_Ke": run_num,
            **prog_values,
        }
        rows.append(row)
        print(
            f"[{idx:02d}/{total:02d}] {path.name:<28} | {proto:<4} {cond:<6} Run={run_num:>2} | "
            f"Grp={grp:<8} Val={val_str:<8} T_dir={str(metrics['T_direct_s']):<7} | "
            f"PDR={metrics['PDR_pct']:>6.2f}% (PM={prog_values['ProgMean_PDR_pct']:>6.2f}%) "
            f"Delay={metrics['Avg_Delay_ms']:>6.2f}ms (PM={prog_values['ProgMean_Avg_Delay_ms']:>6.2f}ms) "
            f"Tput={metrics['Throughput_kbps']:>6.2f}kbps (PM={prog_values['ProgMean_Throughput_kbps']:>6.2f}kbps) "
            f"RO={metrics['RO_Ratio']:>6.4f} (PM={prog_values['ProgMean_RO_Ratio']:>6.4f})"
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
