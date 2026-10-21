#!/usr/bin/env python3
"""
generate_mobility_kelompok_d.py — Generator Mobilitas Kelompok D (Heterogen) & OFAT
===================================================================================
Tugas D6 & Sanity Check S3:
Menghasilkan berkas trace mobilitas NS-2 (`Ns2MobilityHelper`, format `.tcl`)
dan/atau memodifikasi berkas rute SUMO (`.rou.xml`) untuk:
  1. Kelompok D (Heterogen): kecepatan acak independen 15–25 km/jam (4,17–6,94 m/s)
     per kendaraan dengan seed terkontrol (`random.Random(seed)`) sehingga
     100% reprodusibel dan dapat dipakai berpasangan secara adil antara
     skenario Normal dan DoS serta antara AODV dan OLSR.
  2. Kelompok A, B, C & Baseline (Seragam): opsional menghasilkan trace `.tcl`
     dengan kecepatan seragam apabila berkas `.tcl` dari SUMO belum tersedia
     untuk kombinasi (n, d, v) tertentu.
  3. Mode Mitigasi S3 (`--mode per-baris` atau `--constrain-range`): opsi
     tambahan bila peneliti ingin membatasi kecepatan per barisan agar konektivitas
     multi-hop tidak putus sebelum 222 detik.

Setiap eksekusi otomatis menyimpan berkas audit (`*_speed_audit.csv` dan
`*_speed_audit.json`) yang mencatat kecepatan tiap kendaraan per seed, kejadian
salip-menyalip (overtaking), jarak akhir Receiver–Attacker, serta estimasi waktu
putus konektivitas (`first_partition_time_s`) terhadap `MaxRange = 250 m`.

Contoh Penggunaan:
  # 1. Bangkitkan trace Kelompok D (10 node, d=200m, v=15..25 km/jam) untuk 5 seed:
  python generate_mobility_kelompok_d.py --seeds 1 2 3 4 5 --out-dir mobility

  # 2. Terapkan kecepatan acak 15-25 km/jam berdasarkan posisi awal dari file .tcl SUMO:
  python generate_mobility_kelompok_d.py --from-tcl ns2mobility-multihop.tcl --seeds 1 2 3 4 5

  # 3. Bangkitkan seluruh file mobilitas untuk 9 titik uji OFAT (B0, A, B, C, D):
  python generate_mobility_kelompok_d.py --generate-all-ofat --seeds 1 2 3 4 5 --out-dir mobility
"""

import argparse
import csv
import json
import math
import os
import random
import re
from typing import Dict, List, Optional, Tuple


# ==============================================================================
# KONSTANTA DEFAULT SKENARIO VANET
# ==============================================================================
DEFAULT_NODES = 10
DEFAULT_ROW_DISTANCE = 200.0
DEFAULT_LANE_WIDTH = 3.2
DEFAULT_SIM_TIME = 222.0
DEFAULT_MAX_RANGE = 250.0
DEFAULT_V_MIN_KMH = 15.0
DEFAULT_V_MAX_KMH = 25.0


def kmh_to_mps(v_kmh: float) -> float:
    return v_kmh / 3.6


def parse_initial_positions_from_tcl(tcl_path: str) -> Dict[int, Tuple[float, float]]:
    """
    Membaca koordinat awal (X_, Y_) tiap node dari file NS-2 mobility (.tcl)
    yang dihasilkan oleh SUMO traceExporter.py.
    """
    x_coords: Dict[int, float] = {}
    y_coords: Dict[int, float] = {}

    re_x = re.compile(r'\$node_\((\d+)\)\s+set\s+X_\s+([+-]?\d+(?:\.\d+)?)')
    re_y = re.compile(r'\$node_\((\d+)\)\s+set\s+Y_\s+([+-]?\d+(?:\.\d+)?)')
    re_at = re.compile(
        r'\$ns_\s+at\s+([0-9.]+)\s+"\$node_\((\d+)\)\s+setdest\s+'
        r'([+-]?\d+(?:\.\d+)?)\s+([+-]?\d+(?:\.\d+)?)\s+([+-]?\d+(?:\.\d+)?)"'
    )

    with open(tcl_path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            mx = re_x.search(line)
            if mx:
                nid = int(mx.group(1))
                if nid not in x_coords:
                    x_coords[nid] = float(mx.group(2))
                continue
            my = re_y.search(line)
            if my:
                nid = int(my.group(1))
                if nid not in y_coords:
                    y_coords[nid] = float(my.group(2))
                continue
            mat = re_at.search(line)
            if mat and float(mat.group(1)) == 0.0:
                nid = int(mat.group(2))
                if nid not in x_coords:
                    x_coords[nid] = float(mat.group(3))
                if nid not in y_coords:
                    y_coords[nid] = float(mat.group(4))

    positions: Dict[int, Tuple[float, float]] = {}
    for nid in sorted(set(x_coords.keys()) | set(y_coords.keys())):
        positions[nid] = (x_coords.get(nid, 0.0), y_coords.get(nid, 0.0))
    return positions


def compute_grid_initial_positions(
    total_nodes: int,
    row_distance: float,
    lane_width: float = DEFAULT_LANE_WIDTH,
) -> Dict[int, Tuple[float, float]]:
    """
    Menghitung posisi awal formasi berpasangan (N/2 barisan x 2 kendaraan per baris).
    Baris r = i // 2 berada pada X = r * row_distance.
    Lajur l = i % 2 berada pada Y = l * lane_width (mis. 0.0 m dan 3.2 m).
    """
    positions: Dict[int, Tuple[float, float]] = {}
    for nid in range(total_nodes):
        row_idx = nid // 2
        lane_idx = nid % 2
        x0 = float(row_idx) * float(row_distance)
        y0 = float(lane_idx) * float(lane_width)
        positions[nid] = (x0, y0)
    return positions


def assign_vehicle_speeds(
    total_nodes: int,
    mode: str,
    seed: int,
    v_min_kmh: float = DEFAULT_V_MIN_KMH,
    v_max_kmh: float = DEFAULT_V_MAX_KMH,
    v_uniform_kmh: float = 20.0,
) -> List[float]:
    """
    Menentukan kecepatan (km/jam) untuk masing-masing kendaraan (0..total_nodes-1).
    - mode == 'acak': kecepatan acak independen U(v_min_kmh, v_max_kmh) per kendaraan (D6).
    - mode == 'per-baris': kecepatan acak U(v_min_kmh, v_max_kmh) per barisan (2 mobil sebaris sama).
    - mode == 'seragam': seluruh kendaraan bergerak dengan v_uniform_kmh.
    """
    rng = random.Random(seed)
    speeds_kmh: List[float] = []

    if mode == "seragam":
        speeds_kmh = [float(v_uniform_kmh) for _ in range(total_nodes)]
    elif mode == "per-baris":
        num_rows = (total_nodes + 1) // 2
        row_speeds = [rng.uniform(v_min_kmh, v_max_kmh) for _ in range(num_rows)]
        for nid in range(total_nodes):
            speeds_kmh.append(row_speeds[nid // 2])
    else:
        # Default 'acak' sesuai spesifikasi Kelompok D: independen per kendaraan
        for _ in range(total_nodes):
            speeds_kmh.append(rng.uniform(v_min_kmh, v_max_kmh))

    return speeds_kmh


def analyze_s3_topology(
    positions: Dict[int, Tuple[float, float]],
    speeds_kmh: List[float],
    sim_time: float = DEFAULT_SIM_TIME,
    max_range: float = DEFAULT_MAX_RANGE,
) -> Dict[str, object]:
    """
    Sanity Check S3: menganalisis dampak perbedaan kecepatan terhadap topologi
    multi-hop selama 0..sim_time detik (overtaking, jarak Receiver-Attacker,
    dan waktu pertama kali graf node legit terputus di atas max_range).
    """
    total_nodes = len(speeds_kmh)
    sender_idx = 0
    receiver_idx = total_nodes - 2
    attacker_idx = total_nodes - 1
    legit_nodes = list(range(0, total_nodes - 1))

    # 1. Hitung jumlah pasangan (i, j) dengan X_awal(i) < X_awal(j) tetapi X_akhir(i) > X_akhir(j)
    overtaking_pairs: List[Dict[str, object]] = []
    for i in range(total_nodes):
        x0_i, _ = positions[i]
        vi_mps = kmh_to_mps(speeds_kmh[i])
        x1_i = x0_i + vi_mps * sim_time
        for j in range(total_nodes):
            if i == j:
                continue
            x0_j, _ = positions[j]
            vj_mps = kmh_to_mps(speeds_kmh[j])
            x1_j = x0_j + vj_mps * sim_time
            if x0_i < x0_j - 1e-6 and x1_i > x1_j + 1e-6:
                t_overtake = (x0_j - x0_i) / (vi_mps - vj_mps)
                overtaking_pairs.append({
                    "rear_node": i,
                    "front_node": j,
                    "t_overtake_s": round(t_overtake, 2),
                })

    # 2. Jarak Receiver (N-2) dan Attacker (N-1) di awal dan akhir simulasi
    rx_x0, rx_y0 = positions[receiver_idx]
    att_x0, att_y0 = positions[attacker_idx]
    rx_x1 = rx_x0 + kmh_to_mps(speeds_kmh[receiver_idx]) * sim_time
    att_x1 = att_x0 + kmh_to_mps(speeds_kmh[attacker_idx]) * sim_time
    dist_rx_att_start = math.hypot(rx_x0 - att_x0, rx_y0 - att_y0)
    dist_rx_att_end = math.hypot(rx_x1 - att_x1, rx_y0 - att_y0)

    # 3. Periksa konektivitas multi-hop dari sender_idx ke receiver_idx tiap detik (0..sim_time)
    first_partition_time_s: Optional[int] = None
    disconnected_seconds = 0
    max_adjacent_gap_end_m = 0.0

    for t_sec in range(int(sim_time) + 1):
        # Posisi saat t_sec untuk node legit (0..N-2)
        cur_pos = {}
        for nid in legit_nodes:
            x0, y0 = positions[nid]
            cur_pos[nid] = (x0 + kmh_to_mps(speeds_kmh[nid]) * t_sec, y0)

        # BFS dari sender_idx ke receiver_idx dengan ambang max_range
        visited = {sender_idx}
        queue = [sender_idx]
        while queue:
            u = queue.pop(0)
            ux, uy = cur_pos[u]
            for v in legit_nodes:
                if v not in visited:
                    vx, vy = cur_pos[v]
                    if math.hypot(ux - vx, uy - vy) <= max_range:
                        visited.add(v)
                        queue.append(v)

        if receiver_idx not in visited:
            disconnected_seconds += 1
            if first_partition_time_s is None:
                first_partition_time_s = t_sec

        if t_sec == int(sim_time):
            xs_sorted = sorted(cur_pos[nid][0] for nid in legit_nodes)
            if len(xs_sorted) >= 2:
                max_adjacent_gap_end_m = max(
                    xs_sorted[k + 1] - xs_sorted[k] for k in range(len(xs_sorted) - 1)
                )

    return {
        "overtaking_count": len(overtaking_pairs),
        "overtaking_events": overtaking_pairs,
        "dist_receiver_attacker_start_m": round(dist_rx_att_start, 2),
        "dist_receiver_attacker_end_m": round(dist_rx_att_end, 2),
        "attacker_in_range_of_receiver_at_end": dist_rx_att_end <= max_range,
        "first_partition_time_s": first_partition_time_s,
        "disconnected_duration_s": disconnected_seconds,
        "max_adjacent_gap_end_m": round(max_adjacent_gap_end_m, 2),
    }


def write_ns2_mobility_tcl(
    out_tcl_path: str,
    positions: Dict[int, Tuple[float, float]],
    speeds_kmh: List[float],
    sim_time: float = DEFAULT_SIM_TIME,
    dt_step: float = 1.0,
    header_comment: str = "",
) -> None:
    """
    Menulis berkas mobilitas format NS-2 (`Ns2MobilityHelper`) yang kompatibel penuh
    dengan skrip NS-3 `olsr-vanet-mh-*.cc` dan `aodv-vanet-mh-*.cc`.
    """
    os.makedirs(os.path.dirname(os.path.abspath(out_tcl_path)), exist_ok=True)
    total_nodes = len(speeds_kmh)

    with open(out_tcl_path, "w", encoding="utf-8") as f:
        if header_comment:
            for line in header_comment.strip().splitlines():
                f.write(f"# {line}\n")
        for nid in range(total_nodes):
            x0, y0 = positions[nid]
            f.write(f"$node_({nid}) set X_ {x0:.2f}\n")
            f.write(f"$node_({nid}) set Y_ {y0:.2f}\n")
            f.write(f"$node_({nid}) set Z_ 0.00\n")

        # Tulis event pergerakan linear sepanjang sim_time
        # Menggunakan interval dt_step (atau 1 segmen penuh jika dt_step <= 0)
        if dt_step <= 0 or dt_step >= sim_time:
            for nid in range(total_nodes):
                x0, y0 = positions[nid]
                v_mps = kmh_to_mps(speeds_kmh[nid])
                x_end = x0 + v_mps * sim_time
                f.write(
                    f'$ns_ at 0.00 "$node_({nid}) setdest {x_end:.4f} {y0:.2f} {v_mps:.4f}"\n'
                )
        else:
            steps = int(math.ceil(sim_time / dt_step))
            for s in range(steps):
                t_cur = s * dt_step
                t_next = min((s + 1) * dt_step, sim_time)
                for nid in range(total_nodes):
                    x0, y0 = positions[nid]
                    v_mps = kmh_to_mps(speeds_kmh[nid])
                    x_target = x0 + v_mps * t_next
                    f.write(
                        f'$ns_ at {t_cur:.2f} "$node_({nid}) setdest '
                        f'{x_target:.2f} {y0:.2f} {v_mps:.2f}"\n'
                    )


def get_node_role(nid: int, total_nodes: int) -> str:
    if nid == 0:
        return "Sender"
    if nid == total_nodes - 2:
        return "Receiver"
    if nid == total_nodes - 1:
        return "Attacker_or_Passive"
    return "Relay"


def generate_kelompok_d_traces(
    seeds: List[int],
    out_dir: str,
    total_nodes: int = DEFAULT_NODES,
    row_distance: float = DEFAULT_ROW_DISTANCE,
    v_min_kmh: float = DEFAULT_V_MIN_KMH,
    v_max_kmh: float = DEFAULT_V_MAX_KMH,
    mode: str = "acak",
    sim_time: float = DEFAULT_SIM_TIME,
    max_range: float = DEFAULT_MAX_RANGE,
    from_tcl: Optional[str] = None,
    dt_step: float = 0.0,
) -> Tuple[List[Dict[str, object]], Dict[str, object]]:
    """
    Menghasilkan berkas `.tcl` untuk setiap seed pada Kelompok D dan mengembalikan
    baris audit kecepatan per kendaraan beserta ringkasan diagnostik S3.
    """
    os.makedirs(out_dir, exist_ok=True)
    if from_tcl and os.path.isfile(from_tcl):
        positions = parse_initial_positions_from_tcl(from_tcl)
        if len(positions) < total_nodes:
            positions = compute_grid_initial_positions(total_nodes, row_distance)
    else:
        positions = compute_grid_initial_positions(total_nodes, row_distance)

    audit_rows: List[Dict[str, object]] = []
    s3_reports: Dict[str, object] = {}

    for seed in seeds:
        speeds_kmh = assign_vehicle_speeds(
            total_nodes=total_nodes,
            mode=mode,
            seed=seed,
            v_min_kmh=v_min_kmh,
            v_max_kmh=v_max_kmh,
        )
        tcl_name = f"mobility_n{total_nodes}_d{int(row_distance)}_v15_25_run{seed}.tcl"
        tcl_path = os.path.join(out_dir, tcl_name)

        comment = (
            f"Kelompok D (Heterogen) Mobility Trace | mode={mode} | "
            f"n={total_nodes}, d={row_distance}m, v=[{v_min_kmh},{v_max_kmh}] km/jam, seed={seed}"
        )
        write_ns2_mobility_tcl(
            out_tcl_path=tcl_path,
            positions=positions,
            speeds_kmh=speeds_kmh,
            sim_time=sim_time,
            dt_step=dt_step,
            header_comment=comment,
        )

        s3_diag = analyze_s3_topology(
            positions=positions,
            speeds_kmh=speeds_kmh,
            sim_time=sim_time,
            max_range=max_range,
        )
        s3_reports[f"seed_{seed}"] = {
            "tcl_file": tcl_path,
            "mode": mode,
            **s3_diag,
        }

        for nid, v_kmh in enumerate(speeds_kmh):
            x0, y0 = positions[nid]
            v_mps = kmh_to_mps(v_kmh)
            x_end = x0 + v_mps * sim_time
            audit_rows.append({
                "Seed": seed,
                "Mode": mode,
                "Node_ID": nid,
                "Row_Index": nid // 2,
                "Lane_Index": nid % 2,
                "Role": get_node_role(nid, total_nodes),
                "Initial_X_m": round(x0, 2),
                "Initial_Y_m": round(y0, 2),
                "Speed_kmh": round(v_kmh, 4),
                "Speed_mps": round(v_mps, 4),
                "Final_X_m": round(x_end, 2),
                "First_Partition_Time_s": s3_diag["first_partition_time_s"],
                "Overtaking_Count_Run": s3_diag["overtaking_count"],
                "Dist_Rx_Att_End_m": s3_diag["dist_receiver_attacker_end_m"],
                "Tcl_File": tcl_name,
            })

    # Simpan berkas audit CSV dan JSON
    audit_csv_path = os.path.join(out_dir, "kelompok_d_speed_audit.csv")
    if audit_rows:
        fieldnames = list(audit_rows[0].keys())
        with open(audit_csv_path, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(audit_rows)

    audit_json_path = os.path.join(out_dir, "kelompok_d_speed_audit.json")
    with open(audit_json_path, "w", encoding="utf-8") as f:
        json.dump(
            {
                "parameters": {
                    "total_nodes": total_nodes,
                    "row_distance_m": row_distance,
                    "v_min_kmh": v_min_kmh,
                    "v_max_kmh": v_max_kmh,
                    "mode": mode,
                    "sim_time_s": sim_time,
                    "max_range_m": max_range,
                    "seeds": seeds,
                },
                "s3_diagnostics_per_seed": s3_reports,
                "vehicle_speeds": audit_rows,
            },
            f,
            indent=2,
        )

    return audit_rows, s3_reports


def generate_all_ofat_uniform_traces(
    out_dir: str,
    sim_time: float = DEFAULT_SIM_TIME,
    dt_step: float = 0.0,
) -> List[str]:
    """
    Menghasilkan berkas `.tcl` seragam untuk 8 titik uji OFAT non-heterogen
    (B0 + Kelompok A + Kelompok B + Kelompok C) agar `run_vanet_batch.py` selalu
    memiliki berkas mobilitas yang siap pakai.
    """
    os.makedirs(out_dir, exist_ok=True)
    # 8 titik uji seragam (n, d, v)
    uniform_points = [
        (10, 200, 20),  # B0 (Baseline)
        (20, 200, 20),  # Kelompok A: n=20
        (30, 200, 20),  # Kelompok A: n=30
        (10, 100, 20),  # Kelompok B: d=100
        (10, 300, 20),  # Kelompok B: d=300
        (10, 400, 20),  # Kelompok B: d=400
        (10, 200, 30),  # Kelompok C: v=30
        (10, 200, 40),  # Kelompok C: v=40
    ]
    created_files: List[str] = []
    for n_val, d_val, v_val in uniform_points:
        tcl_name = f"mobility_n{n_val}_d{d_val}_v{v_val}.tcl"
        tcl_path = os.path.join(out_dir, tcl_name)
        positions = compute_grid_initial_positions(n_val, float(d_val))
        speeds = assign_vehicle_speeds(n_val, mode="seragam", seed=1, v_uniform_kmh=float(v_val))
        comment = f"OFAT Uniform Mobility Trace | n={n_val}, d={d_val}m, v={v_val} km/jam"
        write_ns2_mobility_tcl(
            out_tcl_path=tcl_path,
            positions=positions,
            speeds_kmh=speeds,
            sim_time=sim_time,
            dt_step=dt_step,
            header_comment=comment,
        )
        created_files.append(tcl_path)
    return created_files


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Generator Mobilitas Kelompok D (15-25 km/jam acak independen) & Audit S3"
    )
    parser.add_argument(
        "--seeds",
        type=int,
        nargs="+",
        default=[1, 2, 3, 4, 5],
        help="Daftar seed yang akan dibangkitkan (default: 1 2 3 4 5)",
    )
    parser.add_argument(
        "--out-dir",
        default="mobility",
        help="Direktori keluaran file .tcl dan file audit kecepatan (default: mobility)",
    )
    parser.add_argument(
        "--nodes",
        type=int,
        default=DEFAULT_NODES,
        help="Jumlah kendaraan (default: 10)",
    )
    parser.add_argument(
        "--row-distance",
        type=float,
        default=DEFAULT_ROW_DISTANCE,
        help="Jarak awal antar-baris dalam meter (default: 200.0)",
    )
    parser.add_argument(
        "--v-min",
        type=float,
        default=DEFAULT_V_MIN_KMH,
        help="Batas bawah kecepatan acak dalam km/jam (default: 15.0)",
    )
    parser.add_argument(
        "--v-max",
        type=float,
        default=DEFAULT_V_MAX_KMH,
        help="Batas atas kecepatan acak dalam km/jam (default: 25.0)",
    )
    parser.add_argument(
        "--mode",
        choices=["acak", "per-baris", "seragam"],
        default="acak",
        help="Mode pembangkitan kecepatan: 'acak' (independen per kendaraan, default D6), "
             "'per-baris' (mitigasi S3), atau 'seragam'",
    )
    parser.add_argument(
        "--sim-time",
        type=float,
        default=DEFAULT_SIM_TIME,
        help="Durasi simulasi dalam detik (default: 222.0)",
    )
    parser.add_argument(
        "--max-range",
        type=float,
        default=DEFAULT_MAX_RANGE,
        help="Jangkauan radio MaxRange dalam meter untuk diagnostik S3 (default: 250.0)",
    )
    parser.add_argument(
        "--from-tcl",
        default=None,
        help="Opsional: baca koordinat awal (X_, Y_) dari file .tcl SUMO yang sudah ada",
    )
    parser.add_argument(
        "--dt-step",
        type=float,
        default=0.0,
        help="Interval waktu penulisan setdest (0 = 1 baris setdest linear penuh per node)",
    )
    parser.add_argument(
        "--generate-all-ofat",
        action="store_true",
        help="Bangkitkan juga file .tcl seragam untuk seluruh titik uji B0, Kelompok A, B, dan C",
    )

    args = parser.parse_args()

    if args.generate_all_ofat:
        uniform_files = generate_all_ofat_uniform_traces(
            out_dir=args.out_dir,
            sim_time=args.sim_time,
            dt_step=args.dt_step,
        )
        print(f"[INFO] Berhasil membuat {len(uniform_files)} file mobilitas seragam OFAT di '{args.out_dir}'")

    audit_rows, s3_reports = generate_kelompok_d_traces(
        seeds=args.seeds,
        out_dir=args.out_dir,
        total_nodes=args.nodes,
        row_distance=args.row_distance,
        v_min_kmh=args.v_min,
        v_max_kmh=args.v_max,
        mode=args.mode,
        sim_time=args.sim_time,
        max_range=args.max_range,
        from_tcl=args.from_tcl,
        dt_step=args.dt_step,
    )

    print(f"[INFO] Berhasil membuat {len(args.seeds)} file mobilitas Kelompok D (mode={args.mode}):")
    for seed_key, rep in s3_reports.items():
        print(
            f"  - {seed_key}: file={rep['tcl_file']} | "
            f"overtaking={rep['overtaking_count']} pasang | "
            f"dist(Rx,Att) akhir={rep['dist_receiver_attacker_end_m']} m | "
            f"first_partition_t={rep['first_partition_time_s']} s"
        )
    print(f"[INFO] Audit kecepatan tersimpan di: {os.path.join(args.out_dir, 'kelompok_d_speed_audit.csv')}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
