#!/usr/bin/env python3
"""
run_vanet_batch.py — Orkestrator Batch 36 Skenario OFAT VANET (AODV vs OLSR)
=============================================================================
Tugas D7:
Mengeksekusi matriks eksperimen OFAT (9 titik uji unik x 2 protokol x 2 kondisi
= 36 skenario x K seed, default 5 seed = 180 run) tanpa duplikasi titik Baseline (B0).

Jaminan Keadilan Eksperimen (Apple-to-Apple):
  1. Titik Baseline B0 (10 node, d=200 m, v=20 km/jam seragam) hanya dijalankan
     SATU KALI per (protokol, kondisi, seed), kemudian hasilnya dirujuk ulang
     oleh `aggregate_vanet.py` untuk Kelompok A, B, C, dan D.
  2. Pada satu titik uji dan seed yang sama, keempat kombinasi
     (OLSR-Normal, OLSR-DoS, AODV-Normal, AODV-DoS) dijamin memakai berkas
     `--traceFile` mobilitas `.tcl` dan `--seed` (`RngSeedManager::SetRun`) yang
     SAMA PERSIS.
  3. Nama berkas keluaran otomatis mengikuti format standar parser:
     `{protokol}_{kondisi}_n{N}_d{D}_v{V}_run{SEED}.tr` (beserta `-flowmon-results.xml`,
     `-routingtable.txt`, dan `-summary.csv`).

Contoh Penggunaan:
  # 1. Uji rencana eksekusi (Dry-Run) untuk 36 skenario x 5 seed = 180 run:
  python run_vanet_batch.py --dry-run --seeds 1 2 3 4 5

  # 2. Jalankan langsung di Linux / WSL menuju instalasi NS-3 + otomatis parse & agregasi:
  python run_vanet_batch.py --ns3-dir /home/dzaky/ns-3/ns-3-dev --stage-scratch \\
      --seeds 1 2 3 4 5 --out-dir results_raw --parse-and-aggregate
"""

import argparse
import csv
import os
import shutil
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from typing import Dict, List, Optional

from generate_mobility_kelompok_d import (
    generate_all_ofat_uniform_traces,
    generate_kelompok_d_traces,
)


@dataclass(frozen=True)
class OfatPoint:
    point_id: str
    group_label: str
    total_nodes: int
    row_distance: int
    speed_tag: str
    is_baseline: bool
    is_hetero: bool


# ==============================================================================
# 9 TITIK UJI UNIK OFAT (TANPA DUPLIKASI BASELINE B0)
# ==============================================================================
OFAT_POINTS: List[OfatPoint] = [
    # Baseline B0 (dipakai bersama oleh Kelompok A, B, C, dan pembanding D)
    OfatPoint("B0", "Baseline (A/B/C/D)", 10, 200, "20", is_baseline=True, is_hetero=False),
    # Kelompok A — Kepadatan Kendaraan (n=10 sudah diwakili B0)
    OfatPoint("A_n20", "Kelompok A (Kepadatan)", 20, 200, "20", is_baseline=False, is_hetero=False),
    OfatPoint("A_n30", "Kelompok A (Kepadatan)", 30, 200, "20", is_baseline=False, is_hetero=False),
    # Kelompok B — Jarak Antar-Baris (d=200 sudah diwakili B0)
    OfatPoint("B_d100", "Kelompok B (Jarak)", 10, 100, "20", is_baseline=False, is_hetero=False),
    OfatPoint("B_d300", "Kelompok B (Jarak)", 10, 300, "20", is_baseline=False, is_hetero=False),
    OfatPoint("B_d400", "Kelompok B (Jarak)", 10, 400, "20", is_baseline=False, is_hetero=False),
    # Kelompok C — Kecepatan Seragam (v=20 sudah diwakili B0)
    OfatPoint("C_v30", "Kelompok C (Kecepatan)", 10, 200, "30", is_baseline=False, is_hetero=False),
    OfatPoint("C_v40", "Kelompok C (Kecepatan)", 10, 200, "40", is_baseline=False, is_hetero=False),
    # Kelompok D — Kecepatan Heterogen Acak Independen 15-25 km/jam
    OfatPoint("D_v15_25", "Kelompok D (Heterogen)", 10, 200, "15_25", is_baseline=False, is_hetero=True),
]

PROTOCOLS = ["olsr", "aodv"]
CONDITIONS = ["normal", "dos"]

CC_PROGRAM_MAP = {
    ("olsr", "normal"): "olsr-vanet-mh-normal",
    ("olsr", "dos"): "olsr-vanet-mh-dos",
    ("aodv", "normal"): "aodv-vanet-mh-normal",
    ("aodv", "dos"): "aodv-vanet-mh-dos",
}


def resolve_mobility_tcl(
    point: OfatPoint,
    seed: int,
    mobility_dir: str,
) -> str:
    """
    Menentukan path berkas `.tcl` untuk titik uji dan seed tertentu.
    Pasangan Normal dan DoS serta AODV dan OLSR pada (point, seed) yang sama
    selalu menerima path berkas `.tcl` yang identik.
    """
    if point.is_hetero:
        fname = f"mobility_n{point.total_nodes}_d{point.row_distance}_v{point.speed_tag}_run{seed}.tcl"
    else:
        fname = f"mobility_n{point.total_nodes}_d{point.row_distance}_v{point.speed_tag}.tcl"
    return os.path.abspath(os.path.join(mobility_dir, fname))


def build_execution_plan(
    seeds: List[int],
    mobility_dir: str,
    out_dir: str,
    sim_time: float = 222.0,
    max_range: float = 250.0,
    points_filter: Optional[List[str]] = None,
) -> List[Dict[str, object]]:
    """
    Menyusun daftar 36 skenario x K seed tanpa duplikasi Baseline B0.
    """
    plan: List[Dict[str, object]] = []
    out_dir_abs = os.path.abspath(out_dir)

    for point in OFAT_POINTS:
        if points_filter and point.point_id not in points_filter:
            continue
        for seed in seeds:
            tcl_path = resolve_mobility_tcl(point, seed, mobility_dir)
            for proto in PROTOCOLS:
                for cond in CONDITIONS:
                    prog_name = CC_PROGRAM_MAP[(proto, cond)]
                    out_prefix = (
                        f"{proto}_{cond}_n{point.total_nodes}"
                        f"_d{point.row_distance}_v{point.speed_tag}_run{seed}"
                    )
                    ns3_args = (
                        f"{prog_name} "
                        f"--totalNodes={point.total_nodes} "
                        f"--rowDistance={point.row_distance} "
                        f"--speedTag={point.speed_tag} "
                        f"--seed={seed} "
                        f"--simTime={sim_time} "
                        f"--maxRange={max_range} "
                        f"--traceFile={tcl_path} "
                        f"--outDir={out_dir_abs} "
                        f"--outPrefix={out_prefix}"
                    )
                    plan.append({
                        "point_id": point.point_id,
                        "group_label": point.group_label,
                        "is_baseline": point.is_baseline,
                        "protocol": proto.upper(),
                        "condition": "Normal" if cond == "normal" else "DoS",
                        "total_nodes": point.total_nodes,
                        "row_distance": point.row_distance,
                        "speed_tag": point.speed_tag,
                        "seed": seed,
                        "program": prog_name,
                        "trace_file": tcl_path,
                        "out_prefix": out_prefix,
                        "expected_tr": os.path.join(out_dir_abs, f"{out_prefix}.tr"),
                        "expected_flowmon": os.path.join(out_dir_abs, f"{out_prefix}-flowmon-results.xml"),
                        "ns3_run_arg": ns3_args,
                    })
    return plan


def stage_cc_files_to_ns3(script_dir: str, ns3_dir: str) -> List[str]:
    """
    Menyalin keempat berkas `.cc` (OLSR & AODV, Normal & DoS) ke `<ns3_dir>/scratch/`.
    """
    scratch_dir = os.path.join(ns3_dir, "scratch")
    if not os.path.isdir(scratch_dir):
        raise FileNotFoundError(f"Direktori scratch NS-3 tidak ditemukan: {scratch_dir}")

    copied: List[str] = []
    for prog in CC_PROGRAM_MAP.values():
        src = os.path.join(script_dir, f"{prog}.cc")
        dst = os.path.join(scratch_dir, f"{prog}.cc")
        if not os.path.isfile(src):
            raise FileNotFoundError(f"Berkas sumber .cc tidak ditemukan: {src}")
        shutil.copy2(src, dst)
        copied.append(dst)
    return copied


def run_single_job(job: Dict[str, object], ns3_dir: str, skip_existing: bool = True) -> Tuple[str, int, str]:
    """
    Menjalankan satu skenario NS-3 via `./ns3 run --no-build "<ns3_run_arg>"`.
    """
    out_prefix = str(job["out_prefix"])
    expected_tr = str(job["expected_tr"])
    if skip_existing and os.path.isfile(expected_tr) and os.path.getsize(expected_tr) > 0:
        return (out_prefix, 0, "SKIPPED (file .tr sudah ada)")

    cmd = ["./ns3", "run", "--no-build", str(job["ns3_run_arg"])]
    proc = subprocess.run(
        cmd,
        cwd=ns3_dir,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    return (out_prefix, proc.returncode, proc.stdout[-500:] if proc.stdout else "")


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Batch Runner 36 Skenario OFAT VANET (AODV vs OLSR, Normal vs DoS)"
    )
    parser.add_argument(
        "--seeds",
        type=int,
        nargs="+",
        default=[1, 2, 3, 4, 5],
        help="Daftar seed yang dijalankan (default: 1 2 3 4 5 -> >= 5 seed)",
    )
    parser.add_argument(
        "--mobility-dir",
        default="mobility",
        help="Direktori tempat berkas .tcl mobilitas berada/dibangkitkan (default: mobility)",
    )
    parser.add_argument(
        "--out-dir",
        default="results_raw",
        help="Direktori keluaran untuk berkas .tr, XML FlowMonitor, dan summary (default: results_raw)",
    )
    parser.add_argument(
        "--ns3-dir",
        default="/home/dzaky/ns-3/ns-3-dev",
        help="Path direktori instalasi NS-3 (default: /home/dzaky/ns-3/ns-3-dev)",
    )
    parser.add_argument(
        "--sim-time",
        type=float,
        default=222.0,
        help="Durasi simulasi dalam detik (default: 222.0)",
    )
    parser.add_argument(
        "--max-range",
        type=float,
        default=250.0,
        help="Jangkauan radio MaxRange dalam meter (default: 250.0)",
    )
    parser.add_argument(
        "--points",
        nargs="+",
        default=None,
        help="Filter titik uji tertentu saja (mis. B0 A_n20 D_v15_25)",
    )
    parser.add_argument(
        "--stage-scratch",
        action="store_true",
        help="Salin keempat file .cc ke <ns3-dir>/scratch/ dan kompilasi dengan ./ns3 build",
    )
    parser.add_argument(
        "--jobs",
        type=int,
        default=1,
        help="Jumlah worker paralel saat menjalankan simulasi (default: 1)",
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="Jalankan ulang walaupun file .tr sudah ada",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Hanya cetak & simpan manifest rencana eksekusi 36 skenario x seed tanpa menjalankan NS-3",
    )
    parser.add_argument(
        "--parse-and-aggregate",
        action="store_true",
        help="Setelah simulasi selesai, jalankan vanet_trace_parser_ns3.py dan aggregate_vanet.py",
    )

    args = parser.parse_args()
    script_dir = os.path.dirname(os.path.abspath(__file__))
    os.makedirs(args.mobility_dir, exist_ok=True)
    os.makedirs(args.out_dir, exist_ok=True)

    # 1. Pastikan seluruh berkas mobilitas .tcl tersedia
    generate_all_ofat_uniform_traces(out_dir=args.mobility_dir, sim_time=args.sim_time)
    generate_kelompok_d_traces(
        seeds=args.seeds,
        out_dir=args.mobility_dir,
        sim_time=args.sim_time,
        max_range=args.max_range,
    )

    # 2. Bangun rencana eksekusi tanpa duplikasi Baseline B0
    plan = build_execution_plan(
        seeds=args.seeds,
        mobility_dir=args.mobility_dir,
        out_dir=args.out_dir,
        sim_time=args.sim_time,
        max_range=args.max_range,
        points_filter=args.points,
    )

    manifest_path = os.path.join(args.out_dir, "batch_execution_manifest.csv")
    if plan:
        with open(manifest_path, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=list(plan[0].keys()))
            writer.writeheader()
            writer.writerows(plan)

    unique_scenarios = len({(p["point_id"], p["protocol"], p["condition"]) for p in plan})
    print(
        f"[INFO] Rencana Batch: {unique_scenarios} skenario unik x {len(args.seeds)} seed "
        f"= {len(plan)} eksekusi (Baseline B0 dieksekusi 1x per protokol/kondisi/seed)."
    )
    print(f"[INFO] Manifest batch disimpan di: {manifest_path}")

    if args.dry_run:
        print("[DRY-RUN] 8 baris pertama dari rencana eksekusi:")
        for row in plan[:8]:
            print(f"  - [{row['point_id']}] {row['out_prefix']} -> trace={os.path.basename(str(row['trace_file']))}")
        return 0

    # 3. Stage .cc dan build NS-3 jika diminta
    if args.stage_scratch:
        copied = stage_cc_files_to_ns3(script_dir, args.ns3_dir)
        print(f"[INFO] Menyalin {len(copied)} file .cc ke {args.ns3_dir}/scratch/")
        build_proc = subprocess.run(["./ns3", "build"], cwd=args.ns3_dir)
        if build_proc.returncode != 0:
            print("[ERROR] Kompilasi './ns3 build' gagal.", file=sys.stderr)
            return build_proc.returncode

    # 4. Eksekusi pekerjaan simulasi
    failures = 0
    if args.jobs <= 1:
        for idx, job in enumerate(plan, start=1):
            prefix, rc, msg = run_single_job(job, args.ns3_dir, skip_existing=not args.force)
            status_str = "OK" if rc == 0 else f"FAIL({rc})"
            print(f"[{idx}/{len(plan)}] {prefix}: {status_str} {msg if 'SKIPPED' in msg else ''}")
            if rc != 0:
                failures += 1
    else:
        with ThreadPoolExecutor(max_workers=args.jobs) as pool:
            fut_map = {
                pool.submit(run_single_job, job, args.ns3_dir, not args.force): job
                for job in plan
            }
            done_cnt = 0
            for fut in as_completed(fut_map):
                done_cnt += 1
                prefix, rc, msg = fut.result()
                status_str = "OK" if rc == 0 else f"FAIL({rc})"
                print(f"[{done_cnt}/{len(plan)}] {prefix}: {status_str}")
                if rc != 0:
                    failures += 1

    # 5. Jalankan parser dan agregasi jika diminta
    if args.parse_and_aggregate and failures == 0:
        parsed_csv = os.path.join(args.out_dir, "parsed_all_runs.csv")
        detail_json = os.path.join(args.out_dir, "parsed_all_runs_detail.json")
        parser_script = os.path.join(script_dir, "vanet_trace_parser_ns3.py")
        agg_script = os.path.join(script_dir, "aggregate_vanet.py")

        tr_files = [str(job["expected_tr"]) for job in plan if os.path.isfile(str(job["expected_tr"]))]
        if tr_files:
            cmd_parse = [
                sys.executable,
                parser_script,
                "-d",
                args.out_dir,
                "--flowmon-xml",
                args.out_dir,
                "--strict",
                "-o",
                parsed_csv,
                "--detail-json",
                detail_json,
            ]
            subprocess.run(cmd_parse, check=True)
            cmd_agg = [
                sys.executable,
                agg_script,
                "-i",
                parsed_csv,
                "-o",
                os.path.join(args.out_dir, "aggregated"),
            ]
            subprocess.run(cmd_agg, check=True)

    return 1 if failures > 0 else 0


if __name__ == "__main__":
    raise SystemExit(main())
