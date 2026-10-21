#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
aggregate_vanet.py
==================

Skrip agregasi statistik dan visualisasi grafik hasil simulasi komparatif
AODV vs OLSR pada VANET multi-hop IEEE 802.11p (Normal vs DoS, desain OFAT).

Fitur utama (Tugas C)
---------------------
1. Membaca CSV keluaran ``vanet_trace_parser_ns3.py`` (banyak baris/seed).
2. Menggunakan ulang (referensi silang) baris **Baseline (B0: 10 node, 200 m,
   20 km/jam seragam)** ke dalam:
   - Kelompok A (Kepadatan: 10, 20, 30 node)
   - Kelompok B (Jarak: 100, 200, 300, 400 m)
   - Kelompok C (Kecepatan seragam: 20, 30, 40 km/jam)
   - Pembanding Baseline untuk Kelompok D (Kecepatan heterogen 15-25 km/jam)
   tanpa menghitung dua kali seed yang sama pada kelompok yang sama.
3. Menghitung metrik berpasangan Normal vs DoS per ``(Protokol, Kelompok_OFAT,
   Nilai_Variabel, Seed)``:
   - ``Delta_PDR = PDR_Normal - PDR_DoS``
   - ``Delta_Delay = Avg_Delay_Normal - Avg_Delay_DoS`` (serta ``Delta_Delay_DoS_minus_Normal``)
   - ``Delta_Median_Delay = Median_Delay_Normal - Median_Delay_DoS``
   - ``Degradasi_PDR_pct = (PDR_Normal - PDR_DoS) / PDR_Normal * 100``
   - ``Degradasi_Throughput_pct = (Thr_Normal - Thr_DoS) / Thr_Normal * 100``
   - ``Degradasi_Delay_pct = (Avg_Delay_Normal - Avg_Delay_DoS) / Avg_Delay_Normal * 100``
4. Mengelompokkan per ``(Protokol, Kondisi, Kelompok_OFAT, Nilai_Variabel)`` dan
   menghitung ``mean``, ``std`` (sampel, ddof=1), serta **CI 95% (t-distribution)**
   di atas ``Seed``.
5. Menghasilkan:
   - CSV ringkasan agregasi (``vanet_aggregated_summary.csv``)
   - CSV pasangan degradasi per-seed (``vanet_paired_degradation.csv``)
   - Grafik PNG per kelompok (4 seri: ``AODV-Normal``, ``AODV-DoS``,
     ``OLSR-Normal``, ``OLSR-DoS`` dengan error bar CI 95% / std):
     * Kelompok A, B, C: grafik garis dengan error bar untuk PDR, Delay
       (Median + P95), Throughput, dan RO/NRL.
     * Kelompok D: grafik batang terkelompok (grouped bar chart) / titik
       perbandingan terhadap Baseline (bukan sumbu kontinu).

Contoh pemakaian
----------------
    python aggregate_vanet.py -i vanet_metrics_ns3.csv -o hasil_agregasi
"""

from __future__ import annotations

import argparse
import math
import sys
from pathlib import Path
from typing import Dict, List, Optional, Sequence, Tuple

import numpy as np
import pandas as pd

# Tabel kuantil kritis dua-arah t_{0.975, df} (alpha=0.05, CI 95%) untuk df = 1..30
_T_CRIT_95 = {
    1: 12.706205, 2: 4.302653, 3: 3.182446, 4: 2.776445, 5: 2.570582,
    6: 2.446912, 7: 2.364624, 8: 2.306004, 9: 2.262157, 10: 2.228139,
    11: 2.200985, 12: 2.178813, 13: 2.160369, 14: 2.144787, 15: 2.131450,
    16: 2.119905, 17: 2.109816, 18: 2.100922, 19: 2.093024, 20: 2.085963,
    21: 2.079614, 22: 2.073873, 23: 2.068658, 24: 2.063899, 25: 2.059539,
    26: 2.055529, 27: 2.051831, 28: 2.048407, 29: 2.045230, 30: 2.042272,
}


def t_crit_95(df: int) -> float:
    """Nilai kritis distribusi-t Student dua-arah untuk CI 95% (alpha=0.05)."""
    if df <= 0:
        return float("nan")
    if df in _T_CRIT_95:
        return _T_CRIT_95[df]
    # Aproksimasi Peizer-Pratt / Cornish-Fisher akurat untuk df > 30
    z = 1.959963984540054
    return z + (z**3 + z) / (4.0 * df) + (5.0 * z**5 + 16.0 * z**3 + 3.0 * z) / (96.0 * df**2)


METRICS_TO_AGGREGATE = [
    "Legal_Sent_App",
    "Legal_Sent",
    "Legal_Received",
    "Legal_Lost",
    "PDR_pct",
    "PLR_pct",
    "Avg_Delay_ms",
    "Median_Delay_ms",
    "P95_Delay_ms",
    "P99_Delay_ms",
    "Max_Delay_ms",
    "Throughput_kbps",
    "Throughput_active_kbps",
    "Active_Duration_s",
    "Routing_Packets_Sent",
    "Routing_Bytes_Sent",
    "Routing_Overhead",
    "NRL",
    "HELLO_Msgs",
    "TC_Msgs",
    "RREQ_Msgs",
    "RREP_Msgs",
    "RERR_Msgs",
    "Hello_Msgs",
    "DoS_Packets_Detected",
    "DoS_Rate_Observed_Mbps",
    "DoS_Id_Gap",
    "MAC_Retry_Count",
    "MAC_Retry_Ratio",
    "Hop_Count_Mean",
    "Route_Change_Count",
    "Num_Loss_Windows",
    "Longest_Outage_s",
]

SERIES_ORDER = [
    ("AODV", "Normal", "AODV-Normal", "#1f77b4", "-", "o"),
    ("AODV", "DoS", "AODV-DoS", "#d62728", "--", "s"),
    ("OLSR", "Normal", "OLSR-Normal", "#2ca02c", "-", "^"),
    ("OLSR", "DoS", "OLSR-DoS", "#ff7f0e", "--", "D"),
]


def expand_baseline_rows(df: pd.DataFrame) -> pd.DataFrame:
    """Rujuk ulang baris Baseline (10 node, 200 m, 20 km/jam seragam) ke Kelompok A, B, dan C.

    Jika baris baseline sudah berlabel ``Baseline`` atau ``Is_Baseline == 1``,
    baris tersebut direplikasi secara virtual ke:
      - Kelompok A: Variabel_Uji='Kepadatan', Nilai_Variabel='10'
      - Kelompok B: Variabel_Uji='Jarak', Nilai_Variabel='200'
      - Kelompok C: Variabel_Uji='Kecepatan', Nilai_Variabel='20'
    Lalu dideduplikasi per ``(Protokol, Kondisi, Kelompok_OFAT, Nilai_Variabel, Seed)``
    agar titik baseline tidak pernah dihitung dua kali.
    """
    df = df.copy()
    if "Seed" not in df.columns or df["Seed"].isna().all():
        df["Seed"] = df.get("Run", 1).fillna(1).astype(int)
    else:
        df["Seed"] = df["Seed"].fillna(1).astype(int)

    if "Is_Baseline" not in df.columns:
        df["Is_Baseline"] = (
            (df.get("Jumlah_Node") == 10)
            & (df.get("Jarak_m") == 200)
            & (df.get("Kecepatan_kmh").astype(str) == "20")
            & (df.get("Kelompok_OFAT") != "D")
        ).astype(int)

    # Prioritaskan baris dengan Kelompok_OFAT == 'Baseline' terlebih dahulu
    explicit_base = df[df["Kelompok_OFAT"] == "Baseline"]
    implicit_base = df[(df["Kelompok_OFAT"] != "Baseline") & (df["Is_Baseline"] == 1)]
    base_rows = pd.concat([explicit_base, implicit_base], ignore_index=True)

    # Deduplikasi baseline per (Protokol, Kondisi, Seed)
    base_unique = base_rows.drop_duplicates(subset=["Protokol", "Kondisi", "Seed"], keep="first").copy()

    # Pertahankan seluruh baris yang sudah memiliki kelompok eksplisit (A, B, C, D)
    non_base = df[df["Kelompok_OFAT"] != "Baseline"].copy()
    expanded: List[pd.DataFrame] = [non_base]

    if not base_unique.empty:
        # Simpan juga grup Baseline eksplisit (untuk perbandingan Kelompok D)
        b_ref = base_unique.copy()
        b_ref["Kelompok_OFAT"] = "Baseline"
        b_ref["Variabel_Uji"] = "Baseline"
        b_ref["Nilai_Variabel"] = "Baseline (20 km/jam seragam)"
        expanded.append(b_ref)

        for grp, var_name, val_str in (
            ("A", "Kepadatan", "10"),
            ("B", "Jarak", "200"),
            ("C", "Kecepatan", "20"),
        ):
            g_df = base_unique.copy()
            g_df["Kelompok_OFAT"] = grp
            g_df["Variabel_Uji"] = var_name
            g_df["Nilai_Variabel"] = val_str
            expanded.append(g_df)

    combined = pd.concat(expanded, ignore_index=True)
    combined["Nilai_Variabel"] = combined["Nilai_Variabel"].astype(str)
    combined = combined.drop_duplicates(
        subset=["Protokol", "Kondisi", "Kelompok_OFAT", "Nilai_Variabel", "Seed"],
        keep="first",
    )
    return combined


def compute_paired_degradation(df: pd.DataFrame) -> pd.DataFrame:
    """Hitung Delta_PDR, Delta_Delay, dan Degradasi_% = (Normal - DoS)/Normal per pasangan seed."""
    key_cols = ["Protokol", "Kelompok_OFAT", "Variabel_Uji", "Nilai_Variabel", "Seed"]
    normal_df = df[df["Kondisi"] == "Normal"].copy()
    dos_df = df[df["Kondisi"] == "DoS"].copy()

    if normal_df.empty or dos_df.empty:
        return pd.DataFrame()

    keep_metrics = [
        c for c in (
            "PDR_pct", "Avg_Delay_ms", "Median_Delay_ms", "P95_Delay_ms",
            "Throughput_kbps", "Routing_Overhead", "NRL",
        )
        if c in df.columns
    ]
    merged = pd.merge(
        normal_df[key_cols + keep_metrics],
        dos_df[key_cols + keep_metrics],
        on=key_cols,
        suffixes=("_Normal", "_DoS"),
        how="inner",
    )
    if merged.empty:
        return merged

    if "PDR_pct_Normal" in merged and "PDR_pct_DoS" in merged:
        merged["Delta_PDR"] = merged["PDR_pct_Normal"] - merged["PDR_pct_DoS"]
        merged["Degradasi_PDR_%"] = np.where(
            merged["PDR_pct_Normal"] != 0,
            (merged["PDR_pct_Normal"] - merged["PDR_pct_DoS"]) / merged["PDR_pct_Normal"] * 100.0,
            np.nan,
        )

    if "Avg_Delay_ms_Normal" in merged and "Avg_Delay_ms_DoS" in merged:
        merged["Delta_Delay"] = merged["Avg_Delay_ms_Normal"] - merged["Avg_Delay_ms_DoS"]
        merged["Delta_Delay_Increase_ms"] = merged["Avg_Delay_ms_DoS"] - merged["Avg_Delay_ms_Normal"]
        merged["Degradasi_Delay_%"] = np.where(
            merged["Avg_Delay_ms_Normal"] != 0,
            (merged["Avg_Delay_ms_Normal"] - merged["Avg_Delay_ms_DoS"])
            / merged["Avg_Delay_ms_Normal"] * 100.0,
            np.nan,
        )

    if "Median_Delay_ms_Normal" in merged and "Median_Delay_ms_DoS" in merged:
        merged["Delta_Median_Delay"] = (
            merged["Median_Delay_ms_Normal"] - merged["Median_Delay_ms_DoS"]
        )

    if "Throughput_kbps_Normal" in merged and "Throughput_kbps_DoS" in merged:
        merged["Delta_Throughput_kbps"] = (
            merged["Throughput_kbps_Normal"] - merged["Throughput_kbps_DoS"]
        )
        merged["Degradasi_Throughput_%"] = np.where(
            merged["Throughput_kbps_Normal"] != 0,
            (merged["Throughput_kbps_Normal"] - merged["Throughput_kbps_DoS"])
            / merged["Throughput_kbps_Normal"] * 100.0,
            np.nan,
        )

    return merged


def _agg_series(s: pd.Series) -> Tuple[int, float, float, float]:
    """Return (n, mean, std, ci95) untuk satu seri numerik di atas seed."""
    valid = pd.to_numeric(s, errors="coerce").dropna()
    n = len(valid)
    if n == 0:
        return 0, np.nan, np.nan, np.nan
    mean_v = float(valid.mean())
    if n == 1:
        return 1, mean_v, 0.0, 0.0
    std_v = float(valid.std(ddof=1))
    ci95_v = t_crit_95(n - 1) * std_v / math.sqrt(n)
    return n, mean_v, std_v, ci95_v


def aggregate_metrics(df: pd.DataFrame, paired_df: pd.DataFrame) -> pd.DataFrame:
    """Kelompokkan per (Protokol, Kondisi, Kelompok_OFAT, Nilai_Variabel) dan hitung mean, std, CI95."""
    group_cols = ["Protokol", "Kondisi", "Kelompok_OFAT", "Variabel_Uji", "Nilai_Variabel"]
    avail_metrics = [c for c in METRICS_TO_AGGREGATE if c in df.columns]

    rows: List[Dict[str, object]] = []
    for keys, grp in df.groupby(group_cols, dropna=False):
        proto, cond, klp, var_uji, nilai = keys
        rec: Dict[str, object] = {
            "Protokol": proto,
            "Kondisi": cond,
            "Kelompok_OFAT": klp,
            "Variabel_Uji": var_uji,
            "Nilai_Variabel": nilai,
            "N_Seeds": int(grp["Seed"].nunique()),
        }
        for col in avail_metrics:
            n, mean_v, std_v, ci95_v = _agg_series(grp[col])
            rec[f"{col}_mean"] = round(mean_v, 4) if not np.isnan(mean_v) else np.nan
            rec[f"{col}_std"] = round(std_v, 4) if not np.isnan(std_v) else np.nan
            rec[f"{col}_ci95"] = round(ci95_v, 4) if not np.isnan(ci95_v) else np.nan

        # Tambahkan ringkasan Delta/Degradasi pada baris skenario yang memiliki pasangan
        if not paired_df.empty:
            p_sub = paired_df[
                (paired_df["Protokol"] == proto)
                & (paired_df["Kelompok_OFAT"] == klp)
                & (paired_df["Nilai_Variabel"] == str(nilai))
            ]
            for dcol in (
                "Delta_PDR", "Degradasi_PDR_%",
                "Delta_Delay", "Delta_Delay_Increase_ms", "Degradasi_Delay_%",
                "Delta_Throughput_kbps", "Degradasi_Throughput_%",
            ):
                if dcol in p_sub.columns:
                    _, m_v, s_v, c_v = _agg_series(p_sub[dcol])
                    rec[f"{dcol}_mean"] = round(m_v, 4) if not np.isnan(m_v) else np.nan
                    rec[f"{dcol}_std"] = round(s_v, 4) if not np.isnan(s_v) else np.nan
                    rec[f"{dcol}_ci95"] = round(c_v, 4) if not np.isnan(c_v) else np.nan

        rows.append(rec)

    res = pd.DataFrame(rows)
    if not res.empty:
        res["_num"] = pd.to_numeric(res["Nilai_Variabel"], errors="coerce").fillna(9999.0)
        res = res.sort_values(
            by=["Kelompok_OFAT", "_num", "Protokol", "Kondisi"]
        ).drop(columns=["_num"]).reset_index(drop=True)
    return res


def plot_ofat_groups(summary_df: pd.DataFrame, out_dir: Path) -> List[Path]:
    """Hasilkan grafik PNG per kelompok (A, B, C: garis + error bar; D: batang perbandingan vs Baseline)."""
    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
    except ImportError:
        print("[!] matplotlib tidak tersedia; melewati pembuatan grafik PNG.", file=sys.stderr)
        return []

    out_dir.mkdir(parents=True, exist_ok=True)
    saved_files: List[Path] = []

    group_meta = {
        "A": ("Kelompok A - Variasi Kepadatan Kendaraan", "Jumlah Node Kendaraan", [10, 20, 30]),
        "B": ("Kelompok B - Variasi Jarak Antar-Baris", "Jarak Antar-Baris (m)", [100, 200, 300, 400]),
        "C": ("Kelompok C - Variasi Kecepatan Seragam", "Kecepatan Kendaraan (km/jam)", [20, 30, 40]),
    }

    # 1. Kelompok A, B, C (Garis dengan error bar CI 95%)
    for grp, (title_prefix, xlabel, x_ticks) in group_meta.items():
        sub = summary_df[summary_df["Kelompok_OFAT"] == grp].copy()
        if sub.empty:
            continue
        sub["x_val"] = pd.to_numeric(sub["Nilai_Variabel"], errors="coerce")
        sub = sub.dropna(subset=["x_val"]).sort_values("x_val")
        if sub.empty:
            continue

        fig, axes = plt.subplots(2, 3, figsize=(18, 9.5), dpi=150)
        fig.suptitle(f"{title_prefix} (Error Bar: 95% CI)", fontsize=14, fontweight="bold")

        # Panel (0,0): PDR (%)
        ax = axes[0, 0]
        _plot_4_series_line(ax, sub, "PDR_pct", xlabel, "PDR (%)", "Packet Delivery Ratio (PDR)", x_ticks)
        ax.set_ylim(-5, 105)

        # Panel (0,1): PLR / Packet Loss Ratio (%)
        ax = axes[0, 1]
        _plot_4_series_line(ax, sub, "PLR_pct", xlabel, "PLR (%)", "Packet Loss Ratio (PLR)", x_ticks)
        ax.set_ylim(-5, 105)

        # Panel (0,2): Delay (Median + P95)
        ax = axes[0, 2]
        _plot_delay_panel_line(ax, sub, xlabel, x_ticks)

        # Panel (1,0): Throughput (kbps)
        ax = axes[1, 0]
        _plot_4_series_line(ax, sub, "Throughput_kbps", xlabel, "Throughput (kbps)", "Throughput (kbps)", x_ticks)

        # Panel (1,1): Routing Overhead (RO)
        ax = axes[1, 1]
        _plot_4_series_line(ax, sub, "Routing_Overhead", xlabel, "Routing Overhead (rasio)", "Routing Overhead (RO)", x_ticks)

        # Panel (1,2): Normalized Routing Load (NRL)
        ax = axes[1, 2]
        _plot_4_series_line(ax, sub, "NRL", xlabel, "NRL (rasio)", "Normalized Routing Load (NRL)", x_ticks)

        fig.tight_layout(rect=[0, 0, 1, 0.96])
        out_png = out_dir / f"grafik_kelompok_{grp}.png"
        fig.savefig(out_png)
        plt.close(fig)
        saved_files.append(out_png)

    # 2. Kelompok D (Batang / titik perbandingan terhadap Baseline, BUKAN sumbu kontinu)
    sub_d = summary_df[summary_df["Kelompok_OFAT"].isin(["Baseline", "D"])].copy()
    if not sub_d.empty and (sub_d["Kelompok_OFAT"] == "D").any():
        fig, axes = plt.subplots(2, 3, figsize=(18, 9.5), dpi=150)
        fig.suptitle(
            "Kelompok D - Kecepatan Heterogen (15-25 km/jam) vs Baseline (20 km/jam Seragam)",
            fontsize=14,
            fontweight="bold",
        )
        _plot_group_d_bars(axes[0, 0], sub_d, "PDR_pct", "PDR (%)", "Packet Delivery Ratio (PDR)")
        axes[0, 0].set_ylim(0, 108)
        _plot_group_d_bars(axes[0, 1], sub_d, "PLR_pct", "PLR (%)", "Packet Loss Ratio (PLR)")
        axes[0, 1].set_ylim(0, 108)
        _plot_group_d_delay_bars(axes[0, 2], sub_d)
        _plot_group_d_bars(axes[1, 0], sub_d, "Throughput_kbps", "Throughput (kbps)", "Throughput (kbps)")
        _plot_group_d_bars(axes[1, 1], sub_d, "Routing_Overhead", "Routing Overhead (rasio)", "Routing Overhead (RO)")
        _plot_group_d_bars(axes[1, 2], sub_d, "NRL", "NRL (rasio)", "Normalized Routing Load (NRL)")

        fig.tight_layout(rect=[0, 0, 1, 0.96])
        out_png = out_dir / "grafik_kelompok_D.png"
        fig.savefig(out_png)
        plt.close(fig)
        saved_files.append(out_png)

    return saved_files


def _plot_4_series_line(ax, sub: pd.DataFrame, metric: str, xlabel: str, ylabel: str, title: str, x_ticks: Sequence[int]) -> None:
    m_col = f"{metric}_mean"
    e_col = f"{metric}_ci95"
    if m_col not in sub.columns:
        return
    for proto, cond, label, color, ls, marker in SERIES_ORDER:
        s = sub[(sub["Protokol"] == proto) & (sub["Kondisi"] == cond)]
        if s.empty:
            continue
        x = s["x_val"].to_numpy(dtype=float)
        y = s[m_col].to_numpy(dtype=float)
        yerr = s[e_col].fillna(0.0).to_numpy(dtype=float) if e_col in s.columns else np.zeros_like(y)
        valid = ~np.isnan(y)
        if not valid.any():
            continue
        ax.errorbar(
            x[valid], y[valid], yerr=yerr[valid],
            label=label, color=color, linestyle=ls, marker=marker,
            capsize=4, linewidth=1.8, markersize=6,
        )
    ax.set_title(title, fontsize=11, fontweight="bold")
    ax.set_xlabel(xlabel)
    ax.set_ylabel(ylabel)
    ax.set_xticks(x_ticks)
    ax.grid(True, linestyle=":", alpha=0.6)
    ax.legend(fontsize=8.5)


def _plot_delay_panel_line(ax, sub: pd.DataFrame, xlabel: str, x_ticks: Sequence[int]) -> None:
    for proto, cond, label, color, ls, marker in SERIES_ORDER:
        s = sub[(sub["Protokol"] == proto) & (sub["Kondisi"] == cond)]
        if s.empty:
            continue
        x = s["x_val"].to_numpy(dtype=float)
        if "Median_Delay_ms_mean" in s.columns:
            y_med = s["Median_Delay_ms_mean"].to_numpy(dtype=float)
            e_med = s["Median_Delay_ms_ci95"].fillna(0.0).to_numpy(dtype=float)
            v = ~np.isnan(y_med)
            if v.any():
                ax.errorbar(
                    x[v], y_med[v], yerr=e_med[v],
                    label=f"{label} (Median)", color=color, linestyle=ls, marker=marker,
                    capsize=3, linewidth=1.8, markersize=5,
                )
        if "P95_Delay_ms_mean" in s.columns:
            y_p95 = s["P95_Delay_ms_mean"].to_numpy(dtype=float)
            v95 = ~np.isnan(y_p95)
            if v95.any():
                ax.plot(
                    x[v95], y_p95[v95],
                    label=f"{label} (P95)", color=color, linestyle=":", marker=marker,
                    alpha=0.65, linewidth=1.3, markersize=4,
                )
    ax.set_title("End-to-End Delay: Median & P95 (ms)", fontsize=11, fontweight="bold")
    ax.set_xlabel(xlabel)
    ax.set_ylabel("Delay (ms)")
    ax.set_xticks(x_ticks)
    ax.grid(True, linestyle=":", alpha=0.6)
    ax.legend(fontsize=7.5, ncol=2)


def _plot_ro_nrl_panel_line(ax, sub: pd.DataFrame, xlabel: str, x_ticks: Sequence[int]) -> None:
    for proto, cond, label, color, ls, marker in SERIES_ORDER:
        s = sub[(sub["Protokol"] == proto) & (sub["Kondisi"] == cond)]
        if s.empty:
            continue
        x = s["x_val"].to_numpy(dtype=float)
        if "NRL_mean" in s.columns:
            y_nrl = s["NRL_mean"].to_numpy(dtype=float)
            e_nrl = s["NRL_ci95"].fillna(0.0).to_numpy(dtype=float)
            v = ~np.isnan(y_nrl)
            if v.any():
                ax.errorbar(
                    x[v], y_nrl[v], yerr=e_nrl[v],
                    label=f"{label} (NRL)", color=color, linestyle=ls, marker=marker,
                    capsize=3, linewidth=1.8, markersize=5,
                )
        if "Routing_Overhead_mean" in s.columns:
            y_ro = s["Routing_Overhead_mean"].to_numpy(dtype=float)
            v_ro = ~np.isnan(y_ro)
            if v_ro.any():
                ax.plot(
                    x[v_ro], y_ro[v_ro],
                    label=f"{label} (RO)", color=color, linestyle=":", marker=marker,
                    alpha=0.65, linewidth=1.3, markersize=4,
                )
    ax.set_title("Beban Kontrol Routing: NRL & RO", fontsize=11, fontweight="bold")
    ax.set_xlabel(xlabel)
    ax.set_ylabel("Rasio Paket Kontrol")
    ax.set_xticks(x_ticks)
    ax.grid(True, linestyle=":", alpha=0.6)
    ax.legend(fontsize=7.5, ncol=2)


def _plot_group_d_bars(ax, sub_d: pd.DataFrame, metric: str, ylabel: str, title: str) -> None:
    categories = ["Baseline", "D"]
    cat_labels = ["Baseline\n(20 km/jam Seragam)", "Kelompok D\n(15-25 km/jam Acak)"]
    x = np.arange(len(categories))
    width = 0.18
    m_col = f"{metric}_mean"
    e_col = f"{metric}_ci95"

    for idx, (proto, cond, label, color, _, _) in enumerate(SERIES_ORDER):
        means, errs = [], []
        for cat in categories:
            row = sub_d[
                (sub_d["Kelompok_OFAT"] == cat)
                & (sub_d["Protokol"] == proto)
                & (sub_d["Kondisi"] == cond)
            ]
            if not row.empty and m_col in row.columns:
                val = float(row.iloc[0][m_col])
                err = float(row.iloc[0][e_col]) if e_col in row.columns and not pd.isna(row.iloc[0][e_col]) else 0.0
                means.append(0.0 if np.isnan(val) else val)
                errs.append(0.0 if np.isnan(err) else err)
            else:
                means.append(0.0)
                errs.append(0.0)
        offset = (idx - 1.5) * width
        ax.bar(x + offset, means, width, yerr=errs, label=label, color=color, capsize=3, alpha=0.88)

    ax.set_title(title, fontsize=11, fontweight="bold")
    ax.set_xticks(x)
    ax.set_xticklabels(cat_labels)
    ax.set_ylabel(ylabel)
    ax.grid(True, axis="y", linestyle=":", alpha=0.6)
    ax.legend(fontsize=8.5)


def _plot_group_d_delay_bars(ax, sub_d: pd.DataFrame) -> None:
    categories = ["Baseline", "D"]
    cat_labels = ["Baseline\n(20 km/jam Seragam)", "Kelompok D\n(15-25 km/jam Acak)"]
    x = np.arange(len(categories))
    width = 0.18

    for idx, (proto, cond, label, color, _, _) in enumerate(SERIES_ORDER):
        meds, errs, p95s = [], [], []
        for cat in categories:
            row = sub_d[
                (sub_d["Kelompok_OFAT"] == cat)
                & (sub_d["Protokol"] == proto)
                & (sub_d["Kondisi"] == cond)
            ]
            if not row.empty:
                m_val = float(row.iloc[0].get("Median_Delay_ms_mean", np.nan))
                e_val = float(row.iloc[0].get("Median_Delay_ms_ci95", 0.0))
                p_val = float(row.iloc[0].get("P95_Delay_ms_mean", np.nan))
                meds.append(0.0 if np.isnan(m_val) else m_val)
                errs.append(0.0 if np.isnan(e_val) else e_val)
                p95s.append(np.nan if np.isnan(p_val) else p_val)
            else:
                meds.append(0.0)
                errs.append(0.0)
                p95s.append(np.nan)
        offset = (idx - 1.5) * width
        ax.bar(x + offset, meds, width, yerr=errs, label=f"{label} (Median)", color=color, capsize=3, alpha=0.85)
        ax.plot(x + offset, p95s, marker="D", linestyle="none", color="black", markersize=4)

    ax.set_title("End-to-End Delay: Median (Batang) & P95 (Titik ◆)", fontsize=11, fontweight="bold")
    ax.set_xticks(x)
    ax.set_xticklabels(cat_labels)
    ax.set_ylabel("Delay (ms)")
    ax.grid(True, axis="y", linestyle=":", alpha=0.6)
    ax.legend(fontsize=8)


def build_arg_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="Agregasi statistik (mean, std, CI 95% t-dist, Delta/Degradasi) & grafik PNG VANET."
    )
    p.add_argument("-i", "--input", nargs="+", default=["vanet_metrics_ns3.csv"], metavar="CSV",
                   help="satu atau lebih file CSV hasil vanet_trace_parser_ns3.py")
    p.add_argument("-o", "--out-dir", default="hasil_agregasi", metavar="DIR",
                   help="folder keluaran untuk CSV ringkasan dan grafik PNG (default: hasil_agregasi)")
    p.add_argument("--summary-csv", default="vanet_aggregated_summary.csv",
                   help="nama file CSV ringkasan agregasi di dalam --out-dir")
    p.add_argument("--paired-csv", default="vanet_paired_degradation.csv",
                   help="nama file CSV degradasi Normal-vs-DoS per pasangan seed di dalam --out-dir")
    p.add_argument("--no-plots", action="store_true",
                   help="jangan buat grafik PNG (hanya ekspor CSV)")
    return p


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = build_arg_parser().parse_args(argv)
    dfs: List[pd.DataFrame] = []
    for p_str in args.input:
        p = Path(p_str)
        if not p.is_file():
            print(f"[!] File CSV tidak ditemukan: {p}", file=sys.stderr)
            continue
        dfs.append(pd.read_csv(p))
    if not dfs:
        print("Tidak ada file CSV input yang valid.", file=sys.stderr)
        return 2

    raw_df = pd.concat(dfs, ignore_index=True)
    expanded_df = expand_baseline_rows(raw_df)
    paired_df = compute_paired_degradation(expanded_df)
    summary_df = aggregate_metrics(expanded_df, paired_df)

    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    summary_path = out_dir / args.summary_csv
    summary_df.to_csv(summary_path, index=False)
    print(f"[+] CSV Ringkasan Agregasi : {summary_path.resolve()} ({len(summary_df)} baris)")

    if not paired_df.empty:
        paired_path = out_dir / args.paired_csv
        paired_df.to_csv(paired_path, index=False)
        print(f"[+] CSV Pasangan Degradasi : {paired_path.resolve()} ({len(paired_df)} pasangan)")

    if not args.no_plots:
        pngs = plot_ofat_groups(summary_df, out_dir)
        for png in pngs:
            print(f"[+] Grafik PNG             : {png.resolve()}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
