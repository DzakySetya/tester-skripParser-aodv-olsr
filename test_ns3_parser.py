#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Uji unit & regresi vanet_trace_parser_ns3.py.

Mencakup:
1. Trace PHY Wi-Fi sintetis (paket legal sampai, hilang, duplikat, retry,
   overhearing, broadcast DoS, paket kontrol OLSR dengan HELLO+TC gabungan,
   serta trace sintetis AODV dengan RREQ/RREP/RERR/Hello).
2. Verifikasi opsi --strict, --flowmon-xml, --detail-json, dan format CSV
   'sim' (tanpa Legal_Drop_Events) vs 'full' (dengan Legal_Drop_Events).
3. Uji regresi wajib pada trace asli:
   - tester/olsr-mh-normal.tr
   - tester/olsr-mh-dos.tr

Jalankan:  py test_ns3_parser.py
"""
import csv
import json
import statistics
import sys
import tempfile
from pathlib import Path

import vanet_trace_parser_ns3 as P

HDR = (
    "{ev} {t:.6f} {rate}/NodeList/{n}/DeviceList/0/$ns3::WifiNetDevice/Phy/State/{st} {rate2}"
    "ns3::WifiMacHeader (DATA ToDS=0, FromDS=0, MoreFrag=0, Retry={retry}, PowerManagement=0, "
    "MoreData=0 Duration/ID=0us, {da}SA(TA)=00:00:00:00:00:01, BSSID=00:00:00:00:00:01, "
    "FragNumber=0, SeqNumber={seq}) ns3::LlcSnapHeader (type 0x800) ns3::Ipv4Header (tos 0x0 "
    "DSCP Default ECN Not-ECT ttl 64 id {ipid} protocol 17 offset (bytes) 0 flags [none] "
    "length: {iplen} {src} > {dst}) ns3::UdpHeader (length: {udplen} {sp} > {dp}) {tail}"
)


def mac(node: int) -> str:
    return f"00:00:00:00:00:{node + 1:02x}"


def line(
    ev, t, n, src, dst, ipid, sp, dp, size,
    da_node=None, retry=0, seq=0, tail=None,
):
    tx = ev == "t"
    da = "" if da_node == "none" else f"DA(RA)={'ff:ff:ff:ff:ff:ff' if da_node is None else mac(da_node)}, "
    if tail is None:
        tail = f"Payload (size={size})"
    return HDR.format(
        ev=ev, t=t, n=n, st="Tx" if tx else "RxOk",
        rate="" if tx else "OfdmRate6MbpsBW10MHz ",
        rate2="OfdmRate6MbpsBW10MHz " if tx else "",
        retry=retry, da=da, seq=seq, ipid=ipid, iplen=size + 28,
        src=src, dst=dst, udplen=size + 8, sp=sp, dp=dp, tail=tail,
    )


def build_synthetic_olsr(path: Path):
    """Bangun trace sintetis OLSR yang menguji seluruh fitur parser."""
    L, delays = [], []
    S, D = "10.1.1.1", "10.1.1.10"          # node 0 -> node 9
    for i in range(100):                    # 100 paket legal
        t = 5.0 + 2 * i
        # Hop pertama: i < 50 lewat relay node 3, i >= 50 lewat relay node 4 (1 pergantian rute!)
        relay = 3 if i < 50 else 4
        L.append(line("t", t, 0, S, D, i, 49153, 9, 512, da_node=relay, seq=i))
        L.append(line("t", t + 0.002, 0, S, D, i, 49153, 9, 512, da_node=relay, retry=1, seq=i))  # retry
        L.append(line("t", t + 0.004, relay, S, D, i, 49153, 9, 512, da_node=9, seq=500 + i))     # forwarder
        if i < 80:
            dly = 0.010 + i * 0.0005
            # overhearing: node 9 mendengar frame yang dialamatkan ke relay -> HARUS ditolak
            L.append(line("r", t + 0.001, 9, S, D, i, 49153, 9, 512, da_node=relay, seq=i))
            L.append(line("r", t + dly, 9, S, D, i, 49153, 9, 512, da_node=9, seq=500 + i))
            L.append(line("r", t + dly + 0.0001, 9, S, D, i, 49153, 9, 512, da_node=9, seq=500 + i))  # dup
            delays.append(dly * 1000)

    # Paket legal ke-101: diterima tanpa DA(RA) -> tidak dihitung (missing_da = 1, lost)
    L.append(line("t", 202.5, 0, S, D, 900, 49153, 9, 512, da_node=4))
    L.append(line("r", 202.52, 9, S, D, 900, 49153, 9, 512, da_node="none"))

    # Paket legal ke-102: IP-ID 0 dipakai ulang > 60 s setelah id 0 pertama -> paket baru (sampai, 1 hop)
    L.append(line("t", 210.0, 0, S, D, 0, 49153, 9, 512, da_node=9))
    L.append(line("r", 210.03, 9, S, D, 0, 49153, 9, 512, da_node=9))
    delays.append(30.0)

    # 25 paket kontrol OLSR:
    # - 20 paket hanya HELLO (20 HELLO)
    # - 5 paket gabungan HELLO + 2 TC sekaligus (5 HELLO + 10 TC)
    # Total pesan: HELLO_Msgs = 25, TC_Msgs = 10; Routing_Packets_Sent = 25
    hello_only = (
        "ns3::olsr::PacketHeader (len: 20 seqNo: 1) "
        "ns3::olsr::MessageHeader (type: HELLO TTL: 1 Orig: 10.1.1.1 SeqNo: 1 Validity: 134 Hop count: 0 Size: 16)"
    )
    hello_plus_2tc = (
        "ns3::olsr::PacketHeader (len: 52 seqNo: 2) "
        "ns3::olsr::MessageHeader (type: TC TTL: 255 Orig: 10.1.1.2 SeqNo: 1 Validity: 199 Hop count: 1 Size: 16) "
        "ns3::olsr::MessageHeader (type: HELLO TTL: 1 Orig: 10.1.1.1 SeqNo: 2 Validity: 134 Hop count: 0 Size: 16) "
        "ns3::olsr::MessageHeader (type: TC TTL: 255 Orig: 10.1.1.3 SeqNo: 1 Validity: 199 Hop count: 1 Size: 16)"
    )
    for i in range(20):
        L.append(line("t", 1.0 + i, i % 10, f"10.1.1.{i % 10 + 1}", "10.1.1.255", 0, 698, 698, 20, tail=hello_only))
    for i in range(5):
        L.append(line("t", 21.0 + i, i % 10, f"10.1.1.{i % 10 + 1}", "10.1.1.255", 0, 698, 698, 52, tail=hello_plus_2tc))
    # +1 retry OLSR yang tidak boleh dihitung di paket maupun pesan
    L.append(line("t", 30.5, 2, "10.1.1.3", "10.1.1.255", 0, 698, 698, 20, retry=1, tail=hello_only))

    # DoS dari node 3 (10.1.1.4): 50 paket unik di jendela (IP-ID 1000..1051 dengan 2 gap: 1010 & 1020 dilewati)
    dos_ipids = [1000 + k for k in range(52) if (1000 + k) not in (1010, 1020)]
    for i, ipid in enumerate(dos_ipids):
        t = 6.0 + i * 0.004
        L.append(line("t", t, 3, "10.1.1.4", "255.255.255.255", ipid, 50000, 9, 1024))
        L.append(line("r", t + 0.001, 2, "10.1.1.4", "255.255.255.255", ipid, 50000, 9, 1024))
        L.append(line("r", t + 0.001, 4, "10.1.1.4", "255.255.255.255", ipid, 50000, 9, 1024))
    for i in range(5):                      # di luar jendela (t > 220) -> ditolak
        L.append(line("t", 221.0 + i * 0.01, 3, "10.1.1.4", "255.255.255.255", 2000 + i, 50000, 9, 1024))
    # unicast 1024 B & broadcast 512 B -> OTHER (bukan DoS, bukan legal)
    L.append(line("t", 50.0, 5, "10.1.1.6", "10.1.1.8", 7, 50001, 9, 1024, da_node=7))
    L.append(line("t", 50.1, 5, "10.1.1.6", "10.1.1.255", 8, 50001, 9, 512))
    path.write_text("\n".join(L) + "\n", encoding="utf-8")
    return delays


def build_synthetic_aodv(path: Path):
    """Bangun trace sintetis AODV (port 654) dengan RREQ, RREP, RERR, dan Hello."""
    L = []
    # 1 paket legal sampai
    L.append(line("t", 10.0, 0, "10.1.1.1", "10.1.1.9", 1, 49153, 9, 512, da_node=8))
    L.append(line("r", 10.005, 8, "10.1.1.1", "10.1.1.9", 1, 49153, 9, 512, da_node=8))
    # 2 RREQ
    rreq_tail = (
        "ns3::aodv::TypeHeader (RREQ) ns3::aodv::RreqHeader "
        "(RREQ ID 1 destination: ipv4 10.1.1.9 sequence number 0 source: ipv4 10.1.1.1 sequence number 1 "
        "flags: Gratuitous RREP 1 Destination only 0 Unknown sequence number 1)"
    )
    L.append(line("t", 5.01, 0, "10.1.1.1", "10.1.1.255", 10, 654, 654, 24, tail=rreq_tail))
    L.append(line("t", 5.02, 2, "10.1.1.3", "10.1.1.255", 11, 654, 654, 24, tail=rreq_tail))
    # 1 RREP unicast (dst != source)
    rrep_tail = (
        "ns3::aodv::TypeHeader (RREP) ns3::aodv::RrepHeader "
        "(destination: ipv4 10.1.1.9 sequence number 2 source ipv4 10.1.1.1 lifetime 11200 "
        "acknowledgment required flag 0)"
    )
    L.append(line("t", 5.03, 8, "10.1.1.9", "10.1.1.1", 12, 654, 654, 20, da_node=0, tail=rrep_tail))
    # 3 AODV Hello (RrepHeader dengan destination == source)
    hello_tail = (
        "ns3::aodv::TypeHeader (RREP) ns3::aodv::RrepHeader "
        "(destination: ipv4 10.1.1.1 sequence number 1 source ipv4 10.1.1.1 lifetime 2000 "
        "acknowledgment required flag 0)"
    )
    for k in range(3):
        L.append(line("t", 1.0 + k, 0, "10.1.1.1", "10.1.1.255", 20 + k, 654, 654, 20, tail=hello_tail))
    # 1 RERR
    rerr_tail = (
        "ns3::aodv::TypeHeader (RERR) ns3::aodv::RerrHeader "
        "(Unreachable destination (ipv4 address, seq. number):10.1.1.9, 2No delete flag 0)"
    )
    L.append(line("t", 15.0, 2, "10.1.1.3", "10.1.1.1", 30, 654, 654, 12, da_node=0, tail=rerr_tail))
    path.write_text("\n".join(L) + "\n", encoding="utf-8")


def pct(vals, p):
    s = sorted(vals)
    k = (len(s) - 1) * p / 100
    lo = int(k)
    hi = min(lo + 1, len(s) - 1)
    return s[lo] + (s[hi] - s[lo]) * (k - lo)


def check(name, got, exp, tol=1e-4):
    if isinstance(exp, float):
        ok = got is not None and abs(got - exp) <= tol
    else:
        ok = (got == exp)
    print(f"  [{'OK' if ok else 'FAIL'}] {name}: {got!r} (harap {exp!r})")
    return ok


def main():
    tmpdir = Path(tempfile.mkdtemp())
    tmp = tmpdir / "olsr_dos_n10_d200_v20_seed3.tr"
    delays = build_synthetic_olsr(tmp)
    ok = True

    print("== 1. Uji Unit Sintetis OLSR (paket legal, retry, DoS, HELLO+TC gabungan) ==")
    r = P.process_trace(tmp, P.Config(dos_end=220.0))
    r_inf = P.process_trace(tmp, P.Config())
    ok &= check("DoS_Packets_Detected (default dos_end=inf sesuai Proposal)", r_inf["DoS_Packets_Detected"], 55)
    ok &= check("Protokol", r["Protokol"], "OLSR")
    ok &= check("Kondisi", r["Kondisi"], "DoS")
    ok &= check("Is_Baseline", r["Is_Baseline"], 1)
    ok &= check("Mode_Kecepatan", r["Mode_Kecepatan"], "seragam")
    ok &= check("Kecepatan_Min", r["Kecepatan_Min"], 20)
    ok &= check("Kecepatan_Max", r["Kecepatan_Max"], 20)
    ok &= check("Run", r["Run"], "3")
    ok &= check("Seed", r["Seed"], 3)
    ok &= check("Legal_Sent_App (tanpa XML)", r["Legal_Sent_App"], None)
    ok &= check("Legal_Sent", r["Legal_Sent"], 102)
    ok &= check("Legal_Received", r["Legal_Received"], 81)
    ok &= check("PDR_pct", r["PDR_pct"], 81 / 102 * 100)
    ok &= check("Avg_Delay_ms", r["Avg_Delay_ms"], statistics.mean(delays))
    ok &= check("Median_Delay_ms", r["Median_Delay_ms"], statistics.median(delays))
    ok &= check("P95_Delay_ms", r["P95_Delay_ms"], pct(delays, 95))
    ok &= check("P99_Delay_ms", r["P99_Delay_ms"], pct(delays, 99))
    ok &= check("Max_Delay_ms", r["Max_Delay_ms"], max(delays))
    ok &= check("Throughput_kbps (222s)", r["Throughput_kbps"], 81 * 512 * 8 / (222.0 * 1000.0))
    ok &= check("Active_Duration_s", r["Active_Duration_s"], 210.03 - 5.0)
    ok &= check("Throughput_active_kbps", r["Throughput_active_kbps"], 81 * 512 * 8 / ((210.03 - 5.0) * 1000.0))
    ok &= check("Routing_Packets_Sent", r["Routing_Packets_Sent"], 25)
    ok &= check("HELLO_Msgs (per pesan)", r["HELLO_Msgs"], 25)
    ok &= check("TC_Msgs (per pesan)", r["TC_Msgs"], 10)
    ok &= check("RREQ_Msgs (OLSR -> None)", r["RREQ_Msgs"], None)
    ok &= check("DoS_Packets_Detected", r["DoS_Packets_Detected"], 50)
    ok &= check("DoS_Rx_Events", r["DoS_Rx_Events"], 100)
    ok &= check("DoS_Unique_Packets_Recv", r["DoS_Unique_Packets_Recv"], 50)
    ok &= check("Attacker_Node", r["Attacker_Node"], 3)
    ok &= check("DoS_Id_Gap", r["DoS_Id_Gap"], 2)
    ok &= check("MAC_Retry_Count", r["MAC_Retry_Count"], 100)
    ok &= check("MAC_Retry_Ratio", r["MAC_Retry_Ratio"], 100 / 302)
    # 80 paket via 2 pemancar (0, relay) + 1 paket langsung (0) = (80*2 + 1*1)/81
    ok &= check("Hop_Count_Mean", r["Hop_Count_Mean"], (80 * 2 + 1) / 81)
    # Pergantian DA hop pertama di node 0: mac(3) -> mac(4) -> mac(9) = 2 kali
    ok &= check("Route_Change_Count", r["Route_Change_Count"], 2)
    ok &= check("Num_Legal_Flows", r["Num_Legal_Flows"], 1)
    ok &= check("Legal_Drop_Events", r["Legal_Drop_Events"], "N/A")
    ok &= check("Duplicate_Events", r["Duplicate_Events"], 80)

    # Uji pembacaan Legal_Sent_App dari FlowMonitor XML
    fm_xml = tmpdir / "flowmon.xml"
    fm_xml.write_text(
        '<?xml version="1.0" ?>\n<FlowMonitor>\n'
        '  <FlowStats>\n'
        '    <Flow flowId="1" txPackets="5249" rxPackets="4804" />\n'
        '    <Flow flowId="2" txPackets="1110" rxPackets="1110" />\n'
        '  </FlowStats>\n'
        '  <Ipv4FlowClassifier>\n'
        '    <Flow flowId="1" sourceAddress="10.1.1.1" destinationAddress="10.1.1.9" '
        'protocol="17" sourcePort="49153" destinationPort="9" />\n'
        '    <Flow flowId="2" sourceAddress="10.1.1.1" destinationAddress="10.1.1.255" '
        'protocol="17" sourcePort="698" destinationPort="698" />\n'
        '  </Ipv4FlowClassifier>\n'
        '</FlowMonitor>\n',
        encoding="utf-8",
    )
    r_fm = P.process_trace(tmp, P.Config(flowmon_xml=str(fm_xml)))
    ok &= check("Legal_Sent_App (dengan FlowMonitor XML)", r_fm["Legal_Sent_App"], 5249)

    print("== 2. Uji Unit Sintetis AODV (RREQ, RREP, RERR, Hello) & --strict ==")
    tmp_aodv = tmpdir / "aodv_normal_hetero_seed2.tr"
    build_synthetic_aodv(tmp_aodv)
    ra = P.process_trace(tmp_aodv, P.Config())
    ok &= check("AODV Protokol", ra["Protokol"], "AODV")
    ok &= check("AODV Kelompok_OFAT", ra["Kelompok_OFAT"], "D")
    ok &= check("AODV Mode_Kecepatan", ra["Mode_Kecepatan"], "acak")
    ok &= check("AODV Kecepatan_Min", ra["Kecepatan_Min"], 15)
    ok &= check("AODV Kecepatan_Max", ra["Kecepatan_Max"], 25)
    ok &= check("AODV Is_Baseline", ra["Is_Baseline"], 0)
    ok &= check("AODV RREQ_Msgs", ra["RREQ_Msgs"], 2)
    ok &= check("AODV RREP_Msgs", ra["RREP_Msgs"], 1)
    ok &= check("AODV RERR_Msgs", ra["RERR_Msgs"], 1)
    ok &= check("AODV Hello_Msgs", ra["Hello_Msgs"], 3)
    ok &= check("AODV HELLO_Msgs (OLSR -> None)", ra["HELLO_Msgs"], None)

    tmp_unlabeled = tmpdir / "tanpa_token.tr"
    build_synthetic_aodv(tmp_unlabeled)
    rs = P.process_trace(tmp_unlabeled, P.Config(strict=True))
    ok &= check("--strict Status", rs["Status"], "WARN: metadata tidak terdeteksi")
    ok &= check("--strict Kelompok_OFAT", rs["Kelompok_OFAT"], "Unknown")

    # Uji konvensi penamaan Indonesia: -b-j100, -b-j200, -c-k30, -d-normal
    mb100 = P.extract_metadata(Path("olsr-b-j100-normal.tr"), strict=True)
    mb200 = P.extract_metadata(Path("olsr-b-j200-normal.tr"), strict=True)
    mc30 = P.extract_metadata(Path("olsr-c-k30-normal.tr"), strict=True)
    md_norm = P.extract_metadata(Path("olsr-d-normal.tr"), strict=True)
    ok &= check("olsr-b-j100-normal -> Kelompok B, Jarak=100", (mb100.kelompok, mb100.dist, mb100.warnings), ("B", 100, []))
    ok &= check("olsr-b-j200-normal -> Kelompok B, Jarak=200", (mb200.kelompok, mb200.dist, mb200.warnings), ("B", 200, []))
    ok &= check("olsr-c-k30-normal -> Kelompok C, Kec=30", (mc30.kelompok, mc30.speed, mc30.warnings), ("C", "30", []))
    ok &= check("olsr-d-normal -> Kelompok D, mode=acak", (md_norm.kelompok, md_norm.mode_kecepatan, md_norm.warnings), ("D", "acak", []))

    # Cek format CSV 'sim' (tanpa Legal_Drop_Events) vs 'full' (dengan Legal_Drop_Events)
    csv_sim = tmpdir / "out_sim.csv"
    csv_full = tmpdir / "out_full.csv"
    P.write_csv([r], csv_sim, csv_format="sim")
    P.write_csv([r], csv_full, csv_format="full")
    with csv_sim.open("r", encoding="utf-8") as f:
        hdr_sim = next(csv.reader(f))
    with csv_full.open("r", encoding="utf-8") as f:
        hdr_full = next(csv.reader(f))
    ok &= check("Legal_Drop_Events tidak di format sim", "Legal_Drop_Events" in hdr_sim, False)
    ok &= check("Legal_Drop_Events ada di format full", "Legal_Drop_Events" in hdr_full, True)

    # Uji regresi wajib pada trace asli bila tersedia
    base_tester = Path(__file__).resolve().parent / "tester"
    tr_norm = base_tester / "olsr-mh-normal.tr"
    tr_dos = base_tester / "olsr-mh-dos.tr"
    if tr_norm.is_file() and tr_dos.is_file():
        print("\n== 3. Uji Regresi Wajib: olsr-mh-normal.tr ==")
        rn = P.process_trace(tr_norm, P.Config(duration=222.0))
        ok &= check("Normal Legal_Sent", rn["Legal_Sent"], 5082)
        ok &= check("Normal Legal_Received", rn["Legal_Received"], 4804)
        ok &= check("Normal Avg_Delay_ms", round(rn["Avg_Delay_ms"], 4), 3.7381)
        ok &= check("Normal Median_Delay_ms", round(rn["Median_Delay_ms"], 4), 3.7)
        ok &= check("Normal Routing_Packets_Sent", rn["Routing_Packets_Sent"], 1353)
        ok &= check("Normal Lines_Total", rn["Lines_Total"], 222988)
        ok &= check("Normal MAC_Retry_Count", rn["MAC_Retry_Count"], 1428)
        ok &= check("Normal HELLO_Msgs total", rn["HELLO_Msgs"], 1110)
        ok &= check("Normal TC_Msgs total", rn["TC_Msgs"], 609)
        hello_per_node = rn["_detail"]["olsr_hello_per_node"]
        ok &= check("Normal tiap node 111 HELLO", all(v == 111 for v in hello_per_node.values()) and len(hello_per_node) == 10, True)
        ok &= check("Normal Throughput_kbps (222s)", round(rn["Throughput_kbps"], 3), 88.636)

        print("\n== 4. Uji Regresi Wajib: olsr-mh-dos.tr ==")
        rd = P.process_trace(tr_dos, P.Config(duration=222.0))
        ok &= check("DoS Legal_Sent", rd["Legal_Sent"], 5092)
        ok &= check("DoS Legal_Received", rd["Legal_Received"], 4707)
        ok &= check("DoS Avg_Delay_ms", round(rd["Avg_Delay_ms"], 4), 13.6081)
        ok &= check("DoS Median_Delay_ms", round(rd["Median_Delay_ms"], 4), 4.0)
        ok &= check("DoS Routing_Packets_Sent", rd["Routing_Packets_Sent"], 1345)
        ok &= check("DoS DoS_Packets_Detected", rd["DoS_Packets_Detected"], 26246)
        ok &= check("DoS Lines_Total", rd["Lines_Total"], 346720)
        ok &= check("DoS MAC_Retry_Count", rd["MAC_Retry_Count"], 4459)
        ok &= check("DoS DoS_Rate_Observed_Mbps (~1.0)", round(rd["DoS_Rate_Observed_Mbps"], 2), 1.00)
        ok &= check("DoS Num_Loss_Windows > 0", rd["Num_Loss_Windows"] > 0, True)
        ok &= check("DoS Throughput_kbps (222s)", round(rd["Throughput_kbps"], 3), 86.846)

    print("\nSEMUA LULUS" if ok else "\nADA YANG GAGAL")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
