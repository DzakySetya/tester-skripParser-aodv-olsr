/*
 * aodv-vanet-mh-dos.cc
 * ====================
 * Simulasi VANET MULTI-HOP (kondisi DoS): WiFi 802.11p ad-hoc + AODV.
 * Mobilitas diimpor dari trace SUMO (--traceFile) -- SAMA PERSIS dengan versi
 * Normal dan OLSR agar perbandingan komparatif adil.
 *
 * CHANGELOG (Tugas D1, D2, D3, D4, D5):
 *   - [D1] Dibuat dari olsr-vanet-mh-dos.cc dengan diff minimal:
 *          OlsrHelper -> AodvHelper (#include "ns3/aodv-module.h").
 *          Catatan verifikasi NS-3: class ns3::aodv::RoutingProtocol pada
 *          src/aodv/model/aodv-routing-protocol.cc TIDAK memiliki trace source
 *          "Tx" (tidak ada AddTraceSource sama sekali di GetTypeId()). Oleh
 *          karena itu callback Config::ConnectWithoutContext(".../RoutingProtocol/Tx")
 *          dihapus sesuai instruksi D1; perhitungan RO, NRL, dan rincian pesan
 *          (RREQ, RREP, RERR, Hello) dilakukan secara presisi oleh
 *          vanet_trace_parser_ns3.py dari file trace PHY (.tr) pada UDP port 654.
 *   - [D2] Menambahkan argumen CLI --totalNodes dan menghitung dinamis:
 *          senderIdx = 0, receiverIdx = totalNodes - 2, attackerIdx = totalNodes - 1,
 *          legitCount = totalNodes - 1 (menghilangkan hardcode 10/8/9).
 *   - [D3] Menambahkan argumen CLI --seed (RngSeedManager::SetRun), --rowDistance,
 *          --speedTag, --outDir, dan --outPrefix (mis. aodv_dos_n20_d200_v30_run3.tr).
 *   - [D4] Memastikan attackDataRate default "2Mbps" (interval 4,096 ms untuk
 *          payload 1.024 B -> ~52.491 paket selama 5..220 s).
 *   - [D5] Menambahkan trace source aplikasi OnOff ("Tx" -> g_legalSentApp) untuk
 *          Legal_Sent_App dan memfilter FlowMonitor hanya pada flow data legal.
 */

#include "ns3/core-module.h"
#include "ns3/network-module.h"
#include "ns3/mobility-module.h"
#include "ns3/internet-module.h"
#include "ns3/aodv-module.h"
#include "ns3/wifi-module.h"
#include "ns3/applications-module.h"
#include "ns3/flow-monitor-module.h"
#include "ns3/netanim-module.h"
#include <fstream>
#include <sstream>

using namespace ns3;

NS_LOG_COMPONENT_DEFINE("AodvVanetMultihopDos");

static uint32_t g_attackPacketsSent = 0;
static uint32_t g_legalSentApp = 0;
static uint32_t g_legalRecvApp = 0;

void
OnOffTxTrace(Ptr<const Packet> /*packet*/)
{
    g_legalSentApp++;
}

void
SinkRxTrace(Ptr<const Packet> /*packet*/, const Address& /*from*/)
{
    g_legalRecvApp++;
}

void
SendAttackPacket(Ptr<Socket> socket, uint32_t pktSize, double intervalSec, double stopTime)
{
    if (Simulator::Now().GetSeconds() >= stopTime)
    {
        return;
    }
    Ptr<Packet> packet = Create<Packet>(pktSize);
    int sent = socket->Send(packet);
    if (sent >= 0)
    {
        g_attackPacketsSent++;
    }
    Simulator::Schedule(Seconds(intervalSec),
                         &SendAttackPacket,
                         socket,
                         pktSize,
                         intervalSec,
                         stopTime);
}

int
main(int argc, char* argv[])
{
    // ===================== PARAMETER SKENARIO =====================
    uint32_t totalNodes = 10;             // default baseline: 5 barisan x 2 kendaraan
    uint32_t rowDistance = 200;           // jarak antar-baris (m) untuk penamaan file OFAT
    std::string speedTag = "20";          // label kecepatan (km/jam), mis. "20", "30", "15_25"
    uint32_t seed = 1;                    // nomor seed / RngRun
    double simTime = 222.0;
    double maxRange = 250.0;              // RangePropagationLossModel MaxRange (m)
    std::string traceFile = "ns2mobility-multihop.tcl";
    std::string phyMode = "OfdmRate6MbpsBW10MHz";
    uint16_t port = 9;
    uint16_t attackPort = 4000;
    uint32_t packetSize = 512;
    std::string dataRate = "100kbps";
    bool enableNetAnim = false;
    bool enablePcap = false;
    std::string outDir = ".";
    std::string outPrefix = "";

    uint32_t attackPacketSize = 1024;
    std::string attackDataRate = "2Mbps"; // [D4] 2 Mbps -> interval 4,096 ms (1024 B * 8 / 2e6)
    double attackStart = 5.0;             // mulai t=5 s sampai simTime-2.0 (220 s)

    CommandLine cmd(__FILE__);
    cmd.AddValue("totalNodes", "Jumlah total node (harus genap, sesuai traceFile)", totalNodes);
    cmd.AddValue("rowDistance", "Jarak antar-baris (m) untuk metadata nama file", rowDistance);
    cmd.AddValue("speedTag", "Label kecepatan (mis. 20, 30, 40, 15_25)", speedTag);
    cmd.AddValue("seed", "Nomor seed / RngRun (1..N)", seed);
    cmd.AddValue("simTime", "Durasi simulasi (detik)", simTime);
    cmd.AddValue("maxRange", "Jangkauan maksimum RangePropagationLossModel (m)", maxRange);
    cmd.AddValue("traceFile", "Path file ns-2 mobility trace dari SUMO", traceFile);
    cmd.AddValue("attackDataRate", "Data rate flooding penyerang (default 2Mbps)", attackDataRate);
    cmd.AddValue("attackStart", "Waktu mulai serangan (detik)", attackStart);
    cmd.AddValue("enableNetAnim", "Aktifkan output XML NetAnim", enableNetAnim);
    cmd.AddValue("enablePcap", "Aktifkan output PCAP per perangkat", enablePcap);
    cmd.AddValue("outDir", "Direktori keluaran untuk seluruh file hasil", outDir);
    cmd.AddValue("outPrefix", "Override prefix nama file keluaran (opsional)", outPrefix);
    cmd.Parse(argc, argv);

    double attackStop = simTime - 2.0;

    // [D2] Hitung indeks node secara dinamis dari totalNodes
    uint32_t senderIdx = 0;
    uint32_t receiverIdx = totalNodes - 2;
    uint32_t attackerIdx = totalNodes - 1;
    uint32_t legitCount = totalNodes - 1;

    RngSeedManager::SetSeed(1);
    RngSeedManager::SetRun(seed);

    if (outPrefix.empty())
    {
        std::ostringstream oss;
        oss << "aodv_dos_n" << totalNodes
            << "_d" << rowDistance
            << "_v" << speedTag
            << "_run" << seed;
        outPrefix = oss.str();
    }
    std::string basePath = (outDir.empty() || outDir == ".") ? outPrefix : (outDir + "/" + outPrefix);

    NS_LOG_UNCOND("Skenario          : Multi-hop DoS (AODV)");
    NS_LOG_UNCOND("Total node        : " << totalNodes);
    NS_LOG_UNCOND("Node legit        : " << legitCount << " (index 0.." << receiverIdx << ")");
    NS_LOG_UNCOND("Node penyerang    : 1 (index " << attackerIdx << ")");
    NS_LOG_UNCOND("Traffic legit     : node" << senderIdx << " -> node" << receiverIdx);
    NS_LOG_UNCOND("Attack rate       : " << attackDataRate << " mulai t=" << attackStart
                                         << "s s/d " << attackStop << "s");
    NS_LOG_UNCOND("Parameter OFAT    : n=" << totalNodes << ", d=" << rowDistance
                                           << "m, v=" << speedTag << "km/jam, seed=" << seed);
    NS_LOG_UNCOND("Durasi simulasi   : " << simTime << " detik");
    NS_LOG_UNCOND("Trace file SUMO   : " << traceFile);
    NS_LOG_UNCOND("Output prefix     : " << basePath);

    // ===================== NODE & MOBILITAS =====================
    NodeContainer vehicles;
    vehicles.Create(totalNodes);

    Ns2MobilityHelper ns2 = Ns2MobilityHelper(traceFile);
    ns2.Install();

    // ===================== WIFI 802.11p AD-HOC =====================
    YansWifiChannelHelper wifiChannel;
    wifiChannel.SetPropagationDelay("ns3::ConstantSpeedPropagationDelayModel");
    wifiChannel.AddPropagationLoss("ns3::RangePropagationLossModel",
                                    "MaxRange", DoubleValue(maxRange));

    YansWifiPhyHelper wifiPhy;
    wifiPhy.SetChannel(wifiChannel.Create());

    WifiHelper wifi;
    wifi.SetStandard(WIFI_STANDARD_80211p);
    wifi.SetRemoteStationManager(
        "ns3::ConstantRateWifiManager",
        "DataMode", StringValue(phyMode),
        "ControlMode", StringValue(phyMode));

    WifiMacHelper wifiMac;
    wifiMac.SetType("ns3::AdhocWifiMac");

    NetDeviceContainer devices = wifi.Install(wifiPhy, wifiMac, vehicles);

    // ===================== TRACE FILE (.tr dan .pcap) =====================
    AsciiTraceHelper ascii;
    wifiPhy.EnableAsciiAll(ascii.CreateFileStream(basePath + ".tr"));
    if (enablePcap)
    {
        wifiPhy.EnablePcap(basePath, devices);
    }

    // ===================== ROUTING PROTOCOL: AODV =====================
    AodvHelper aodv;
    Ipv4StaticRoutingHelper staticRouting;
    Ipv4ListRoutingHelper routingList;
    routingList.Add(staticRouting, 0);
    routingList.Add(aodv, 10);

    InternetStackHelper internet;
    internet.SetRoutingHelper(routingList);
    internet.Install(vehicles);

    // Catatan D1: ns3::aodv::RoutingProtocol tidak memiliki trace source "Tx".
    // Perhitungan RO & NRL dilakukan dari file trace .tr (UDP port 654) oleh
    // vanet_trace_parser_ns3.py.

    // ===================== PENGALAMATAN IP =====================
    Ipv4AddressHelper address;
    address.SetBase("10.1.1.0", "255.255.255.0");
    Ipv4InterfaceContainer interfaces = address.Assign(devices);

    // ===================== VERIFIKASI MULTI-HOP =====================
    AsciiTraceHelper routingAscii;
    Ptr<OutputStreamWrapper> routingStream =
        routingAscii.CreateFileStream(basePath + "-routingtable.txt");
    aodv.PrintRoutingTableAllAt(Seconds(50.0), routingStream);
    aodv.PrintRoutingTableAllAt(Seconds(150.0), routingStream);

    // ===================== TRAFFIC LEGIT (V2V) =====================
    PacketSinkHelper sink("ns3::UdpSocketFactory",
                           InetSocketAddress(Ipv4Address::GetAny(), port));
    ApplicationContainer sinkApp = sink.Install(vehicles.Get(receiverIdx));
    sinkApp.Start(Seconds(0.0));
    sinkApp.Stop(Seconds(simTime));
    sinkApp.Get(0)->TraceConnectWithoutContext("Rx", MakeCallback(&SinkRxTrace));

    OnOffHelper onoff("ns3::UdpSocketFactory",
                       InetSocketAddress(interfaces.GetAddress(receiverIdx), port));
    onoff.SetAttribute("PacketSize", UintegerValue(packetSize));
    onoff.SetAttribute("DataRate", StringValue(dataRate));
    onoff.SetAttribute("OnTime", StringValue("ns3::ConstantRandomVariable[Constant=1]"));
    onoff.SetAttribute("OffTime", StringValue("ns3::ConstantRandomVariable[Constant=0]"));

    ApplicationContainer sourceApp = onoff.Install(vehicles.Get(senderIdx));
    sourceApp.Start(Seconds(5.0));
    sourceApp.Stop(Seconds(simTime - 2.0));
    // [D5] Trace jumlah paket yang dibangkitkan di layer Aplikasi (Legal_Sent_App)
    sourceApp.Get(0)->TraceConnectWithoutContext("Tx", MakeCallback(&OnOffTxTrace));

    // ===================== TRAFFIC SERANGAN (flooding broadcast) =====================
    Ipv4Address broadcastAddr("10.1.1.255");
    double attackIntervalSec = (attackPacketSize * 8.0) / DataRate(attackDataRate).GetBitRate();

    Ptr<Socket> attackSocket =
        Socket::CreateSocket(vehicles.Get(attackerIdx), UdpSocketFactory::GetTypeId());
    attackSocket->SetAllowBroadcast(true);
    attackSocket->Connect(InetSocketAddress(broadcastAddr, attackPort));

    Simulator::Schedule(Seconds(attackStart),
                         &SendAttackPacket,
                         attackSocket,
                         attackPacketSize,
                         attackIntervalSec,
                         attackStop);

    NS_LOG_UNCOND("Node " << attackerIdx << " berperan sebagai penyerang: " << attackDataRate
                           << " (interval=" << (attackIntervalSec * 1000.0) << " ms, ~"
                           << (1.0 / attackIntervalSec) << " pkt/s), mulai t=" << attackStart << "s");

    // ===================== FLOW MONITOR =====================
    FlowMonitorHelper flowmonHelper;
    Ptr<FlowMonitor> monitor = flowmonHelper.InstallAll();

    AnimationInterface* anim = nullptr;
    if (enableNetAnim)
    {
        anim = new AnimationInterface(basePath + "-netanim.xml");
        anim->SetMobilityPollInterval(Seconds(0.5));
    }

    // ===================== JALANKAN SIMULASI =====================
    Simulator::Stop(Seconds(simTime));
    Simulator::Run();

    // ===================== CETAK RINGKASAN HASIL =====================
    monitor->CheckForLostPackets();
    Ptr<Ipv4FlowClassifier> classifier =
        DynamicCast<Ipv4FlowClassifier>(flowmonHelper.GetClassifier());
    FlowMonitor::FlowStatsContainer stats = monitor->GetFlowStats();

    Ipv4Address expectedSrc = interfaces.GetAddress(senderIdx);
    Ipv4Address expectedDst = interfaces.GetAddress(receiverIdx);

    double dataTxPackets = 0, dataRxPackets = 0, dataLostPackets = 0;
    double totalThroughputBps = 0, totalDelay = 0;
    uint32_t flowCountWithRx = 0;

    for (auto& flow : stats)
    {
        Ipv4FlowClassifier::FiveTuple t = classifier->FindFlow(flow.first);
        // [D5] Filter ketat hanya flow data legal (sender -> receiver, UDP port 9)
        if (t.sourceAddress != expectedSrc || t.destinationAddress != expectedDst ||
            t.destinationPort != port)
        {
            continue;
        }
        dataTxPackets += flow.second.txPackets;
        dataRxPackets += flow.second.rxPackets;
        dataLostPackets += flow.second.lostPackets;

        if (flow.second.rxPackets > 0)
        {
            double duration = flow.second.timeLastRxPacket.GetSeconds() -
                               flow.second.timeFirstTxPacket.GetSeconds();
            if (duration > 0)
            {
                totalThroughputBps += (flow.second.rxBytes * 8.0) / duration;
            }
            totalDelay += flow.second.delaySum.GetSeconds() / flow.second.rxPackets;
            flowCountWithRx++;
        }

        NS_LOG_UNCOND("Flow " << flow.first << " (" << t.sourceAddress << ":" << t.sourcePort
                               << " -> " << t.destinationAddress << ":" << t.destinationPort
                               << ") [DATA LEGIT]"
                               << "  AppTx=" << g_legalSentApp
                               << " IpTx=" << flow.second.txPackets
                               << " Rx=" << flow.second.rxPackets
                               << " Lost=" << flow.second.lostPackets);
    }

    double pdr = (dataTxPackets > 0) ? (dataRxPackets / dataTxPackets) * 100.0 : 0.0;
    double plr = (dataTxPackets > 0) ? (dataLostPackets / dataTxPackets) * 100.0 : 0.0;
    double avgDelayMs = (flowCountWithRx > 0) ? (totalDelay / flowCountWithRx) * 1000.0 : 0.0;

    // Catatan D1: RO & NRL untuk AODV diekstrak dari file .tr (UDP port 654) oleh vanet_trace_parser_ns3.py
    double routingOverhead = 0.0;
    double nrl = 0.0;

    NS_LOG_UNCOND("\n===================== RINGKASAN AODV (Multi-hop DoS) =====================");
    NS_LOG_UNCOND("Legal_Sent_App (OnOff Tx) : " << g_legalSentApp);
    NS_LOG_UNCOND("Legal_Recv_App (Sink Rx)  : " << g_legalRecvApp);
    NS_LOG_UNCOND("Data Tx Packets (FlowMon) : " << dataTxPackets);
    NS_LOG_UNCOND("Data Rx Packets (FlowMon) : " << dataRxPackets);
    NS_LOG_UNCOND("Data Lost Packets         : " << dataLostPackets);
    NS_LOG_UNCOND("PDR (FlowMon)             : " << pdr << " %");
    NS_LOG_UNCOND("Packet Loss Ratio         : " << plr << " %");
    NS_LOG_UNCOND("Avg End-to-End Delay      : " << avgDelayMs << " ms");
    NS_LOG_UNCOND("Total Throughput          : " << totalThroughputBps / 1000.0 << " Kbps");
    NS_LOG_UNCOND("Routing Overhead & NRL    : dihitung via vanet_trace_parser_ns3.py (port 654)");
    NS_LOG_UNCOND("Paket flood terkirim      : " << g_attackPacketsSent);

    monitor->SerializeToXmlFile(basePath + "-flowmon-results.xml", true, true);

    std::ofstream csv(basePath + "-summary.csv");
    csv << "protocol,scenario,totalNodes,legitCount,numAttackers,simTime,attackDataRate,"
        << "dataTxPackets,dataRxPackets,dataLostPackets,"
        << "PDR_percent,PLR_percent,avgDelay_ms,throughput_kbps,"
        << "routingOverhead_packets,NRL,attackPacketsSent,legalSentApp,seed\n";
    csv << "AODV,Multi-hop DoS," << totalNodes << "," << legitCount << ",1," << simTime
        << "," << attackDataRate << "," << dataTxPackets << "," << dataRxPackets << ","
        << dataLostPackets << "," << pdr << "," << plr << "," << avgDelayMs << ","
        << (totalThroughputBps / 1000.0) << "," << routingOverhead << "," << nrl << ","
        << g_attackPacketsSent << "," << g_legalSentApp << "," << seed << "\n";
    csv.close();

    if (anim)
    {
        delete anim;
    }

    Simulator::Destroy();
    return 0;
}
