package main

import (
	"flag"
	"log"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"GoTrafficGen/internal"
	"GoTrafficGen/internal/tls"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

type TrafficConfig struct {
	RecordType int
	RateKbps   float64
	Duration   time.Duration
	Count      int
}

func simulate(cfg TrafficConfig, dstIP string, dstPort int, iface string, wg *sync.WaitGroup) {
	defer wg.Done()

	// 1. Open pcap handle
	handle, err := pcap.OpenLive(iface, 65535, false, pcap.BlockForever)
	if err != nil {
		log.Printf("[Type %d] open iface: %v", cfg.RecordType, err)
		return
	}
	defer handle.Close()

	// 2. Build layers: Ethernet, IP, TCP
	ifi, err := net.InterfaceByName(iface)
	if err != nil {
		log.Printf("[Type %d] iface lookup: %v", cfg.RecordType, err)
		return
	}
	srcMAC := ifi.HardwareAddr
	if len(srcMAC) == 0 {
		srcMAC, _ = net.ParseMAC("00:11:22:33:44:55")
	}
	dstMAC, _ := net.ParseMAC("de:ad:be:ef:de:ad")
	srcIP, err := internal.GetInterfaceIPv4(iface)
	if err != nil {
		log.Printf("[Type %d] src IP: %v", cfg.RecordType, err)
		return
	}

	eth := &layers.Ethernet{SrcMAC: srcMAC, DstMAC: dstMAC, EthernetType: layers.EthernetTypeIPv4}
	ip := &layers.IPv4{SrcIP: srcIP, DstIP: net.ParseIP(dstIP), Version: 4, TTL: 64, Protocol: layers.IPProtocolTCP}
	tcp := &layers.TCP{SrcPort: layers.TCPPort(12345), DstPort: layers.TCPPort(dstPort), Seq: 1105024978, Window: 14600}
	if err := tcp.SetNetworkLayerForChecksum(ip); err != nil {
		log.Printf("[Type %d] TCP checksum: %v", cfg.RecordType, err)
		return
	}

	// 3. Build TLS layer via our tls package
	tlsLayer := tls.Build(cfg.RecordType)

	// 4. Serialize once to compute packet size & pacing
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	if err := gopacket.SerializeLayers(buf, opts, eth, ip, tcp, tlsLayer); err != nil {
		log.Printf("[Type %d] serialize: %v", cfg.RecordType, err)
		return
	}
	raw := buf.Bytes()
	psize := len(raw)
	pps := (cfg.RateKbps * 1000) / (float64(psize) * 8.0)

	// 5. Determine totalPackets & totalDuration
	var totalPkts int
	var totalDur time.Duration
	switch {
	case cfg.Count > 0 && cfg.Duration == 0:
		totalPkts = cfg.Count
		totalDur = time.Duration(float64(cfg.Count)/pps) * time.Second
	case cfg.Duration > 0 && cfg.Count == 0:
		totalDur = cfg.Duration
		totalPkts = int(pps * cfg.Duration.Seconds())
	default:
		totalPkts = cfg.Count
		totalDur = cfg.Duration
	}

	log.Printf("[Type %d] start rate=%.2f kbps pps=%.2f pkts=%d dur=%v size=%d",
		cfg.RecordType, cfg.RateKbps, pps, totalPkts, totalDur, psize)

	// 6. Send loop
	ticker := time.NewTicker(time.Second / time.Duration(pps))
	defer ticker.Stop()
	sent := 0
	start := time.Now()

	for range ticker.C {
		handle.WritePacketData(raw)
		sent++
		if sent >= totalPkts || time.Since(start) > totalDur {
			break
		}
	}

	// 7. Summary
	elapsed := time.Since(start).Seconds()
	actual := (float64(sent*psize) * 8.0) / (elapsed * 1000.0)
	log.Printf("[Type %d] done sent=%d elapsed=%.2fsec rate=%.2fkbps",
		cfg.RecordType, sent, elapsed, actual)
}

func main() {
	// CLI flags
	dst := flag.String("dest", "127.0.0.1", "")
	port := flag.Int("port", 443, "")
	rate := flag.Float64("rate", 0, "")
	dur := flag.Int("duration", 0, "")
	cnt := flag.Int("count", 0, "")
	types := flag.String("types", "", "")
	iface := flag.String("iface", "lo", "")
	flag.Parse()

	if *rate <= 0 || *types == "" || (*dur == 0 && *cnt == 0) {
		log.Fatal("usage: -rate X -types \"20,22\" [-duration N | -count M]")
	}

	// Parse record types
	parts := strings.Split(*types, ",")
	var wg sync.WaitGroup
	for _, p := range parts {
		t, err := strconv.Atoi(strings.TrimSpace(p))
		if err != nil {
			log.Fatalf("invalid type %q", p)
		}
		cfg := TrafficConfig{
			RecordType: t,
			RateKbps:   *rate,
			Duration:   time.Duration(*dur) * time.Second,
			Count:      *cnt,
		}
		wg.Add(1)
		go simulate(cfg, *dst, *port, *iface, &wg)
	}
	wg.Wait()
	log.Println("All simulations done.")
}
