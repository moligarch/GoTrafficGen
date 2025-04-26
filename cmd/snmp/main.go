package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"sync"
	"time"

	"GoTrafficGen/internal/snmp"
)

// simulateTraffic sends packets at the desired rate, duration or count, and logs actual throughput
func simulateTraffic(name string, packet []byte, rateKbps float64, duration time.Duration, count int, conn *net.UDPConn, wg *sync.WaitGroup) {
	defer wg.Done()
	pktSize := len(packet)
	// Calculate packets per second
	pps := (rateKbps * 1000.0) / (8.0 * float64(pktSize))
	if pps <= 0 {
		log.Printf("[%s] invalid rate => pps=%.2f, skipping", name, pps)
		return
	}
	// Determine total packets & duration
	var totalPackets int
	var totalDuration time.Duration
	if duration > 0 && count == 0 {
		totalDuration = duration
		totalPackets = int(pps * duration.Seconds())
	} else if count > 0 && duration == 0 {
		totalPackets = count
		sec := float64(count) / pps
		totalDuration = time.Duration(sec * float64(time.Second))
	} else {
		totalDuration = duration
		totalPackets = count
	}
	log.Printf("[%s] start rate=%.2fkbps pps=%.2f duration=%v packets=%d size=%dB", name, rateKbps, pps, totalDuration, totalPackets, pktSize)
	interval := time.Duration(float64(time.Second) / pps)
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	sent := 0
	start := time.Now()
	for range ticker.C {
		if sent >= totalPackets || time.Since(start) > totalDuration {
			break
		}
		conn.Write(packet)
		sent++
	}
	elapsed := time.Since(start)
	actualKbps := (float64(sent*pktSize) * 8.0) / (elapsed.Seconds() * 1000.0)
	log.Printf("[%s] done sent=%d elapsed=%v actual=%.2fkbps", name, sent, elapsed, actualKbps)
}

func main() {
	// CLI flags
	dest := flag.String("dest", "127.0.0.1", "Destination IP")
	port := flag.Int("port", 161, "Destination port")
	rate := flag.Float64("rate", 10, "Rate in kbps")
	dur := flag.Duration("duration", 0, "Duration (e.g., 10s)")
	cnt := flag.Int("count", 0, "Packet count")
	version := flag.String("version", "2c", "SNMP version: v1, 2c, v3, unknown")
	community := flag.String("community", "public", "SNMP community string")
	v3user := flag.String("v3user", "snmpuser", "SNMP v3 username")
	v3sec := flag.String("v3secLevel", "noAuthNoPriv", "SNMP v3 security level")
	v3authProto := flag.String("v3authproto", "", "SNMP v3 auth proto MD5/SHA")
	v3authPass := flag.String("v3authpass", "", "SNMP v3 auth pass")
	v3privProto := flag.String("v3privproto", "", "SNMP v3 priv proto DES/AES")
	v3privPass := flag.String("v3privpass", "", "SNMP v3 priv pass")
	// Requests
	get := flag.Bool("get", false, "GET")
	getNext := flag.Bool("getnext", false, "GETNEXT")
	setReq := flag.Bool("set", false, "SET")
	trap := flag.Bool("trap", false, "TRAP")
	getBulk := flag.Bool("getbulk", false, "GETBULK")
	inform := flag.Bool("inform", false, "INFORM")
	report := flag.Bool("report", false, "REPORT")
	flag.Parse()
	// Validate
	if !(*get || *getNext || *setReq || *trap || *getBulk || *inform || *report) {
		log.Fatal("Specify at least one request type")
	}
	if *rate <= 0 {
		log.Fatal("Rate must be > 0")
	}
	if *dur == 0 && *cnt == 0 {
		log.Fatal("Specify duration or count")
	}
	// UDP conn
	raddr := fmt.Sprintf("%s:%d", *dest, *port)
	addr, _ := net.ResolveUDPAddr("udp", raddr)
	conn, _ := net.DialUDP("udp", nil, addr)
	defer conn.Close()
	// Dispatch
	types := []struct {
		sel  *bool
		name string
	}{
		{get, "get"},
		{getNext, "getnext"},
		{setReq, "set"},
		{trap, "trap"},
		{getBulk, "getbulk"},
		{inform, "inform"},
		{report, "report"},
	}
	var wg sync.WaitGroup
	for _, t := range types {
		if *t.sel {
			pkt, err := snmp.GenerateSNMPPacket(
				t.name, *version, *community,
				*v3user, *v3sec, *v3authProto, *v3authPass, *v3privProto, *v3privPass,
			)
			if err != nil {
				log.Printf("%s error: %v", t.name, err)
				continue
			}
			wg.Add(1)
			go simulateTraffic(t.name, pkt, *rate, *dur, *cnt, conn, &wg)
		}
	}
	wg.Wait()
	log.Println("All traffic generators finished")
}
