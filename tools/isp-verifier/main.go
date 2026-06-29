// kahf-isp-verify — verifies KahfGuard NAT + firewall rules from a client machine.
//
// Build:
//
//	GOOS=linux   GOARCH=amd64 go build -o bin/kahf-isp-verify-linux-amd64   .
//	GOOS=darwin  GOARCH=arm64 go build -o bin/kahf-isp-verify-darwin-arm64   .
//	GOOS=darwin  GOARCH=amd64 go build -o bin/kahf-isp-verify-darwin-amd64   .
//	GOOS=windows GOARCH=amd64 go build -o bin/kahf-isp-verify-windows-amd64.exe .
//
// Scope: NAT redirect (port 53) + encrypted DNS REJECT rules (DoT/DoQ/QUIC/DoH)
//        + DNS filtering verification (allowed vs blocked sites).
// VPN and TOR blocking are out of scope — not every ISP enables those.
package main

import (
	"encoding/binary"
	"fmt"
	"math/rand"
	"net"
	"os"
	"strings"
	"time"
)

const (
	kahfFwdRange = "203.190.10.116 – 203.190.10.117"

	dialTimeout      = 5 * time.Second
	udpReadTimeout   = 3 * time.Second
	fastRejectThresh = 1500 * time.Millisecond
)

// dohProviders are the IPs in the DoH_Providers address-list.
// TCP/443 to these should be blocked.
var dohProviders = []struct{ ip, name string }{
	{"1.1.1.1", "Cloudflare"},
	{"1.0.0.1", "Cloudflare"},
	{"8.8.8.8", "Google"},
	{"8.8.4.4", "Google"},
	{"9.9.9.9", "Quad9"},
	{"149.112.112.112", "Quad9"},
	{"208.67.222.222", "OpenDNS"},
	{"208.67.220.220", "OpenDNS"},
	{"94.140.14.14", "AdGuard"},
	{"94.140.15.15", "AdGuard"},
	{"45.90.28.0", "NextDNS"},
	{"45.90.30.0", "NextDNS"},
	{"185.228.168.9", "CleanBrowsing"},
	{"185.228.169.9", "CleanBrowsing"},
	{"76.76.2.0", "ControlD"},
	{"76.76.10.0", "ControlD"},
	{"194.242.2.2", "Mullvad"},
}

// allowedSites are safe domains that must resolve successfully through the forwarder.
var allowedSites = []string{
	"google.com",
	"github.com",
	"wikipedia.org",
	"stackoverflow.com",
	"cloudflare.com",
}

// blockedSites are domains KahfGuard filters. Queries should return NXDOMAIN or a block page IP.
var blockedSites = []string{
	"pornhub.com",
	"xvideos.com",
	"xhamster.com",
	"redtube.com",
	"youporn.com",
}

var passCount, failCount int

func report(label string, ok bool, detail string) {
	status := "PASS"
	if !ok {
		status = "FAIL"
		failCount++
	} else {
		passCount++
	}
	fmt.Printf("  [%s] %-54s %s\n", status, label, detail)
}

// ── DNS wire format helpers ───────────────────────────────────────────────────

func buildDNSQuery(domain string) []byte {
	id := uint16(rand.Intn(0xFFFF))
	b := []byte{
		byte(id >> 8), byte(id), // ID (random)
		0x01, 0x00, // Flags: RD=1
		0x00, 0x01, // QDCOUNT
		0x00, 0x00, // ANCOUNT
		0x00, 0x00, // NSCOUNT
		0x00, 0x00, // ARCOUNT
	}
	// Encode domain name labels
	for _, label := range strings.Split(domain, ".") {
		b = append(b, byte(len(label)))
		b = append(b, []byte(label)...)
	}
	b = append(b, 0x00)       // root
	b = append(b, 0x00, 0x01) // QTYPE A
	b = append(b, 0x00, 0x01) // QCLASS IN
	return b
}

type dnsResult struct {
	rcode int    // 0=NOERROR, 3=NXDOMAIN
	addrs []string
}

// queryDNS sends a UDP DNS query to target (ip:port) and parses the response.
// Under KahfGuard NAT rules, any ip:53 is redirected to the Kahf forwarder.
func queryDNS(target, domain string) (*dnsResult, error) {
	conn, err := net.DialTimeout("udp", target, dialTimeout)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(udpReadTimeout))

	q := buildDNSQuery(domain)
	if _, err = conn.Write(q); err != nil {
		return nil, err
	}

	buf := make([]byte, 512)
	n, err := conn.Read(buf)
	if err != nil {
		return nil, err
	}
	if n < 12 {
		return nil, fmt.Errorf("response too short (%d bytes)", n)
	}

	rcode := int(buf[3] & 0x0F)
	ancount := int(binary.BigEndian.Uint16(buf[6:8]))

	res := &dnsResult{rcode: rcode}

	if rcode == 0 && ancount > 0 {
		// Parse answer section (skip question section first)
		offset := 12
		// Skip question: read qname labels
		for offset < n {
			l := int(buf[offset])
			if l == 0 {
				offset++ // root label
				break
			}
			if l&0xC0 == 0xC0 { // pointer
				offset += 2
				break
			}
			offset += 1 + l
		}
		offset += 4 // skip QTYPE + QCLASS

		// Parse each answer RR
		for i := 0; i < ancount && offset+10 < n; i++ {
			// Skip name (may be pointer)
			if buf[offset]&0xC0 == 0xC0 {
				offset += 2
			} else {
				for offset < n && buf[offset] != 0 {
					offset += 1 + int(buf[offset])
				}
				offset++
			}
			if offset+10 > n {
				break
			}
			rrtype := binary.BigEndian.Uint16(buf[offset : offset+2])
			rdlen := int(binary.BigEndian.Uint16(buf[offset+8 : offset+10]))
			offset += 10
			if rrtype == 1 && rdlen == 4 && offset+4 <= n { // A record
				ip := net.IP(buf[offset : offset+4])
				res.addrs = append(res.addrs, ip.String())
			}
			offset += rdlen
		}
	}
	return res, nil
}

func isDNSResponse(b []byte) bool {
	if len(b) < 4 {
		return false
	}
	return binary.BigEndian.Uint16(b[2:4])&0x8000 != 0
}

// ── Section 1: DNS NAT redirect ───────────────────────────────────────────────

func testDNSRedirectUDP() {
	// 192.0.2.1 = TEST-NET-1 (RFC 5737) — no real DNS server.
	// A reply proves the NAT rule intercepted and forwarded the query.
	const target = "192.0.2.1:53"
	conn, err := net.DialTimeout("udp", target, dialTimeout)
	if err != nil {
		report("NAT redirect UDP/53", false, "dial error: "+err.Error())
		return
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(udpReadTimeout))
	conn.Write(buildDNSQuery("google.com"))

	buf := make([]byte, 512)
	n, err := conn.Read(buf)
	if err != nil {
		report("NAT redirect UDP/53", false, "no reply from 192.0.2.1 — redirect not active")
		return
	}
	if isDNSResponse(buf[:n]) {
		report("NAT redirect UDP/53", true, "forwarder replied (192.0.2.1 intercepted → Kahf)")
	} else {
		report("NAT redirect UDP/53", false, "unexpected non-DNS reply")
	}
}

func testDNSRedirectTCP() {
	const target = "192.0.2.1:53"
	conn, err := net.DialTimeout("tcp", target, dialTimeout)
	if err != nil {
		report("NAT redirect TCP/53", false, "no connection — redirect not active")
		return
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(dialTimeout))

	q := buildDNSQuery("google.com")
	lbuf := make([]byte, 2)
	binary.BigEndian.PutUint16(lbuf, uint16(len(q)))
	conn.Write(append(lbuf, q...))

	rlen := make([]byte, 2)
	if _, err = conn.Read(rlen); err != nil {
		report("NAT redirect TCP/53", false, "no TCP DNS reply: "+err.Error())
		return
	}
	msgLen := int(binary.BigEndian.Uint16(rlen))
	if msgLen < 4 || msgLen > 512 {
		report("NAT redirect TCP/53", false, fmt.Sprintf("bad response length %d", msgLen))
		return
	}
	resp := make([]byte, msgLen)
	conn.Read(resp)
	if isDNSResponse(resp) {
		report("NAT redirect TCP/53", true, "forwarder replied (192.0.2.1 intercepted → Kahf)")
	} else {
		report("NAT redirect TCP/53", false, "non-DNS reply")
	}
}

// ── Section 2: Site filtering ─────────────────────────────────────────────────

// testAllowedSite verifies a safe domain resolves to real IPs through the forwarder.
func testAllowedSite(domain string) {
	// Query via NAT-redirected port 53 (any external IP works as the target).
	res, err := queryDNS("8.8.8.8:53", domain)
	label := fmt.Sprintf("Allowed  %-25s", domain)
	if err != nil {
		report(label, false, "query error: "+err.Error())
		return
	}
	if res.rcode == 3 {
		report(label, false, "NXDOMAIN — site incorrectly blocked by forwarder")
		return
	}
	if res.rcode != 0 || len(res.addrs) == 0 {
		report(label, false, fmt.Sprintf("rcode=%d addrs=%v — no A records", res.rcode, res.addrs))
		return
	}
	report(label, true, fmt.Sprintf("resolved → %s", strings.Join(res.addrs[:min(2, len(res.addrs))], ", ")))
}

// testBlockedSite verifies a blocked domain returns NXDOMAIN or a sinkhole/block-page IP
// (not a real routable address for the actual site).
func testBlockedSite(domain string) {
	res, err := queryDNS("8.8.8.8:53", domain)
	label := fmt.Sprintf("Blocked  %-25s", domain)
	if err != nil {
		// Some forwarders close the connection instead of NXDOMAIN
		if strings.Contains(err.Error(), "timeout") || strings.Contains(err.Error(), "deadline") {
			report(label, false, "timeout — forwarder not responding for this domain")
		} else {
			report(label, true, "connection error (blocked at transport): "+err.Error())
		}
		return
	}
	if res.rcode == 3 {
		report(label, true, "NXDOMAIN — correctly blocked")
		return
	}
	if res.rcode == 0 && len(res.addrs) > 0 {
		ip := net.ParseIP(res.addrs[0])
		if isBlockPageIP(ip) {
			report(label, true, fmt.Sprintf("block page IP → %s", res.addrs[0]))
			return
		}
		report(label, false, fmt.Sprintf("resolved to public IP %s — site NOT blocked", res.addrs[0]))
		return
	}
	report(label, false, fmt.Sprintf("unexpected rcode=%d — unclear result", res.rcode))
}

// kahfBlockRanges are Kahf's own IP ranges used for block pages (from Bypass_Safe address-list).
var kahfBlockRanges = []string{
	"203.190.10.112/28", // KAHF-BDIX
	"40.120.32.128/26",  // KAHF-Azure
}

func isBlockPageIP(ip net.IP) bool {
	if ip == nil {
		return false
	}
	// Private / loopback / link-local
	if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() {
		return true
	}
	// Kahf block-page ranges
	for _, cidr := range kahfBlockRanges {
		_, network, _ := net.ParseCIDR(cidr)
		if network != nil && network.Contains(ip) {
			return true
		}
	}
	return false
}

// ── Section 3: TCP/UDP port blocking ─────────────────────────────────────────

func testTCPBlocked(label, ip, port string) {
	addr := ip + ":" + port
	start := time.Now()
	conn, err := net.DialTimeout("tcp", addr, dialTimeout)
	elapsed := time.Since(start)
	if err != nil {
		if elapsed < fastRejectThresh {
			report(label, true, fmt.Sprintf("rejected in %v", elapsed.Round(time.Millisecond)))
		} else {
			report(label, false, fmt.Sprintf("timed out after %v — DROP not REJECT, or rule missing", elapsed.Round(time.Millisecond)))
		}
	} else {
		conn.Close()
		report(label, false, "connected — rule not in effect")
	}
}

func testUDPBlocked(label, ip, port string) {
	addr := ip + ":" + port
	udpAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		report(label, false, "resolve error: "+err.Error())
		return
	}
	conn, err := net.DialUDP("udp", nil, udpAddr)
	if err != nil {
		report(label, true, "blocked at dial: "+err.Error())
		return
	}
	enableICMPErrors(conn) // sets IP_RECVERR on Linux
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(udpReadTimeout))
	conn.Write([]byte{0xc0, 0x00, 0x00, 0x01})

	buf := make([]byte, 128)
	_, err = conn.Read(buf)
	if err == nil {
		report(label, false, "got UDP response — rule not in effect")
		return
	}
	if strings.Contains(err.Error(), "timeout") || strings.Contains(err.Error(), "deadline") {
		report(label, false, "timeout — no ICMP received (DROP instead of REJECT, or local firewall ate ICMP)")
	} else {
		report(label, true, "ICMP unreachable: "+err.Error())
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// ── Main ─────────────────────────────────────────────────────────────────────

func main() {
	rand.Seed(time.Now().UnixNano())

	fmt.Println("═══════════════════════════════════════════════════════════════════")
	fmt.Println("  KahfGuard ISP Filtering Verifier — NAT + Firewall + DNS")
	fmt.Println("  Forwarder: " + kahfFwdRange)
	fmt.Println("═══════════════════════════════════════════════════════════════════")

	// ── 1. DNS NAT redirect ─────────────────────────────────────────────────
	fmt.Println("\n[1] DNS NAT redirect (port 53 → Kahf forwarder):")
	testDNSRedirectUDP()
	testDNSRedirectTCP()

	// ── 2. DNS site filtering ────────────────────────────────────────────────
	fmt.Println("\n[2] DNS filtering — allowed sites (must resolve):")
	for _, d := range allowedSites {
		testAllowedSite(d)
	}

	fmt.Println("\n[3] DNS filtering — blocked sites (must return NXDOMAIN or block page):")
	for _, d := range blockedSites {
		testBlockedSite(d)
	}

	// ── 3. DoT TCP/853 blocked ──────────────────────────────────────────────
	fmt.Println("\n[4] DoT blocked (TCP/853, non-Kahf IPs):")
	testTCPBlocked("DoT 1.1.1.1  Cloudflare", "1.1.1.1", "853")
	testTCPBlocked("DoT 8.8.8.8  Google", "8.8.8.8", "853")
	testTCPBlocked("DoT 9.9.9.9  Quad9", "9.9.9.9", "853")

	// ── 4. DoQ UDP/853 blocked ──────────────────────────────────────────────
	fmt.Println("\n[5] DoQ blocked (UDP/853, non-Kahf IPs):")
	testUDPBlocked("DoQ 1.1.1.1  Cloudflare", "1.1.1.1", "853")
	testUDPBlocked("DoQ 8.8.8.8  Google", "8.8.8.8", "853")
	testUDPBlocked("DoQ 9.9.9.9  Quad9", "9.9.9.9", "853")

	// ── 5. QUIC/HTTP3 UDP/443 blocked ───────────────────────────────────────
	fmt.Println("\n[6] QUIC/HTTP3 blocked (UDP/443, non-Kahf IPs):")
	testUDPBlocked("QUIC 1.1.1.1  Cloudflare", "1.1.1.1", "443")
	testUDPBlocked("QUIC 8.8.8.8  Google", "8.8.8.8", "443")
	testUDPBlocked("QUIC 9.9.9.9  Quad9", "9.9.9.9", "443")

	// ── 6. DoH TCP/443 blocked for all DoH provider IPs ─────────────────────
	fmt.Println("\n[7] DoH blocked (TCP/443, DoH provider IPs):")
	for _, p := range dohProviders {
		testTCPBlocked(fmt.Sprintf("DoH %-17s %s", p.ip, p.name), p.ip, "443")
	}

	// ── Summary ─────────────────────────────────────────────────────────────
	fmt.Println()
	fmt.Println("═══════════════════════════════════════════════════════════════════")
	fmt.Printf("  PASS: %d   FAIL: %d   TOTAL: %d\n", passCount, failCount, passCount+failCount)
	fmt.Println("═══════════════════════════════════════════════════════════════════")
	if failCount == 0 {
		fmt.Println("  All rules verified. Filtering is active on this ISP.")
	} else {
		fmt.Printf("  %d check(s) failed. Review FAIL lines above.\n", failCount)
		os.Exit(1)
	}
}
