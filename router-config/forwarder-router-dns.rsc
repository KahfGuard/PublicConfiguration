# =====================================================================
#  Distribution Router — DNS Filtering Enforcement
# =====================================================================
#
#  BYPASS VECTORS AND MITIGATIONS:
#  ──────────────────────────────────────────────────────────────────
#  Vector              Port        Protocol    Mitigation
#  ──────────────────────────────────────────────────────────────────
#  Plain DNS           53   TCP/UDP            NAT redirect → forwarder
#  DNS-over-TLS (DoT)  853  TCP                DROP (except KAHF)
#  DNS-over-QUIC (DoQ) 853  UDP                DROP (except KAHF)
#  QUIC/HTTP3          443  UDP                DROP (except KAHF)
#  DoH via HTTP/2      443  TCP                DROP to known DoH IPs
#  ──────────────────────────────────────────────────────────────────
#
#  PERMISSIONS:
#  ──────────────────────────────────────────────────────────────────
#  Bypass_Safe       = KahfGuard server IPs (encrypted DNS allowed TO)
#  Safe_Package_IPs  = Client IPs that must be filtered (filtered FROM)
#  DoH_Providers     = Known DoH provider IPs (always blocked for clients)
#  ──────────────────────────────────────────────────────────────────
#
#  IMPORTANT: Rules 853/443 use DROP (firewall filter), NOT dst-nat.
#  NAT redirect fails for encrypted protocols — TLS/QUIC validates the
#  server certificate, so redirecting to a different server causes a
#  silent TLS handshake failure, NOT a block.
#
#  Usage: /import file=forwarder-router-dns.rsc
# =====================================================================


# ===== CHANGE THESE PER ISP =====
:local forwarder "X.X.X.X"
:local safeList "Bypass_Safe"
:local clientList "Safe_Package_IPs"
# =================================


:local notSafeList ("!" . $safeList)


# ─────────────────────────────────
#  Address Lists
# ─────────────────────────────────

# KahfGuard servers — encrypted DNS is ALLOWED to these
/ip firewall address-list
add list=$safeList address=203.190.10.112/28  comment="KAHF-BDIX"
add list=$safeList address=40.120.32.128/26   comment="KAHF-Azure"

# Known DoH provider IPs — blocked on TCP 443 to prevent browser DoH bypass
# These are dedicated DNS anycast IPs, NOT shared with CDN/web services
/ip firewall address-list
add list=DoH_Providers address=1.1.1.1         comment="Cloudflare DNS"
add list=DoH_Providers address=1.0.0.1         comment="Cloudflare DNS"
add list=DoH_Providers address=8.8.8.8         comment="Google DNS"
add list=DoH_Providers address=8.8.4.4         comment="Google DNS"
add list=DoH_Providers address=9.9.9.9         comment="Quad9"
add list=DoH_Providers address=149.112.112.112 comment="Quad9"
add list=DoH_Providers address=9.9.9.10        comment="Quad9 unfiltered"
add list=DoH_Providers address=149.112.112.10  comment="Quad9 unfiltered"
add list=DoH_Providers address=208.67.222.222  comment="OpenDNS"
add list=DoH_Providers address=208.67.220.220  comment="OpenDNS"
add list=DoH_Providers address=94.140.14.14    comment="AdGuard"
add list=DoH_Providers address=94.140.15.15    comment="AdGuard"
add list=DoH_Providers address=45.90.28.0      comment="NextDNS"
add list=DoH_Providers address=45.90.30.0      comment="NextDNS"
add list=DoH_Providers address=185.228.168.9   comment="CleanBrowsing"
add list=DoH_Providers address=185.228.169.9   comment="CleanBrowsing"
add list=DoH_Providers address=76.76.2.0       comment="ControlD"
add list=DoH_Providers address=76.76.10.0      comment="ControlD"
add list=DoH_Providers address=194.242.2.2     comment="Mullvad"


# ─────────────────────────────────
#  NAT: Plain DNS (port 53) → Forwarder
# ─────────────────────────────────
# Only redirects clients in $clientList. Other users keep their own DNS.

/ip firewall nat
add chain=dstnat protocol=udp dst-port=53 src-address-list=$clientList \
    action=dst-nat to-addresses=$forwarder to-ports=53 comment="DNS to Core: UDP"
add chain=dstnat protocol=tcp dst-port=53 src-address-list=$clientList \
    action=dst-nat to-addresses=$forwarder to-ports=53 comment="DNS to Core: TCP"


# ─────────────────────────────────
#  FILTER: Encrypted DNS → DROP (except KAHF)
# ─────────────────────────────────
# Uses firewall filter (DROP), NOT NAT redirect.
# NAT redirect of encrypted protocols fails silently (TLS cert mismatch).

/ip firewall filter
add chain=forward protocol=tcp dst-port=853 src-address-list=$clientList \
    dst-address-list=$notSafeList action=drop comment="Drop DoT"
add chain=forward protocol=udp dst-port=853 src-address-list=$clientList \
    dst-address-list=$notSafeList action=drop comment="Drop DoQ"
add chain=forward protocol=udp dst-port=443 src-address-list=$clientList \
    dst-address-list=$notSafeList action=drop comment="Drop QUIC/DoH3"


# ─────────────────────────────────
#  FILTER: DoH over HTTP/2 (TCP 443) → DROP to known providers
# ─────────────────────────────────
# TCP 443 can't be blanket-blocked (breaks all HTTPS).
# Instead, block TCP 443 to known DoH provider IPs specifically.
# These are dedicated DNS anycast IPs — blocking them does NOT affect
# web browsing (CDN/websites use different IP ranges).

add chain=forward protocol=tcp dst-port=443 src-address-list=$clientList \
    dst-address-list=DoH_Providers action=drop comment="Drop DoH to known providers"


:log info "KahfGuard DNS enforcement loaded: 53->$forwarder, 853/443u->KAHF only, DoH IPs blocked"
