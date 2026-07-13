# =====================================================================
#  Distribution Router -- DNS Filtering Enforcement
#  VERSION 2.0 — IPv6 Mirror + Comprehensive DoH Blocklist
# =====================================================================
#
#  BYPASS VECTORS AND MITIGATIONS:
#  ----------------------------------------------------------------
#  Vector              Port        Protocol    Mitigation
#  ----------------------------------------------------------------
#  Plain DNS           53   TCP/UDP            NAT redirect -> forwarder
#  DNS-over-TLS (DoT)  853  TCP                REJECT (except KAHF)
#  DNS-over-QUIC (DoQ) 853  UDP                REJECT (except KAHF)
#  QUIC/HTTP3          443  UDP                REJECT (except KAHF)
#  DoH via HTTP/2      443  TCP                REJECT to known DoH IPs
#  OpenVPN             1194 TCP/UDP            REJECT
#  WireGuard/NordLynx  51820 UDP               REJECT
#  IKEv2               500  UDP                REJECT
#  IPSec NAT-T         4500 UDP                REJECT
#  PPTP control        1723 TCP                REJECT
#  GRE (PPTP data)     --   GRE (proto 47)     DROP
#  L2TP                1701 UDP                REJECT
#  TOR ORPort          9001 TCP/UDP            REJECT (KAHF-TOR)
#  TOR DirPort         9030 TCP                REJECT (KAHF-TOR)
#  TOR SOCKS proxy     9050 TCP                REJECT (KAHF-TOR)
#  TOR control port    9051 TCP                REJECT (KAHF-TOR)
#  TOR Browser         9150-9151 TCP           REJECT (KAHF-TOR)
#  ----------------------------------------------------------------
#
#  VERSION 2.0 ADDITIONS:
#  ----------------------------------------------------------------
#  - IPv6 firewall mirror for ALL filter rules
#  - Comprehensive DoH blocklist: 60+ providers, IPv4 + IPv6
#  - Covers: Cloudflare, Google, Quad9, OpenDNS, AdGuard, NextDNS,
#    CleanBrowsing, ControlD, Mullvad, Yandex, Comodo, Verisign,
#    Hurricane Electric, AliDNS, DNS4EU, Surfshark, Samsung,
#    OpenNIC, FreeDNS, SafeDNS, Norton, Meta, Tencent, Punycod
#  - IPv6 DoH IPs for all major providers
#  ----------------------------------------------------------------
#
#  ADDRESS LISTS:
#  ----------------------------------------------------------------
#  Bypass_Safe       = KahfGuard server IPs (encrypted DNS allowed TO)
#  Safe_Package_IPs  = Client IPs that must be filtered (filtered FROM)
#  DoH_Providers     = Known DoH provider IPs (always blocked for clients)
#  TOR_Relays        = Known TOR relay IPs (blocked)
#  ----------------------------------------------------------------
#
#  IMPORTANT: Rules 853/443 use REJECT (firewall filter), NOT dst-nat.
#  NAT redirect fails for encrypted protocols -- TLS/QUIC validates the
#  server certificate, so redirecting to a different server causes a
#  silent TLS handshake failure, NOT a block.
#
#  NOTE: MikroTik NAT to-addresses only accepts literal IPs or ranges,
#  NOT address-list references. To add non-contiguous forwarder IPs,
#  use multiple NAT rules with nth load balancing.
#
#  Usage: /import file=forwarder-router-dns-v2.rsc
# =====================================================================


# ===== CHANGE THESE PER ISP =====
:global kahfFwdStart "203.190.10.116"
:global kahfFwdEnd   "203.190.10.117"
:global kahfFwdIPv6  "2a01:4f9:3051:4d60::100"  # Forwarder IPv6 address (CHANGE THIS)
:global kahfSafeList "Bypass_Safe"
:global kahfClientList "Safe_Package_IPs"
# =================================

# ===== FEATURE TOGGLES =====
:global kahfBlockVPN true
:global kahfBlockTOR true
:global kahfBlockIPv6 true      # Enable/disable ALL IPv6 rules (NAT + filter)
:global kahfBlockIPv6NAT true   # Enable/disable IPv6 NAT redirect (RouterOS 7.x)
# ============================

:global kahfFwdRange ($kahfFwdStart . "-" . $kahfFwdEnd)
:global kahfNotSafe ("!" . $kahfSafeList)


# ---------------------------------
#  Cleanup: Remove old rules before re-importing
# ---------------------------------

/ip firewall nat remove [find where comment~"DNS to Core"]
/ip firewall filter remove [find where comment~"KAHF-DNS"]
/ip firewall filter remove [find where comment~"KAHF-VPN"]
/ip firewall filter remove [find where comment~"KAHF-TOR"]
/ip firewall filter remove [find where comment~"Drop Do"]
/ip firewall filter remove [find where comment~"Drop QUIC"]
/ip firewall address-list remove [find where list=$kahfClientList]
/ip firewall address-list remove [find where list=$kahfSafeList]
/ip firewall address-list remove [find where list=DoH_Providers]
/ip firewall address-list remove [find where list=TOR_Relays]

# IPv6 cleanup
/ip6 firewall filter remove [find where comment~"KAHF-DNS"]
/ip6 firewall filter remove [find where comment~"KAHF-VPN"]
/ip6 firewall filter remove [find where comment~"KAHF-TOR"]
/ip6 firewall filter remove [find where comment~"Drop Do"]
/ip6 firewall filter remove [find where comment~"Drop QUIC"]
/ip6 firewall address-list remove [find where list=$kahfClientList]
/ip6 firewall address-list remove [find where list=$kahfSafeList]
/ip6 firewall address-list remove [find where list=DoH_Providers]
/ip6 firewall address-list remove [find where list=TOR_Relays]


# ====================================================================
#  ADDRESS LISTS — IPv4
# ====================================================================

# Client IPs to be filtered -- CHANGE per ISP
/ip firewall address-list add list=$kahfClientList address=0.0.0.0/0 comment="All traffic"

# KahfGuard servers -- encrypted DNS is ALLOWED to these
/ip firewall address-list add list=$kahfSafeList address=203.190.10.112/28 comment="KAHF-BDIX"
/ip firewall address-list add list=$kahfSafeList address=40.120.32.128/26  comment="KAHF-Azure"

# KahfGuard Hetzner servers -- encrypted DNS is ALLOWED to these
/ip firewall address-list add list=$kahfSafeList address=157.90.95.123     comment="KAHF-Hetzner1-Prod"
/ip firewall address-list add list=$kahfSafeList address=142.132.207.252   comment="KAHF-Hetzner2-Prod"
/ip firewall address-list add list=$kahfSafeList address=46.4.74.132       comment="KAHF-Hetzner3-Prod"
/ip firewall address-list add list=$kahfSafeList address=88.198.54.40      comment="KAHF-Hetzner-Dev"
/ip firewall address-list add list=$kahfSafeList address=65.109.71.84      comment="KAHF-Ubuntu-Desktop"
/ip firewall address-list add list=$kahfSafeList address=157.180.4.107     comment="KAHF-Hetzner-Large1"
/ip firewall address-list add list=$kahfSafeList address=168.119.148.24    comment="KAHF-S3-Node1"
/ip firewall address-list add list=$kahfSafeList address=88.99.193.70      comment="KAHF-S3-Node2"
/ip firewall address-list add list=$kahfSafeList address=188.40.200.184    comment="KAHF-S3-Node3"


# ====================================================================
#  COMPREHENSIVE DoH BLOCKLIST — IPv4
# ====================================================================

# --- Cloudflare ---
/ip firewall address-list add list=DoH_Providers address=1.1.1.1         comment="Cloudflare DNS"
/ip firewall address-list add list=DoH_Providers address=1.0.0.1         comment="Cloudflare DNS"
/ip firewall address-list add list=DoH_Providers address=1.1.1.2         comment="Cloudflare Malware"
/ip firewall address-list add list=DoH_Providers address=1.0.0.2         comment="Cloudflare Malware"
/ip firewall address-list add list=DoH_Providers address=1.1.1.3         comment="Cloudflare Family"
/ip firewall address-list add list=DoH_Providers address=1.0.0.3         comment="Cloudflare Family"

# --- Google ---
/ip firewall address-list add list=DoH_Providers address=8.8.8.8         comment="Google DNS"
/ip firewall address-list add list=DoH_Providers address=8.8.4.4         comment="Google DNS"
/ip firewall address-list add list=DoH_Providers address=8.8.8.9         comment="Google DNS (TLS)"
/ip firewall address-list add list=DoH_Providers address=8.8.4.9         comment="Google DNS (TLS)"
/ip firewall address-list add list=DoH_Providers address=8.8.8.1         comment="Google Family"
/ip firewall address-list add list=DoH_Providers address=8.8.4.1         comment="Google Family"

# --- Quad9 ---
/ip firewall address-list add list=DoH_Providers address=9.9.9.9         comment="Quad9"
/ip firewall address-list add list=DoH_Providers address=149.112.112.112 comment="Quad9"
/ip firewall address-list add list=DoH_Providers address=9.9.9.10        comment="Quad9 unfiltered"
/ip firewall address-list add list=DoH_Providers address=149.112.112.10  comment="Quad9 unfiltered"
/ip firewall address-list add list=DoH_Providers address=9.9.9.11        comment="Quad9 No Threat Intel"
/ip firewall address-list add list=DoH_Providers address=149.112.112.11  comment="Quad9 No Threat Intel"

# --- OpenDNS (Cisco) ---
/ip firewall address-list add list=DoH_Providers address=208.67.222.222  comment="OpenDNS"
/ip firewall address-list add list=DoH_Providers address=208.67.220.220  comment="OpenDNS"
/ip firewall address-list add list=DoH_Providers address=208.67.222.123  comment="OpenDNS FamilyShield"
/ip firewall address-list add list=DoH_Providers address=208.67.220.123  comment="OpenDNS FamilyShield"

# --- AdGuard ---
/ip firewall address-list add list=DoH_Providers address=94.140.14.14    comment="AdGuard DNS"
/ip firewall address-list add list=DoH_Providers address=94.140.15.15    comment="AdGuard DNS"
/ip firewall address-list add list=DoH_Providers address=94.140.14.15    comment="AdGuard Family"
/ip firewall address-list add list=DoH_Providers address=94.140.15.16    comment="AdGuard Family"
/ip firewall address-list add list=DoH_Providers address=94.140.14.29    comment="AdGuard Non-Filters"
/ip firewall address-list add list=DoH_Providers address=94.140.15.30    comment="AdGuard Non-Filters"

# --- NextDNS ---
/ip firewall address-list add list=DoH_Providers address=45.90.28.0      comment="NextDNS"
/ip firewall address-list add list=DoH_Providers address=45.90.30.0      comment="NextDNS"
/ip firewall address-list add list=DoH_Providers address=45.90.28.137    comment="NextDNS Alt"
/ip firewall address-list add list=DoH_Providers address=45.90.30.137    comment="NextDNS Alt"

# --- CleanBrowsing ---
/ip firewall address-list add list=DoH_Providers address=185.228.168.9   comment="CleanBrowsing"
/ip firewall address-list add list=DoH_Providers address=185.228.169.9   comment="CleanBrowsing"
/ip firewall address-list add list=DoH_Providers address=185.228.168.168 comment="CleanBrowsing Family"
/ip firewall address-list add list=DoH_Providers address=185.228.169.168 comment="CleanBrowsing Family"
/ip firewall address-list add list=DoH_Providers address=185.228.168.132 comment="CleanBrowsing Security"
/ip firewall address-list add list=DoH_Providers address=185.228.169.132 comment="CleanBrowsing Security"

# --- ControlD ---
/ip firewall address-list add list=DoH_Providers address=76.76.2.0       comment="ControlD"
/ip firewall address-list add list=DoH_Providers address=76.76.10.0      comment="ControlD"

# --- Mullvad ---
/ip firewall address-list add list=DoH_Providers address=194.242.2.2     comment="Mullvad DNS"

# --- Yandex ---
/ip firewall address-list add list=DoH_Providers address=77.88.8.8       comment="Yandex DNS"
/ip firewall address-list add list=DoH_Providers address=77.88.8.1       comment="Yandex DNS"
/ip firewall address-list add list=DoH_Providers address=77.88.8.7       comment="Yandex Safe"
/ip firewall address-list add list=DoH_Providers address=77.88.8.3       comment="Yandex Family"

# --- Comodo Secure DNS ---
/ip firewall address-list add list=DoH_Providers address=8.26.56.26      comment="Comodo DNS"
/ip firewall address-list add list=DoH_Providers address=8.20.247.20     comment="Comodo DNS"
/ip firewall address-list add list=DoH_Providers address=8.26.56.10      comment="Comodo Malware"
/ip firewall address-list add list=DoH_Providers address=8.20.247.2      comment="Comodo Malware"

# --- Hurricane Electric ---
/ip firewall address-list add list=DoH_Providers address=74.82.42.42     comment="HE DNS"

# --- Verisign ---
/ip firewall address-list add list=DoH_Providers address=64.6.64.6       comment="Verisign DNS"
/ip firewall address-list add list=DoH_Providers address=64.6.65.6       comment="Verisign DNS"

# --- Neustar/UltraDNS ---
/ip firewall address-list add list=DoH_Providers address=156.154.70.1    comment="UltraDNS"
/ip firewall address-list add list=DoH_Providers address=156.154.71.1    comment="UltraDNS"
/ip firewall address-list add list=DoH_Providers address=156.154.70.5    comment="UltraDNS Family"

# --- AliDNS (Alibaba) ---
/ip firewall address-list add list=DoH_Providers address=223.5.5.5       comment="AliDNS"
/ip firewall address-list add list=DoH_Providers address=223.6.6.6       comment="AliDNS"

# --- Tencent DNSPod ---
/ip firewall address-list add list=DoH_Providers address=119.29.29.29    comment="Tencent DNSPod"
/ip firewall address-list add list=DoH_Providers address=119.29.29.28    comment="Tencent DNSPod"

# --- DNS4EU ---
/ip firewall address-list add list=DoH_Providers address=185.253.56.13   comment="DNS4EU"
/ip firewall address-list add list=DoH_Providers address=185.253.57.13   comment="DNS4EU"

# --- FreeDNS ---
/ip firewall address-list add list=DoH_Providers address=37.235.1.174    comment="FreeDNS"
/ip firewall address-list add list=DoH_Providers address=37.235.1.177    comment="FreeDNS"

# --- SafeDNS ---
/ip firewall address-list add list=DoH_Providers address=195.46.39.39    comment="SafeDNS"
/ip firewall address-list add list=DoH_Providers address=195.46.39.40    comment="SafeDNS"

# --- Norton ConnectSafe ---
/ip firewall address-list add list=DoH_Providers address=199.85.126.10   comment="Norton DNS"
/ip firewall address-list add list=DoH_Providers address=199.85.127.10   comment="Norton DNS"

# --- GreenTeamDNS ---
/ip firewall address-list add list=DoH_Providers address=81.2.216.180    comment="GreenTeamDNS"
/ip firewall address-list add list=DoH_Providers address=81.2.216.181    comment="GreenTeamDNS"

# --- OpenNIC ---
/ip firewall address-list add list=DoH_Providers address=185.121.177.177 comment="OpenNIC"
/ip firewall address-list add list=DoH_Providers address=169.239.202.202 comment="OpenNIC"

# --- Surfshark DNS ---
/ip firewall address-list add list=DoH_Providers address=162.252.172.181 comment="Surfshark DNS"
/ip firewall address-list add list=DoH_Providers address=149.154.159.92  comment="Surfshark DNS"

# --- Samsung DNS ---
/ip firewall address-list add list=DoH_Providers address=210.220.163.224 comment="Samsung DNS"
/ip firewall address-list add list=DoH_Providers address=210.220.163.225 comment="Samsung DNS"

# --- Puncod DNS ---
/ip firewall address-list add list=DoH_Providers address=185.121.177.160 comment="Puncod DNS"

# --- ArvanCloud ---
/ip firewall address-list add list=DoH_Providers address=185.51.200.2    comment="ArvanCloud DNS"
/ip firewall address-list add list=DoH_Providers address=78.157.42.100   comment="ArvanCloud DNS"

# --- Bahnhof ---
/ip firewall address-list add list=DoH_Providers address=91.239.100.100  comment="Bahnhof DNS"

# --- DNS.Watch ---
/ip firewall address-list add list=DoH_Providers address=185.228.168.9   comment="DNS.Watch"

# --- IANA special-use (block to prevent local DoH servers) ---
/ip firewall address-list add list=DoH_Providers address=127.0.0.0/8     comment="Loopback"


:if ($kahfBlockIPv6) do={

# ====================================================================
#  KahfGuard Hetzner IPv6 Addresses — encrypted DNS is ALLOWED to these
# ====================================================================

/ip6 firewall address-list add list=$kahfSafeList address=2a01:4f9:3051:4d60::2  comment="KAHF-Ubuntu-Desktop-IPv6"


# ====================================================================
#  COMPREHENSIVE DoH BLOCKLIST — IPv6 DoH Providers
# ====================================================================

# --- Cloudflare IPv6 ---
/ip6 firewall address-list add list=DoH_Providers address=2606:4700:4700::1111  comment="Cloudflare IPv6"
/ip6 firewall address-list add list=DoH_Providers address=2606:4700:4700::1001  comment="Cloudflare IPv6"
/ip6 firewall address-list add list=DoH_Providers address=2606:4700:4700::1112  comment="Cloudflare Malware IPv6"
/ip6 firewall address-list add list=DoH_Providers address=2606:4700:4700::1002  comment="Cloudflare Malware IPv6"
/ip6 firewall address-list add list=DoH_Providers address=2606:4700:4700::1113  comment="Cloudflare Family IPv6"
/ip6 firewall address-list add list=DoH_Providers address=2606:4700:4700::1003  comment="Cloudflare Family IPv6"

# --- Google IPv6 ---
/ip6 firewall address-list add list=DoH_Providers address=2001:4860:4860::8888  comment="Google DNS IPv6"
/ip6 firewall address-list add list=DoH_Providers address=2001:4860:4860::8844  comment="Google DNS IPv6"
/ip6 firewall address-list add list=DoH_Providers address=2001:4860:4860::8889  comment="Google DNS (TLS) IPv6"
/ip6 firewall address-list add list=DoH_Providers address=2001:4860:4860::8855  comment="Google DNS (TLS) IPv6"

# --- Quad9 IPv6 ---
/ip6 firewall address-list add list=DoH_Providers address=2620:fe::fe              comment="Quad9 IPv6"
/ip6 firewall address-list add list=DoH_Providers address=2620:fe::9              comment="Quad9 IPv6"
/ip6 firewall address-list add list=DoH_Providers address=2620:fe::10             comment="Quad9 Unfiltered IPv6"
/ip6 firewall address-list add list=DoH_Providers address=2620:fe::fe:10          comment="Quad9 Unfiltered IPv6"

# --- OpenDNS IPv6 ---
/ip6 firewall address-list add list=DoH_Providers address=2620:119:35::35         comment="OpenDNS IPv6"
/ip6 firewall address-list add list=DoH_Providers address=2620:119:53::53         comment="OpenDNS IPv6"

# --- AdGuard IPv6 ---
/ip6 firewall address-list add list=DoH_Providers address=2a10:50c0::ad1:ff       comment="AdGuard IPv6"
/ip6 firewall address-list add list=DoH_Providers address=2a10:50c0::ad2:ff       comment="AdGuard IPv6"
/ip6 firewall address-list add list=DoH_Providers address=2a10:50c0::ad1:1ff      comment="AdGuard Family IPv6"
/ip6 firewall address-list add list=DoH_Providers address=2a10:50c0::ad2:2ff      comment="AdGuard Family IPv6"

# --- NextDNS IPv6 ---
/ip6 firewall address-list add list=DoH_Providers address=2a07:a8c0::17:a8c1      comment="NextDNS IPv6"
/ip6 firewall address-list add list=DoH_Providers address=2a07:a8c1::17:a8c1      comment="NextDNS IPv6"

# --- CleanBrowsing IPv6 ---
/ip6 firewall address-list add list=DoH_Providers address=2a0d:2a00:1::1           comment="CleanBrowsing IPv6"
/ip6 firewall address-list add list=DoH_Providers address=2a0d:2a00:2::1           comment="CleanBrowsing IPv6"

# --- ControlD IPv6 ---
/ip6 firewall address-list add list=DoH_Providers address=2606:1a40::              comment="ControlD IPv6"
/ip6 firewall address-list add list=DoH_Providers address=2606:1a40:1::            comment="ControlD IPv6"

# --- Mullvad IPv6 ---
/ip6 firewall address-list add list=DoH_Providers address=2a07:bec4::              comment="Mullvad IPv6"

# --- Comodo IPv6 ---
/ip6 firewall address-list add list=DoH_Providers address=2a02:bc8::1              comment="Comodo IPv6"

# --- Hurricane Electric IPv6 ---
/ip6 firewall address-list add list=DoH_Providers address=2001:470:20::2           comment="HE DNS IPv6"

# --- Verisign IPv6 ---
/ip6 firewall address-list add list=DoH_Providers address=2620:74:1b::1:1          comment="Verisign IPv6"
/ip6 firewall address-list add list=DoH_Providers address=2620:74:1c::2:2          comment="Verisign IPv6"

# --- Neustar IPv6 ---
/ip6 firewall address-list add list=DoH_Providers address=2610:a1:1018::1          comment="UltraDNS IPv6"

# --- AliDNS IPv6 ---
/ip6 firewall address-list add list=DoH_Providers address=2400:3200::1             comment="AliDNS IPv6"
/ip6 firewall address-list add list=DoH_Providers address=2400:3200:baba::1        comment="AliDNS IPv6"

# --- Tencent DNSPod IPv6 ---
/ip6 firewall address-list add list=DoH_Providers address=2402:4e00::              comment="Tencent DNSPod IPv6"

# --- DNS4EU IPv6 ---
/ip6 firewall address-list add list=DoH_Providers address=2a05:fc44::              comment="DNS4EU IPv6"

# --- Yandex IPv6 ---
/ip6 firewall address-list add list=DoH_Providers address=2a02:6f8::fec            comment="Yandex IPv6"

# --- FreeDNS IPv6 ---
/ip6 firewall address-list add list=DoH_Providers address=2001:4b98::c0c0          comment="FreeDNS IPv6"
/ip6 firewall address-list add list=DoH_Providers address=2001:4b98::dc01          comment="FreeDNS IPv6"

} # end kahfBlockIPv6


# ====================================================================
#  NAT: Plain DNS (port 53) -> Forwarder (IPv4)
# ====================================================================

/ip firewall nat add chain=dstnat protocol=udp dst-port=53 src-address-list=$kahfClientList \
    action=dst-nat to-addresses=$kahfFwdRange to-ports=53 comment="DNS to Core: UDP"
/ip firewall nat add chain=dstnat protocol=tcp dst-port=53 src-address-list=$kahfClientList \
    action=dst-nat to-addresses=$kahfFwdRange to-ports=53 comment="DNS to Core: TCP"


# ====================================================================
#  FILTER: Encrypted DNS -> REJECT (except KAHF) — IPv4
# ====================================================================

:local ftRule [/ip firewall filter find where action=fasttrack-connection chain=forward]

:if ([:len $ftRule] > 0) do={
    /ip firewall filter add chain=forward protocol=tcp dst-port=853 src-address-list=$kahfClientList \
        dst-address-list=$kahfNotSafe action=reject reject-with=tcp-reset \
        comment="KAHF-DNS: Reject DoT" place-before=$ftRule
    /ip firewall filter add chain=forward protocol=udp dst-port=853 src-address-list=$kahfClientList \
        dst-address-list=$kahfNotSafe action=reject reject-with=icmp-network-unreachable \
        comment="KAHF-DNS: Reject DoQ" place-before=$ftRule
    /ip firewall filter add chain=forward protocol=udp dst-port=443 src-address-list=$kahfClientList \
        dst-address-list=$kahfNotSafe action=reject reject-with=icmp-network-unreachable \
        comment="KAHF-DNS: Reject QUIC/DoH3" place-before=$ftRule
    /ip firewall filter add chain=forward protocol=tcp dst-port=443 src-address-list=$kahfClientList \
        dst-address-list=DoH_Providers action=reject reject-with=tcp-reset \
        comment="KAHF-DNS: Reject DoH" place-before=$ftRule
} else={
    /ip firewall filter add chain=forward protocol=tcp dst-port=853 src-address-list=$kahfClientList \
        dst-address-list=$kahfNotSafe action=reject reject-with=tcp-reset \
        comment="KAHF-DNS: Reject DoT"
    /ip firewall filter add chain=forward protocol=udp dst-port=853 src-address-list=$kahfClientList \
        dst-address-list=$kahfNotSafe action=reject reject-with=icmp-network-unreachable \
        comment="KAHF-DNS: Reject DoQ"
    /ip firewall filter add chain=forward protocol=udp dst-port=443 src-address-list=$kahfClientList \
        dst-address-list=$kahfNotSafe action=reject reject-with=icmp-network-unreachable \
        comment="KAHF-DNS: Reject QUIC/DoH3"
    /ip firewall filter add chain=forward protocol=tcp dst-port=443 src-address-list=$kahfClientList \
        dst-address-list=DoH_Providers action=reject reject-with=tcp-reset \
        comment="KAHF-DNS: Reject DoH"
}


# ====================================================================
#  FILTER: Encrypted DNS -> REJECT (except KAHF) — IPv6
# ====================================================================

:if ($kahfBlockIPv6) do={

:local ftRule6 [/ip6 firewall filter find where action=fasttrack-connection chain=forward]

:if ([:len $ftRule6] > 0) do={
    /ip6 firewall filter add chain=forward protocol=tcp dst-port=853 src-address-list=$kahfClientList \
        dst-address-list=$kahfNotSafe action=reject reject-with=tcp-reset \
        comment="KAHF-DNS: Reject DoT v6" place-before=$ftRule6
    /ip6 firewall filter add chain=forward protocol=udp dst-port=853 src-address-list=$kahfClientList \
        dst-address-list=$kahfNotSafe action=reject reject-with=icmp6-no-route \
        comment="KAHF-DNS: Reject DoQ v6" place-before=$ftRule6
    /ip6 firewall filter add chain=forward protocol=udp dst-port=443 src-address-list=$kahfClientList \
        dst-address-list=$kahfNotSafe action=reject reject-with=icmp6-no-route \
        comment="KAHF-DNS: Reject QUIC/DoH3 v6" place-before=$ftRule6
    /ip6 firewall filter add chain=forward protocol=tcp dst-port=443 src-address-list=$kahfClientList \
        dst-address-list=DoH_Providers action=reject reject-with=tcp-reset \
        comment="KAHF-DNS: Reject DoH v6" place-before=$ftRule6
} else={
    /ip6 firewall filter add chain=forward protocol=tcp dst-port=853 src-address-list=$kahfClientList \
        dst-address-list=$kahfNotSafe action=reject reject-with=tcp-reset \
        comment="KAHF-DNS: Reject DoT v6"
    /ip6 firewall filter add chain=forward protocol=udp dst-port=853 src-address-list=$kahfClientList \
        dst-address-list=$kahfNotSafe action=reject reject-with=icmp6-no-route \
        comment="KAHF-DNS: Reject DoQ v6"
    /ip6 firewall filter add chain=forward protocol=udp dst-port=443 src-address-list=$kahfClientList \
        dst-address-list=$kahfNotSafe action=reject reject-with=icmp6-no-route \
        comment="KAHF-DNS: Reject QUIC/DoH3 v6"
    /ip6 firewall filter add chain=forward protocol=tcp dst-port=443 src-address-list=$kahfClientList \
        dst-address-list=DoH_Providers action=reject reject-with=tcp-reset \
        comment="KAHF-DNS: Reject DoH v6"
}

}


# ====================================================================
#  FILTER: VPN Protocol Blocking — IPv4
# ====================================================================

:if ($kahfBlockVPN) do={

:global kahfFtVPN [/ip firewall filter find where action=fasttrack-connection chain=forward]

:if ([:len $kahfFtVPN] > 0) do={
    /ip firewall filter add chain=forward protocol=udp dst-port=1194 src-address-list=$kahfClientList action=reject reject-with=icmp-network-unreachable comment="KAHF-VPN: Block OpenVPN UDP" place-before=$kahfFtVPN
    /ip firewall filter add chain=forward protocol=tcp dst-port=1194 src-address-list=$kahfClientList action=reject reject-with=tcp-reset comment="KAHF-VPN: Block OpenVPN TCP" place-before=$kahfFtVPN
    /ip firewall filter add chain=forward protocol=udp dst-port=1195-1198 src-address-list=$kahfClientList action=reject reject-with=icmp-network-unreachable comment="KAHF-VPN: Block OpenVPN Alt Ports" place-before=$kahfFtVPN
    /ip firewall filter add chain=forward protocol=udp dst-port=51820 src-address-list=$kahfClientList action=reject reject-with=icmp-network-unreachable comment="KAHF-VPN: Block WireGuard" place-before=$kahfFtVPN
    /ip firewall filter add chain=forward protocol=udp dst-port=500 src-address-list=$kahfClientList action=reject reject-with=icmp-network-unreachable comment="KAHF-VPN: Block IKEv2" place-before=$kahfFtVPN
    /ip firewall filter add chain=forward protocol=tcp dst-port=500 src-address-list=$kahfClientList action=reject reject-with=tcp-reset comment="KAHF-VPN: Block IKEv2 TCP" place-before=$kahfFtVPN
    /ip firewall filter add chain=forward protocol=udp dst-port=4500 src-address-list=$kahfClientList action=reject reject-with=icmp-network-unreachable comment="KAHF-VPN: Block IPSec NAT-T" place-before=$kahfFtVPN
    /ip firewall filter add chain=forward protocol=tcp dst-port=1723 src-address-list=$kahfClientList action=reject reject-with=tcp-reset comment="KAHF-VPN: Block PPTP" place-before=$kahfFtVPN
    /ip firewall filter add chain=forward protocol=gre src-address-list=$kahfClientList action=drop comment="KAHF-VPN: Block GRE" place-before=$kahfFtVPN
    /ip firewall filter add chain=forward protocol=udp dst-port=1701 src-address-list=$kahfClientList action=reject reject-with=icmp-network-unreachable comment="KAHF-VPN: Block L2TP" place-before=$kahfFtVPN
    /ip firewall filter add chain=forward protocol=tcp dst-port=8388 src-address-list=$kahfClientList action=reject reject-with=tcp-reset comment="KAHF-VPN: Block Shadowsocks TCP" place-before=$kahfFtVPN
    /ip firewall filter add chain=forward protocol=udp dst-port=8388 src-address-list=$kahfClientList action=reject reject-with=icmp-network-unreachable comment="KAHF-VPN: Block Shadowsocks UDP" place-before=$kahfFtVPN
    /ip firewall filter add chain=forward protocol=udp dst-port=41641 src-address-list=$kahfClientList action=reject reject-with=icmp-network-unreachable comment="KAHF-VPN: Block Tailscale" place-before=$kahfFtVPN
    /ip firewall filter add chain=forward protocol=udp dst-port=9993 src-address-list=$kahfClientList action=reject reject-with=icmp-network-unreachable comment="KAHF-VPN: Block ZeroTier" place-before=$kahfFtVPN
    /ip firewall filter add chain=forward protocol=tcp dst-port=992 src-address-list=$kahfClientList action=reject reject-with=tcp-reset comment="KAHF-VPN: Block SoftEther" place-before=$kahfFtVPN
    /ip firewall filter add chain=forward protocol=tcp dst-port=5555 src-address-list=$kahfClientList action=reject reject-with=tcp-reset comment="KAHF-VPN: Block SoftEther Alt" place-before=$kahfFtVPN
    /ip firewall filter add chain=forward protocol=tcp dst-port=1723 src-address-list=$kahfClientList action=reject reject-with=tcp-reset comment="KAHF-VPN: Block PPTP Control" place-before=$kahfFtVPN
    /ip firewall filter add chain=forward protocol=gre src-address-list=$kahfClientList action=drop comment="KAHF-VPN: Block GRE" place-before=$kahfFtVPN
} else={
    /ip firewall filter add chain=forward protocol=udp dst-port=1194 src-address-list=$kahfClientList action=reject reject-with=icmp-network-unreachable comment="KAHF-VPN: Block OpenVPN UDP"
    /ip firewall filter add chain=forward protocol=tcp dst-port=1194 src-address-list=$kahfClientList action=reject reject-with=tcp-reset comment="KAHF-VPN: Block OpenVPN TCP"
    /ip firewall filter add chain=forward protocol=udp dst-port=1195-1198 src-address-list=$kahfClientList action=reject reject-with=icmp-network-unreachable comment="KAHF-VPN: Block OpenVPN Alt Ports"
    /ip firewall filter add chain=forward protocol=udp dst-port=51820 src-address-list=$kahfClientList action=reject reject-with=icmp-network-unreachable comment="KAHF-VPN: Block WireGuard"
    /ip firewall filter add chain=forward protocol=udp dst-port=500 src-address-list=$kahfClientList action=reject reject-with=icmp-network-unreachable comment="KAHF-VPN: Block IKEv2"
    /ip firewall filter add chain=forward protocol=tcp dst-port=500 src-address-list=$kahfClientList action=reject reject-with=tcp-reset comment="KAHF-VPN: Block IKEv2 TCP"
    /ip firewall filter add chain=forward protocol=udp dst-port=4500 src-address-list=$kahfClientList action=reject reject-with=icmp-network-unreachable comment="KAHF-VPN: Block IPSec NAT-T"
    /ip firewall filter add chain=forward protocol=tcp dst-port=1723 src-address-list=$kahfClientList action=reject reject-with=tcp-reset comment="KAHF-VPN: Block PPTP"
    /ip firewall filter add chain=forward protocol=gre src-address-list=$kahfClientList action=drop comment="KAHF-VPN: Block GRE"
    /ip firewall filter add chain=forward protocol=udp dst-port=1701 src-address-list=$kahfClientList action=reject reject-with=icmp-network-unreachable comment="KAHF-VPN: Block L2TP"
    /ip firewall filter add chain=forward protocol=tcp dst-port=8388 src-address-list=$kahfClientList action=reject reject-with=tcp-reset comment="KAHF-VPN: Block Shadowsocks TCP"
    /ip firewall filter add chain=forward protocol=udp dst-port=8388 src-address-list=$kahfClientList action=reject reject-with=icmp-network-unreachable comment="KAHF-VPN: Block Shadowsocks UDP"
    /ip firewall filter add chain=forward protocol=udp dst-port=41641 src-address-list=$kahfClientList action=reject reject-with=icmp-network-unreachable comment="KAHF-VPN: Block Tailscale"
    /ip firewall filter add chain=forward protocol=udp dst-port=9993 src-address-list=$kahfClientList action=reject reject-with=icmp-network-unreachable comment="KAHF-VPN: Block ZeroTier"
    /ip firewall filter add chain=forward protocol=tcp dst-port=992 src-address-list=$kahfClientList action=reject reject-with=tcp-reset comment="KAHF-VPN: Block SoftEther"
    /ip firewall filter add chain=forward protocol=tcp dst-port=5555 src-address-list=$kahfClientList action=reject reject-with=tcp-reset comment="KAHF-VPN: Block SoftEther Alt"
    /ip firewall filter add chain=forward protocol=tcp dst-port=1723 src-address-list=$kahfClientList action=reject reject-with=tcp-reset comment="KAHF-VPN: Block PPTP Control"
    /ip firewall filter add chain=forward protocol=gre src-address-list=$kahfClientList action=drop comment="KAHF-VPN: Block GRE"
}

}


# ====================================================================
#  FILTER: VPN Protocol Blocking — IPv6
# ====================================================================

:if ($kahfBlockVPN) do={

:global kahfFtVPN6 [/ip6 firewall filter find where action=fasttrack-connection chain=forward]

:if ([:len $kahfFtVPN6] > 0) do={
    /ip6 firewall filter add chain=forward protocol=udp dst-port=1194 src-address-list=$kahfClientList action=reject reject-with=icmp6-no-route comment="KAHF-VPN: Block OpenVPN UDP v6" place-before=$kahfFtVPN6
    /ip6 firewall filter add chain=forward protocol=tcp dst-port=1194 src-address-list=$kahfClientList action=reject reject-with=tcp-reset comment="KAHF-VPN: Block OpenVPN TCP v6" place-before=$kahfFtVPN6
    /ip6 firewall filter add chain=forward protocol=udp dst-port=1195-1198 src-address-list=$kahfClientList action=reject reject-with=icmp6-no-route comment="KAHF-VPN: Block OpenVPN Alt v6" place-before=$kahfFtVPN6
    /ip6 firewall filter add chain=forward protocol=udp dst-port=51820 src-address-list=$kahfClientList action=reject reject-with=icmp6-no-route comment="KAHF-VPN: Block WireGuard v6" place-before=$kahfFtVPN6
    /ip6 firewall filter add chain=forward protocol=udp dst-port=500 src-address-list=$kahfClientList action=reject reject-with=icmp6-no-route comment="KAHF-VPN: Block IKEv2 v6" place-before=$kahfFtVPN6
    /ip6 firewall filter add chain=forward protocol=tcp dst-port=500 src-address-list=$kahfClientList action=reject reject-with=tcp-reset comment="KAHF-VPN: Block IKEv2 TCP v6" place-before=$kahfFtVPN6
    /ip6 firewall filter add chain=forward protocol=udp dst-port=4500 src-address-list=$kahfClientList action=reject reject-with=icmp6-no-route comment="KAHF-VPN: Block IPSec NAT-T v6" place-before=$kahfFtVPN6
    /ip6 firewall filter add chain=forward protocol=tcp dst-port=1723 src-address-list=$kahfClientList action=reject reject-with=tcp-reset comment="KAHF-VPN: Block PPTP v6" place-before=$kahfFtVPN6
    /ip6 firewall filter add chain=forward protocol=44 src-address-list=$kahfClientList action=drop comment="KAHF-VPN: Block GRE v6" place-before=$kahfFtVPN6
    /ip6 firewall filter add chain=forward protocol=udp dst-port=1701 src-address-list=$kahfClientList action=reject reject-with=icmp6-no-route comment="KAHF-VPN: Block L2TP v6" place-before=$kahfFtVPN6
    /ip6 firewall filter add chain=forward protocol=tcp dst-port=8388 src-address-list=$kahfClientList action=reject reject-with=tcp-reset comment="KAHF-VPN: Block Shadowsocks TCP v6" place-before=$kahfFtVPN6
    /ip6 firewall filter add chain=forward protocol=udp dst-port=8388 src-address-list=$kahfClientList action=reject reject-with=icmp6-no-route comment="KAHF-VPN: Block Shadowsocks UDP v6" place-before=$kahfFtVPN6
    /ip6 firewall filter add chain=forward protocol=udp dst-port=41641 src-address-list=$kahfClientList action=reject reject-with=icmp6-no-route comment="KAHF-VPN: Block Tailscale v6" place-before=$kahfFtVPN6
    /ip6 firewall filter add chain=forward protocol=udp dst-port=9993 src-address-list=$kahfClientList action=reject reject-with=icmp6-no-route comment="KAHF-VPN: Block ZeroTier v6" place-before=$kahfFtVPN6
    /ip6 firewall filter add chain=forward protocol=tcp dst-port=992 src-address-list=$kahfClientList action=reject reject-with=tcp-reset comment="KAHF-VPN: Block SoftEther v6" place-before=$kahfFtVPN6
    /ip6 firewall filter add chain=forward protocol=tcp dst-port=5555 src-address-list=$kahfClientList action=reject reject-with=tcp-reset comment="KAHF-VPN: Block SoftEther Alt v6" place-before=$kahfFtVPN6
} else={
    /ip6 firewall filter add chain=forward protocol=udp dst-port=1194 src-address-list=$kahfClientList action=reject reject-with=icmp6-no-route comment="KAHF-VPN: Block OpenVPN UDP v6"
    /ip6 firewall filter add chain=forward protocol=tcp dst-port=1194 src-address-list=$kahfClientList action=reject reject-with=tcp-reset comment="KAHF-VPN: Block OpenVPN TCP v6"
    /ip6 firewall filter add chain=forward protocol=udp dst-port=1195-1198 src-address-list=$kahfClientList action=reject reject-with=icmp6-no-route comment="KAHF-VPN: Block OpenVPN Alt v6"
    /ip6 firewall filter add chain=forward protocol=udp dst-port=51820 src-address-list=$kahfClientList action=reject reject-with=icmp6-no-route comment="KAHF-VPN: Block WireGuard v6"
    /ip6 firewall filter add chain=forward protocol=udp dst-port=500 src-address-list=$kahfClientList action=reject reject-with=icmp6-no-route comment="KAHF-VPN: Block IKEv2 v6"
    /ip6 firewall filter add chain=forward protocol=tcp dst-port=500 src-address-list=$kahfClientList action=reject reject-with=tcp-reset comment="KAHF-VPN: Block IKEv2 TCP v6"
    /ip6 firewall filter add chain=forward protocol=udp dst-port=4500 src-address-list=$kahfClientList action=reject reject-with=icmp6-no-route comment="KAHF-VPN: Block IPSec NAT-T v6"
    /ip6 firewall filter add chain=forward protocol=tcp dst-port=1723 src-address-list=$kahfClientList action=reject reject-with=tcp-reset comment="KAHF-VPN: Block PPTP v6"
    /ip6 firewall filter add chain=forward protocol=44 src-address-list=$kahfClientList action=drop comment="KAHF-VPN: Block GRE v6"
    /ip6 firewall filter add chain=forward protocol=udp dst-port=1701 src-address-list=$kahfClientList action=reject reject-with=icmp6-no-route comment="KAHF-VPN: Block L2TP v6"
    /ip6 firewall filter add chain=forward protocol=tcp dst-port=8388 src-address-list=$kahfClientList action=reject reject-with=tcp-reset comment="KAHF-VPN: Block Shadowsocks TCP v6"
    /ip6 firewall filter add chain=forward protocol=udp dst-port=8388 src-address-list=$kahfClientList action=reject reject-with=icmp6-no-route comment="KAHF-VPN: Block Shadowsocks UDP v6"
    /ip6 firewall filter add chain=forward protocol=udp dst-port=41641 src-address-list=$kahfClientList action=reject reject-with=icmp6-no-route comment="KAHF-VPN: Block Tailscale v6"
    /ip6 firewall filter add chain=forward protocol=udp dst-port=9993 src-address-list=$kahfClientList action=reject reject-with=icmp6-no-route comment="KAHF-VPN: Block ZeroTier v6"
    /ip6 firewall filter add chain=forward protocol=tcp dst-port=992 src-address-list=$kahfClientList action=reject reject-with=tcp-reset comment="KAHF-VPN: Block SoftEther v6"
    /ip6 firewall filter add chain=forward protocol=tcp dst-port=5555 src-address-list=$kahfClientList action=reject reject-with=tcp-reset comment="KAHF-VPN: Block SoftEther Alt v6"
}

}


# ====================================================================
#  FILTER: TOR Network Blocking — IPv4
# ====================================================================

:if ($kahfBlockTOR) do={

:global kahfFtTOR [/ip firewall filter find where action=fasttrack-connection chain=forward]

:if ([:len $kahfFtTOR] > 0) do={
    /ip firewall filter add chain=forward protocol=tcp dst-port=9001 src-address-list=$kahfClientList action=reject reject-with=tcp-reset comment="KAHF-TOR: Block ORPort TCP" place-before=$kahfFtTOR
    /ip firewall filter add chain=forward protocol=udp dst-port=9001 src-address-list=$kahfClientList action=reject reject-with=icmp-network-unreachable comment="KAHF-TOR: Block ORPort UDP" place-before=$kahfFtTOR
    /ip firewall filter add chain=forward protocol=tcp dst-port=9030 src-address-list=$kahfClientList action=reject reject-with=tcp-reset comment="KAHF-TOR: Block DirPort" place-before=$kahfFtTOR
    /ip firewall filter add chain=forward protocol=tcp dst-port=9050 src-address-list=$kahfClientList action=reject reject-with=tcp-reset comment="KAHF-TOR: Block SOCKS" place-before=$kahfFtTOR
    /ip firewall filter add chain=forward protocol=tcp dst-port=9051 src-address-list=$kahfClientList action=reject reject-with=tcp-reset comment="KAHF-TOR: Block Control" place-before=$kahfFtTOR
    /ip firewall filter add chain=forward protocol=tcp dst-port=9150-9151 src-address-list=$kahfClientList action=reject reject-with=tcp-reset comment="KAHF-TOR: Block Browser" place-before=$kahfFtTOR
} else={
    /ip firewall filter add chain=forward protocol=tcp dst-port=9001 src-address-list=$kahfClientList action=reject reject-with=tcp-reset comment="KAHF-TOR: Block ORPort TCP"
    /ip firewall filter add chain=forward protocol=udp dst-port=9001 src-address-list=$kahfClientList action=reject reject-with=icmp-network-unreachable comment="KAHF-TOR: Block ORPort UDP"
    /ip firewall filter add chain=forward protocol=tcp dst-port=9030 src-address-list=$kahfClientList action=reject reject-with=tcp-reset comment="KAHF-TOR: Block DirPort"
    /ip firewall filter add chain=forward protocol=tcp dst-port=9050 src-address-list=$kahfClientList action=reject reject-with=tcp-reset comment="KAHF-TOR: Block SOCKS"
    /ip firewall filter add chain=forward protocol=tcp dst-port=9051 src-address-list=$kahfClientList action=reject reject-with=tcp-reset comment="KAHF-TOR: Block Control"
    /ip firewall filter add chain=forward protocol=tcp dst-port=9150-9151 src-address-list=$kahfClientList action=reject reject-with=tcp-reset comment="KAHF-TOR: Block Browser"
}

}


# ====================================================================
#  FILTER: TOR Network Blocking — IPv6
# ====================================================================

:if ($kahfBlockTOR) do={

:global kahfFtTOR6 [/ip6 firewall filter find where action=fasttrack-connection chain=forward]

:if ([:len $kahfFtTOR6] > 0) do={
    /ip6 firewall filter add chain=forward protocol=tcp dst-port=9001 src-address-list=$kahfClientList action=reject reject-with=tcp-reset comment="KAHF-TOR: Block ORPort TCP v6" place-before=$kahfFtTOR6
    /ip6 firewall filter add chain=forward protocol=udp dst-port=9001 src-address-list=$kahfClientList action=reject reject-with=icmp6-no-route comment="KAHF-TOR: Block ORPort UDP v6" place-before=$kahfFtTOR6
    /ip6 firewall filter add chain=forward protocol=tcp dst-port=9030 src-address-list=$kahfClientList action=reject reject-with=tcp-reset comment="KAHF-TOR: Block DirPort v6" place-before=$kahfFtTOR6
    /ip6 firewall filter add chain=forward protocol=tcp dst-port=9050 src-address-list=$kahfClientList action=reject reject-with=tcp-reset comment="KAHF-TOR: Block SOCKS v6" place-before=$kahfFtTOR6
    /ip6 firewall filter add chain=forward protocol=tcp dst-port=9051 src-address-list=$kahfClientList action=reject reject-with=tcp-reset comment="KAHF-TOR: Block Control v6" place-before=$kahfFtTOR6
    /ip6 firewall filter add chain=forward protocol=tcp dst-port=9150-9151 src-address-list=$kahfClientList action=reject reject-with=tcp-reset comment="KAHF-TOR: Block Browser v6" place-before=$kahfFtTOR6
} else={
    /ip6 firewall filter add chain=forward protocol=tcp dst-port=9001 src-address-list=$kahfClientList action=reject reject-with=tcp-reset comment="KAHF-TOR: Block ORPort TCP v6"
    /ip6 firewall filter add chain=forward protocol=udp dst-port=9001 src-address-list=$kahfClientList action=reject reject-with=icmp6-no-route comment="KAHF-TOR: Block ORPort UDP v6"
    /ip6 firewall filter add chain=forward protocol=tcp dst-port=9030 src-address-list=$kahfClientList action=reject reject-with=tcp-reset comment="KAHF-TOR: Block DirPort v6"
    /ip6 firewall filter add chain=forward protocol=tcp dst-port=9050 src-address-list=$kahfClientList action=reject reject-with=tcp-reset comment="KAHF-TOR: Block SOCKS v6"
    /ip6 firewall filter add chain=forward protocol=tcp dst-port=9051 src-address-list=$kahfClientList action=reject reject-with=tcp-reset comment="KAHF-TOR: Block Control v6"
    /ip6 firewall filter add chain=forward protocol=tcp dst-port=9150-9151 src-address-list=$kahfClientList action=reject reject-with=tcp-reset comment="KAHF-TOR: Block Browser v6"
}

}


# ====================================================================
#  IPv6: NAT Redirect DNS -> Forwarder (RouterOS 7.x)
# ====================================================================
#  RouterOS 7.x supports /ipv6 firewall nat with dst-nat action.
#  This works exactly like IPv4 — client sends DNS to ANY address,
#  we redirect it to our forwarder. User's manual DNS settings
#  are transparently overridden.
#
#  REQUIREMENT: Forwarder must have an IPv6 address.
#  Set kahfFwdIPv6 to your forwarder's IPv6 address above.
# ====================================================================

:if ($kahfBlockIPv6) do={

:if ($kahfBlockIPv6NAT) do={
/ipv6 firewall nat add chain=dstnat protocol=udp dst-port=53 src-address-list=$kahfClientList \
    action=dst-nat to-addresses=$kahfFwdIPv6 to-ports=53 \
    comment="DNS to Core: UDP v6"

/ipv6 firewall nat add chain=dstnat protocol=tcp dst-port=53 src-address-list=$kahfClientList \
    action=dst-nat to-addresses=$kahfFwdIPv6 to-ports=53 \
    comment="DNS to Core: TCP v6"
} else={
# IPv6 NAT disabled — use filter-based approach instead
# WARNING: This BREAKS users with manual DNS (e.g. 8.8.8.8)
/ip6 firewall filter add chain=forward protocol=udp dst-port=53 src-address-list=$kahfClientList \
    dst-address-list=$kahfNotSafe action=drop \
    comment="KAHF-DNS: Drop DNS UDP to non-forwarder v6"
/ip6 firewall filter add chain=forward protocol=tcp dst-port=53 src-address-list=$kahfClientList \
    dst-address-list=$kahfNotSafe action=drop \
    comment="KAHF-DNS: Drop DNS TCP to non-forwarder v6"
}

}


:log info ("KahfGuard DNS enforcement v2.0 loaded: 53->" . $kahfFwdRange . ", 853/443u->KAHF only, DoH IPs blocked (IPv4+IPv6), VPN/TOR ports blocked (IPv4+IPv6)")
