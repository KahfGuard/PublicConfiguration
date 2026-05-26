# =====================================================================
#  Distribution Router -- DNS Filtering Enforcement
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
#  ADDRESS LISTS:
#  ----------------------------------------------------------------
#  Bypass_Safe       = KahfGuard server IPs (encrypted DNS allowed TO)
#  Safe_Package_IPs  = Client IPs that must be filtered (filtered FROM)
#  DoH_Providers     = Known DoH provider IPs (always blocked for clients)
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
#  Usage: /import file=forwarder-router-dns.rsc
# =====================================================================


# ===== CHANGE THESE PER ISP =====
:global forwarderStart "203.190.10.116"
:global forwarderEnd   "203.190.10.117"
:global safeList "Bypass_Safe"
:global clientList "Safe_Package_IPs"
# =================================

# ===== FEATURE TOGGLES =====
:global blockVPN true
:global blockTOR true
# ============================

:global forwarderRange ($forwarderStart . "-" . $forwarderEnd)
:global notSafeList ("!" . $safeList)


# ---------------------------------
#  Cleanup: Remove old rules before re-importing
# ---------------------------------

/ip firewall nat remove [find where comment~"DNS to Core"]
/ip firewall filter remove [find where comment~"KAHF-DNS"]
/ip firewall filter remove [find where comment~"KAHF-VPN"]
/ip firewall filter remove [find where comment~"KAHF-TOR"]
/ip firewall filter remove [find where comment~"Drop Do"]
/ip firewall filter remove [find where comment~"Drop QUIC"]
/ip firewall address-list remove [find where list=$clientList]
/ip firewall address-list remove [find where list=$safeList]
/ip firewall address-list remove [find where list=DoH_Providers]
/ip firewall address-list remove [find where list=TOR_Relays]


# ---------------------------------
#  Address Lists
# ---------------------------------

# Client IPs to be filtered -- CHANGE per ISP
/ip firewall address-list add list=$clientList address=0.0.0.0/0 comment="All traffic"

# KahfGuard servers -- encrypted DNS is ALLOWED to these
/ip firewall address-list add list=$safeList address=203.190.10.112/28 comment="KAHF-BDIX"
/ip firewall address-list add list=$safeList address=40.120.32.128/26  comment="KAHF-Azure"

# Known DoH provider IPs -- blocked on TCP 443 to prevent browser DoH bypass
/ip firewall address-list add list=DoH_Providers address=1.1.1.1         comment="Cloudflare DNS"
/ip firewall address-list add list=DoH_Providers address=1.0.0.1         comment="Cloudflare DNS"
/ip firewall address-list add list=DoH_Providers address=8.8.8.8         comment="Google DNS"
/ip firewall address-list add list=DoH_Providers address=8.8.4.4         comment="Google DNS"
/ip firewall address-list add list=DoH_Providers address=9.9.9.9         comment="Quad9"
/ip firewall address-list add list=DoH_Providers address=149.112.112.112 comment="Quad9"
/ip firewall address-list add list=DoH_Providers address=9.9.9.10        comment="Quad9 unfiltered"
/ip firewall address-list add list=DoH_Providers address=149.112.112.10  comment="Quad9 unfiltered"
/ip firewall address-list add list=DoH_Providers address=208.67.222.222  comment="OpenDNS"
/ip firewall address-list add list=DoH_Providers address=208.67.220.220  comment="OpenDNS"
/ip firewall address-list add list=DoH_Providers address=94.140.14.14    comment="AdGuard"
/ip firewall address-list add list=DoH_Providers address=94.140.15.15    comment="AdGuard"
/ip firewall address-list add list=DoH_Providers address=45.90.28.0      comment="NextDNS"
/ip firewall address-list add list=DoH_Providers address=45.90.30.0      comment="NextDNS"
/ip firewall address-list add list=DoH_Providers address=185.228.168.9   comment="CleanBrowsing"
/ip firewall address-list add list=DoH_Providers address=185.228.169.9   comment="CleanBrowsing"
/ip firewall address-list add list=DoH_Providers address=76.76.2.0       comment="ControlD"
/ip firewall address-list add list=DoH_Providers address=76.76.10.0      comment="ControlD"
/ip firewall address-list add list=DoH_Providers address=194.242.2.2     comment="Mullvad"


# ---------------------------------
#  NAT: Plain DNS (port 53) -> Forwarder
# ---------------------------------

/ip firewall nat add chain=dstnat protocol=udp dst-port=53 src-address-list=$clientList \
    action=dst-nat to-addresses=$forwarderRange to-ports=53 comment="DNS to Core: UDP"
/ip firewall nat add chain=dstnat protocol=tcp dst-port=53 src-address-list=$clientList \
    action=dst-nat to-addresses=$forwarderRange to-ports=53 comment="DNS to Core: TCP"


# ---------------------------------
#  FILTER: Encrypted DNS -> REJECT (except KAHF)
# ---------------------------------

:local ftRule [/ip firewall filter find where action=fasttrack-connection chain=forward]

:if ([:len $ftRule] > 0) do={
    /ip firewall filter add chain=forward protocol=tcp dst-port=853 src-address-list=$clientList \
        dst-address-list=$notSafeList action=reject reject-with=tcp-reset \
        comment="KAHF-DNS: Reject DoT" place-before=$ftRule
    /ip firewall filter add chain=forward protocol=udp dst-port=853 src-address-list=$clientList \
        dst-address-list=$notSafeList action=reject reject-with=icmp-network-unreachable \
        comment="KAHF-DNS: Reject DoQ" place-before=$ftRule
    /ip firewall filter add chain=forward protocol=udp dst-port=443 src-address-list=$clientList \
        dst-address-list=$notSafeList action=reject reject-with=icmp-network-unreachable \
        comment="KAHF-DNS: Reject QUIC/DoH3" place-before=$ftRule
    /ip firewall filter add chain=forward protocol=tcp dst-port=443 src-address-list=$clientList \
        dst-address-list=DoH_Providers action=reject reject-with=tcp-reset \
        comment="KAHF-DNS: Reject DoH" place-before=$ftRule
} else={
    /ip firewall filter add chain=forward protocol=tcp dst-port=853 src-address-list=$clientList \
        dst-address-list=$notSafeList action=reject reject-with=tcp-reset \
        comment="KAHF-DNS: Reject DoT"
    /ip firewall filter add chain=forward protocol=udp dst-port=853 src-address-list=$clientList \
        dst-address-list=$notSafeList action=reject reject-with=icmp-network-unreachable \
        comment="KAHF-DNS: Reject DoQ"
    /ip firewall filter add chain=forward protocol=udp dst-port=443 src-address-list=$clientList \
        dst-address-list=$notSafeList action=reject reject-with=icmp-network-unreachable \
        comment="KAHF-DNS: Reject QUIC/DoH3"
    /ip firewall filter add chain=forward protocol=tcp dst-port=443 src-address-list=$clientList \
        dst-address-list=DoH_Providers action=reject reject-with=tcp-reset \
        comment="KAHF-DNS: Reject DoH"
}


# ---------------------------------
#  FILTER: VPN Protocol Blocking
# ---------------------------------

:if ($blockVPN) do={

:global ftRule2 [/ip firewall filter find where action=fasttrack-connection chain=forward]

:if ([:len $ftRule2] > 0) do={
    /ip firewall filter add chain=forward protocol=udp dst-port=1194 src-address-list=$clientList action=reject reject-with=icmp-network-unreachable comment="KAHF-VPN: Block OpenVPN UDP" place-before=$ftRule2
    /ip firewall filter add chain=forward protocol=tcp dst-port=1194 src-address-list=$clientList action=reject reject-with=tcp-reset comment="KAHF-VPN: Block OpenVPN TCP" place-before=$ftRule2
    /ip firewall filter add chain=forward protocol=udp dst-port=1195-1198 src-address-list=$clientList action=reject reject-with=icmp-network-unreachable comment="KAHF-VPN: Block OpenVPN Alt Ports" place-before=$ftRule2
    /ip firewall filter add chain=forward protocol=udp dst-port=51820 src-address-list=$clientList action=reject reject-with=icmp-network-unreachable comment="KAHF-VPN: Block WireGuard" place-before=$ftRule2
    /ip firewall filter add chain=forward protocol=udp dst-port=500 src-address-list=$clientList action=reject reject-with=icmp-network-unreachable comment="KAHF-VPN: Block IKEv2" place-before=$ftRule2
    /ip firewall filter add chain=forward protocol=udp dst-port=4500 src-address-list=$clientList action=reject reject-with=icmp-network-unreachable comment="KAHF-VPN: Block IPSec NAT-T" place-before=$ftRule2
    /ip firewall filter add chain=forward protocol=tcp dst-port=1723 src-address-list=$clientList action=reject reject-with=tcp-reset comment="KAHF-VPN: Block PPTP" place-before=$ftRule2
    /ip firewall filter add chain=forward protocol=gre src-address-list=$clientList action=drop comment="KAHF-VPN: Block GRE" place-before=$ftRule2
    /ip firewall filter add chain=forward protocol=udp dst-port=1701 src-address-list=$clientList action=reject reject-with=icmp-network-unreachable comment="KAHF-VPN: Block L2TP" place-before=$ftRule2
    /ip firewall filter add chain=forward protocol=tcp dst-port=8388 src-address-list=$clientList action=reject reject-with=tcp-reset comment="KAHF-VPN: Block Shadowsocks TCP" place-before=$ftRule2
    /ip firewall filter add chain=forward protocol=udp dst-port=8388 src-address-list=$clientList action=reject reject-with=icmp-network-unreachable comment="KAHF-VPN: Block Shadowsocks UDP" place-before=$ftRule2
    /ip firewall filter add chain=forward protocol=udp dst-port=41641 src-address-list=$clientList action=reject reject-with=icmp-network-unreachable comment="KAHF-VPN: Block Tailscale" place-before=$ftRule2
    /ip firewall filter add chain=forward protocol=udp dst-port=9993 src-address-list=$clientList action=reject reject-with=icmp-network-unreachable comment="KAHF-VPN: Block ZeroTier" place-before=$ftRule2
    /ip firewall filter add chain=forward protocol=tcp dst-port=992 src-address-list=$clientList action=reject reject-with=tcp-reset comment="KAHF-VPN: Block SoftEther" place-before=$ftRule2
    /ip firewall filter add chain=forward protocol=tcp dst-port=5555 src-address-list=$clientList action=reject reject-with=tcp-reset comment="KAHF-VPN: Block SoftEther Alt" place-before=$ftRule2
} else={
    /ip firewall filter add chain=forward protocol=udp dst-port=1194 src-address-list=$clientList action=reject reject-with=icmp-network-unreachable comment="KAHF-VPN: Block OpenVPN UDP"
    /ip firewall filter add chain=forward protocol=tcp dst-port=1194 src-address-list=$clientList action=reject reject-with=tcp-reset comment="KAHF-VPN: Block OpenVPN TCP"
    /ip firewall filter add chain=forward protocol=udp dst-port=1195-1198 src-address-list=$clientList action=reject reject-with=icmp-network-unreachable comment="KAHF-VPN: Block OpenVPN Alt Ports"
    /ip firewall filter add chain=forward protocol=udp dst-port=51820 src-address-list=$clientList action=reject reject-with=icmp-network-unreachable comment="KAHF-VPN: Block WireGuard"
    /ip firewall filter add chain=forward protocol=udp dst-port=500 src-address-list=$clientList action=reject reject-with=icmp-network-unreachable comment="KAHF-VPN: Block IKEv2"
    /ip firewall filter add chain=forward protocol=udp dst-port=4500 src-address-list=$clientList action=reject reject-with=icmp-network-unreachable comment="KAHF-VPN: Block IPSec NAT-T"
    /ip firewall filter add chain=forward protocol=tcp dst-port=1723 src-address-list=$clientList action=reject reject-with=tcp-reset comment="KAHF-VPN: Block PPTP"
    /ip firewall filter add chain=forward protocol=gre src-address-list=$clientList action=drop comment="KAHF-VPN: Block GRE"
    /ip firewall filter add chain=forward protocol=udp dst-port=1701 src-address-list=$clientList action=reject reject-with=icmp-network-unreachable comment="KAHF-VPN: Block L2TP"
    /ip firewall filter add chain=forward protocol=tcp dst-port=8388 src-address-list=$clientList action=reject reject-with=tcp-reset comment="KAHF-VPN: Block Shadowsocks TCP"
    /ip firewall filter add chain=forward protocol=udp dst-port=8388 src-address-list=$clientList action=reject reject-with=icmp-network-unreachable comment="KAHF-VPN: Block Shadowsocks UDP"
    /ip firewall filter add chain=forward protocol=udp dst-port=41641 src-address-list=$clientList action=reject reject-with=icmp-network-unreachable comment="KAHF-VPN: Block Tailscale"
    /ip firewall filter add chain=forward protocol=udp dst-port=9993 src-address-list=$clientList action=reject reject-with=icmp-network-unreachable comment="KAHF-VPN: Block ZeroTier"
    /ip firewall filter add chain=forward protocol=tcp dst-port=992 src-address-list=$clientList action=reject reject-with=tcp-reset comment="KAHF-VPN: Block SoftEther"
    /ip firewall filter add chain=forward protocol=tcp dst-port=5555 src-address-list=$clientList action=reject reject-with=tcp-reset comment="KAHF-VPN: Block SoftEther Alt"
}

}


# ---------------------------------
#  FILTER: TOR Network Blocking
# ---------------------------------

:if ($blockTOR) do={

:global ftRule3 [/ip firewall filter find where action=fasttrack-connection chain=forward]

:if ([:len $ftRule3] > 0) do={
    /ip firewall filter add chain=forward protocol=tcp dst-port=9001 src-address-list=$clientList action=reject reject-with=tcp-reset comment="KAHF-TOR: Block ORPort TCP" place-before=$ftRule3
    /ip firewall filter add chain=forward protocol=udp dst-port=9001 src-address-list=$clientList action=reject reject-with=icmp-network-unreachable comment="KAHF-TOR: Block ORPort UDP" place-before=$ftRule3
    /ip firewall filter add chain=forward protocol=tcp dst-port=9030 src-address-list=$clientList action=reject reject-with=tcp-reset comment="KAHF-TOR: Block DirPort" place-before=$ftRule3
    /ip firewall filter add chain=forward protocol=tcp dst-port=9050 src-address-list=$clientList action=reject reject-with=tcp-reset comment="KAHF-TOR: Block SOCKS" place-before=$ftRule3
    /ip firewall filter add chain=forward protocol=tcp dst-port=9051 src-address-list=$clientList action=reject reject-with=tcp-reset comment="KAHF-TOR: Block Control" place-before=$ftRule3
    /ip firewall filter add chain=forward protocol=tcp dst-port=9150-9151 src-address-list=$clientList action=reject reject-with=tcp-reset comment="KAHF-TOR: Block Browser" place-before=$ftRule3
} else={
    /ip firewall filter add chain=forward protocol=tcp dst-port=9001 src-address-list=$clientList action=reject reject-with=tcp-reset comment="KAHF-TOR: Block ORPort TCP"
    /ip firewall filter add chain=forward protocol=udp dst-port=9001 src-address-list=$clientList action=reject reject-with=icmp-network-unreachable comment="KAHF-TOR: Block ORPort UDP"
    /ip firewall filter add chain=forward protocol=tcp dst-port=9030 src-address-list=$clientList action=reject reject-with=tcp-reset comment="KAHF-TOR: Block DirPort"
    /ip firewall filter add chain=forward protocol=tcp dst-port=9050 src-address-list=$clientList action=reject reject-with=tcp-reset comment="KAHF-TOR: Block SOCKS"
    /ip firewall filter add chain=forward protocol=tcp dst-port=9051 src-address-list=$clientList action=reject reject-with=tcp-reset comment="KAHF-TOR: Block Control"
    /ip firewall filter add chain=forward protocol=tcp dst-port=9150-9151 src-address-list=$clientList action=reject reject-with=tcp-reset comment="KAHF-TOR: Block Browser"
}

}


:log info ("KahfGuard DNS enforcement loaded: 53->" . $forwarderRange . ", 853/443u->KAHF only, DoH IPs blocked, TOR ports blocked")

# Cleanup globals
:set forwarderStart
:set forwarderEnd
:set safeList
:set clientList
:set blockVPN
:set blockTOR
:set forwarderRange
:set notSafeList
:set ftRule2
:set ftRule3
