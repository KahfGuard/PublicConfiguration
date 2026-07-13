# =====================================================================
#  Distribution Router -- KahfGuard Cleanup Script
#  VERSION 2.0 — Removes ALL KahfGuard DNS/VPN/TOR rules
# =====================================================================
#
#  This script removes ALL rules created by forwarder-router-dns.rsc
#  (both v1 and v2). Safe to run multiple times (idempotent).
#
#  WARNING: This will disable all KahfGuard filtering!
#  Only run this when you need to:
#    - Upgrade to a new version of the script
#    - Troubleshoot DNS/VPN/TOR issues
#    - Temporarily disable filtering
#
#  Usage: /import file=forwarder-router-cleanup.rsc
# =====================================================================


# ---------------------------------
#  IPv4: Remove all KahfGuard rules
# ---------------------------------

# Remove NAT rules (DNS redirect)
/ip firewall nat remove [find where comment~"DNS to Core"]

# Remove all KahfGuard filter rules
/ip firewall filter remove [find where comment~"KAHF-DNS"]
/ip firewall filter remove [find where comment~"KAHF-VPN"]
/ip firewall filter remove [find where comment~"KAHF-TOR"]
/ip firewall filter remove [find where comment~"Drop Do"]
/ip firewall filter remove [find where comment~"Drop QUIC"]

# Remove all KahfGuard address lists
/ip firewall address-list remove [find where list="Safe_Package_IPs"]
/ip firewall address-list remove [find where list="Bypass_Safe"]
/ip firewall address-list remove [find where list="DoH_Providers"]
/ip firewall address-list remove [find where list="TOR_Relays"]


# ---------------------------------
#  IPv6: Remove all KahfGuard rules
# ---------------------------------

# Remove IPv6 NAT rules (DNS redirect)
/ipv6 firewall nat remove [find where comment~"DNS to Core"]

# Remove all KahfGuard IPv6 filter rules
/ip6 firewall filter remove [find where comment~"KAHF-DNS"]
/ip6 firewall filter remove [find where comment~"KAHF-VPN"]
/ip6 firewall filter remove [find where comment~"KAHF-TOR"]
/ip6 firewall filter remove [find where comment~"Drop Do"]
/ip6 firewall filter remove [find where comment~"Drop QUIC"]

# Remove all KahfGuard IPv6 address lists
/ip6 firewall address-list remove [find where list="Safe_Package_IPs"]
/ip6 firewall address-list remove [find where list="Bypass_Safe"]
/ip6 firewall address-list remove [find where list="DoH_Providers"]
/ip6 firewall address-list remove [find where list="TOR_Relays"]


:log info ("KahfGuard cleanup v2.0 complete: all IPv4+IPv6 DNS/VPN/TOR rules removed")
