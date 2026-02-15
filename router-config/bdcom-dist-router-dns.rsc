# =============================================
#  Distribution Router - DNS Interception ( BDCOM's Network)
# =============================================
#
#  Port 53         →  Forward to core router
#  Port 853, 443u  →  Allow only to KAHF, drop rest
#
#  Usage   : /import file=dist-router-dns.rsc
# =============================================


# ===== CHANGE THESE PER ISP =====
:local coreRouter "114.31.10.62"
:local clientList "Safe_IP"
# =================================


# ----- KAHF Servers -----

/ip firewall address-list
add list=Bypass_Safe address=203.190.10.112/28  comment="KAHF-BDIX"
add list=Bypass_Safe address=40.120.32.128/26   comment="KAHF-Azure"


# ----- DNS (port 53) → Core Router -----

/ip firewall nat
add chain=dstnat protocol=udp dst-port=53 src-address-list=$clientList \
    action=dst-nat to-addresses=$coreRouter to-ports=53 comment="DNS to Core: UDP"
add chain=dstnat protocol=tcp dst-port=53 src-address-list=$clientList \
    action=dst-nat to-addresses=$coreRouter to-ports=53 comment="DNS to Core: TCP"


# ----- Encrypted DNS → KAHF only, drop rest -----

/ip firewall filter
add chain=forward protocol=tcp dst-port=853 dst-address-list=!Bypass_Safe action=drop comment="Drop DoT"
add chain=forward protocol=udp dst-port=853 dst-address-list=!Bypass_Safe action=drop comment="Drop DoQ"
add chain=forward protocol=udp dst-port=443 dst-address-list=!Bypass_Safe action=drop comment="Drop QUIC"


:log info "Dist DNS: Done. Port 53->core($coreRouter), 853/443u->KAHF only"
