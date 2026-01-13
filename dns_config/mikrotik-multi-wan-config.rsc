# MikroTik Multi-WAN Configuration
# ==================================
# Triple WAN with per-port routing and static IP ingress
#
# BEFORE RUNNING:
# 1. Update BDCOM_USERNAME and BDCOM_PASSWORD
# 2. Update JUMP_HOST_IP (default: 10.0.0.100)
# 3. Update WEB_SERVER_IP (default: 10.0.0.100)
#
# AFTER UPDATING CREDENTIALS:
# 1. Enable BDCOM PPPoE: /interface pppoe-client enable BDCOM
# 2. Enable BDCOM routes: /ip route enable [find where comment~"BDCOM"]
# 3. Enable ingress rules: /ip firewall filter enable [find where comment~"INGRESS"]
# 4. Enable dst-nat rules: /ip firewall nat enable [find where comment~"DNAT"]

# ============================================
# NETWORK TOPOLOGY
# ============================================
#
# WAN Interfaces:
#   ether1 → DOT (PPPoE)     - IPv6 + Failover
#   ether2 → MAZEDA (PPPoE)  - ether4 primary, last resort
#   ether3 → BDCOM (PPPoE)   - Primary IPv4, static IP, ingress
#
# LAN Interfaces:
#   ether4 → Media/TV AP     - Routes via MAZEDA → DOT
#   ether5 → Work AP         - Routes via BDCOM → DOT → MAZEDA + IPv6
#
# Ingress via BDCOM:
#   :22   → Router SSH
#   :2222 → Jump host SSH
#   :80   → Web server HTTP
#   :443  → Web server HTTPS

# ============================================
# PLACEHOLDER VARIABLES (UPDATE THESE)
# ============================================
# BDCOM_USERNAME = your_bdcom_username
# BDCOM_PASSWORD = your_bdcom_password
# JUMP_HOST_IP   = 10.0.0.100
# WEB_SERVER_IP  = 10.0.0.100

# ============================================
# PHASE 1: BDCOM WAN INTERFACE
# ============================================

# Remove ether3 from bridge (if in bridge)
/interface bridge port remove [find where interface=ether3]

# Create BDCOM PPPoE client (DISABLED - update credentials first)
/interface pppoe-client
remove [find where name=BDCOM]
add name=BDCOM interface=ether3 \
    user="BDCOM_USERNAME" password="BDCOM_PASSWORD" \
    add-default-route=no use-peer-dns=no disabled=yes \
    comment="BDCOM - Update credentials and enable"

# Add BDCOM masquerade NAT
/ip firewall nat
remove [find where comment="BDCOM masquerade"]
add chain=srcnat out-interface=BDCOM action=masquerade \
    comment="BDCOM masquerade"

# ============================================
# PHASE 2: WAN PRIORITY ROUTES
# ============================================

/ip route
# BDCOM as primary (DISABLED until credentials set)
remove [find where comment~"PRIMARY: BDCOM"]
add dst-address=0.0.0.0/0 gateway=BDCOM distance=1 disabled=yes \
    comment="PRIMARY: BDCOM - enable when credentials set"

# Update existing DOT route
set [find where gateway=DOT and dst-address=0.0.0.0/0 and routing-mark=""] \
    distance=2 comment="SECONDARY: DOT (IPv6 + failover)"

# Update existing MAZEDA route
set [find where gateway=MAZEDA and dst-address=0.0.0.0/0 and routing-mark=""] \
    distance=3 comment="FAILOVER: MAZEDA (last resort)"

# ============================================
# PHASE 3: PER-PORT ROUTING
# ============================================

# Enable bridge IP firewall (required for in-bridge-port matching)
/interface bridge settings set use-ip-firewall=yes

# Mangle rules for connection marking
/ip firewall mangle
remove [find where comment~"PBR: ether"]

# ether4 → MAZEDA
add chain=prerouting in-bridge-port=ether4 connection-mark=no-mark \
    action=mark-connection new-connection-mark=wan_mazeda passthrough=no \
    comment="PBR: ether4 → MAZEDA"

# ether5 → BDCOM
add chain=prerouting in-bridge-port=ether5 connection-mark=no-mark \
    action=mark-connection new-connection-mark=wan_bdcom passthrough=no \
    comment="PBR: ether5 → BDCOM"

# Routing-mark routes
/ip route
remove [find where comment~"PBR: wan_mazeda" or comment~"PBR: wan_bdcom"]

# wan_mazeda: MAZEDA primary, DOT failover
add dst-address=0.0.0.0/0 gateway=MAZEDA routing-mark=wan_mazeda distance=1 \
    comment="PBR: wan_mazeda via MAZEDA"
add dst-address=0.0.0.0/0 gateway=DOT routing-mark=wan_mazeda distance=2 \
    comment="PBR: wan_mazeda failover to DOT"

# wan_bdcom: BDCOM primary, DOT failover, MAZEDA last resort
add dst-address=0.0.0.0/0 gateway=BDCOM routing-mark=wan_bdcom distance=1 \
    disabled=yes comment="PBR: wan_bdcom via BDCOM - enable when ready"
add dst-address=0.0.0.0/0 gateway=DOT routing-mark=wan_bdcom distance=2 \
    comment="PBR: wan_bdcom failover to DOT"
add dst-address=0.0.0.0/0 gateway=MAZEDA routing-mark=wan_bdcom distance=3 \
    comment="PBR: wan_bdcom last resort MAZEDA"

# ============================================
# PHASE 4: INGRESS RULES (via BDCOM)
# ============================================

# Firewall filter - accept ingress (DISABLED until BDCOM active)
/ip firewall filter
remove [find where comment~"INGRESS:"]

add chain=input protocol=tcp dst-port=22 in-interface=BDCOM action=accept \
    disabled=yes comment="INGRESS: Allow SSH to router via BDCOM"
add chain=forward protocol=tcp dst-port=2222 in-interface=BDCOM action=accept \
    disabled=yes comment="INGRESS: Allow SSH to jump host via BDCOM"
add chain=forward protocol=tcp dst-port=80 in-interface=BDCOM action=accept \
    disabled=yes comment="INGRESS: Allow HTTP to web server via BDCOM"
add chain=forward protocol=tcp dst-port=443 in-interface=BDCOM action=accept \
    disabled=yes comment="INGRESS: Allow HTTPS to web server via BDCOM"

# NAT dst-nat for port forwarding (DISABLED - update IPs first)
/ip firewall nat
remove [find where comment~"DNAT:"]

# Port 2222 → Jump host SSH (UPDATE to-addresses!)
add chain=dstnat in-interface=BDCOM protocol=tcp dst-port=2222 \
    action=dst-nat to-addresses=10.0.0.100 to-ports=22 \
    disabled=yes comment="DNAT: 2222 → Jump host SSH (update IP)"

# Port 80 → Web server HTTP (UPDATE to-addresses!)
add chain=dstnat in-interface=BDCOM protocol=tcp dst-port=80 \
    action=dst-nat to-addresses=10.0.0.100 to-ports=80 \
    disabled=yes comment="DNAT: 80 → Web server HTTP (update IP)"

# Port 443 → Web server HTTPS (UPDATE to-addresses!)
add chain=dstnat in-interface=BDCOM protocol=tcp dst-port=443 \
    action=dst-nat to-addresses=10.0.0.100 to-ports=443 \
    disabled=yes comment="DNAT: 443 → Web server HTTPS (update IP)"

# ============================================
# PHASE 5: IPv6 (via DOT)
# ============================================

# Disable peer DNS on IPv6 DHCP client
/ipv6 dhcp-client set [find where interface=DOT] use-peer-dns=no

# ============================================
# ACTIVATION COMMANDS (RUN AFTER SETTING CREDENTIALS)
# ============================================
#
# Step 1: Update BDCOM credentials
#   /interface pppoe-client set BDCOM user="real_username" password="real_password"
#
# Step 2: Enable BDCOM interface
#   /interface pppoe-client enable BDCOM
#
# Step 3: Wait for BDCOM to connect, verify with:
#   /interface pppoe-client print where name=BDCOM
#   /ping 8.8.8.8 interface=BDCOM count=3
#
# Step 4: Enable BDCOM routes
#   /ip route enable [find where comment~"BDCOM" and disabled=yes]
#
# Step 5: Update dst-nat IPs (replace 10.0.0.100 with actual server IP)
#   /ip firewall nat set [find where comment~"DNAT:"] to-addresses=<YOUR_SERVER_IP>
#
# Step 6: Enable ingress rules
#   /ip firewall filter enable [find where comment~"INGRESS:"]
#   /ip firewall nat enable [find where comment~"DNAT:"]
#
# Step 7: Test ingress (from external network)
#   ssh -p 22 <BDCOM_STATIC_IP>     # Router SSH
#   ssh -p 2222 <BDCOM_STATIC_IP>   # Jump host SSH
#   curl http://<BDCOM_STATIC_IP>   # Web server

# ============================================
# VERIFICATION COMMANDS
# ============================================
#
# Check WAN status:
#   /interface pppoe-client print
#   /ip route print where dst-address=0.0.0.0/0
#
# Check per-port routing:
#   /ip firewall mangle print where comment~"PBR"
#   /ip route print where comment~"PBR"
#
# Check ingress rules:
#   /ip firewall filter print where comment~"INGRESS"
#   /ip firewall nat print where comment~"DNAT"
#
# Test connectivity per interface:
#   /ping 8.8.8.8 interface=BDCOM count=3
#   /ping 8.8.8.8 interface=DOT count=3
#   /ping 8.8.8.8 interface=MAZEDA count=3
