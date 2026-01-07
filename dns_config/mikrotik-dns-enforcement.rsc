# MikroTik DNS Enforcement Configuration
# ========================================
# This script configures:
# 1. DNS servers (Kahf DNS - IPv4 and IPv6)
# 2. Address lists for allowed DNS providers
# 3. NAT rules to redirect all DNS queries to router
# 4. Firewall rules to block DoT (853) and DoH/QUIC (443/udp) bypass attempts
#
# Usage: /import file-name=mikrotik-dns-enforcement.rsc
#
# Note: Review and adjust interface names (e.g., "bridge" in NAT rules) as needed

# ============================================
# SECTION 1: Address Lists for Allowed DNS
# ============================================

/ip firewall address-list

# Kahf DNS IPv4 Servers
add address=203.190.10.114 list=allowed-dns-servers comment="Kahf DNS Primary"
add address=203.190.10.115 list=allowed-dns-servers comment="Kahf DNS Secondary"
add address=203.190.10.124 list=allowed-dns-servers comment="Kahf DNS Tertiary"

# Allowed DNS Provider Ranges (IPv4)
add address=203.190.10.112/28 list=allowed-dns-providers comment="Kahf DNS Network"
add address=40.120.32.128/26 list=allowed-dns-providers comment="Azure DNS Network"

/ipv6 firewall address-list

# Kahf DNS IPv6 Servers
add address=2400:fa40:400:1::105a list=allowed-dns-servers-v6 comment="Kahf DNS IPv6 Primary"
add address=2400:fa40:400:1::106a list=allowed-dns-servers-v6 comment="Kahf DNS IPv6 Secondary"
add address=2400:fa40:400:1::104a list=allowed-dns-servers-v6 comment="Kahf DNS IPv6 Tertiary"

# Allowed DNS Provider Ranges (IPv6)
add address=2400:fa40:400:1::/64 list=allowed-dns-providers-v6 comment="Kahf DNS IPv6 Network"


# ============================================
# SECTION 2: DNS Server Configuration
# ============================================

/ip dns set allow-remote-requests=yes servers=203.190.10.114,203.190.10.115,203.190.10.124


# ============================================
# SECTION 3: NAT Rules - Force DNS to Router
# ============================================

/ip firewall nat

# Redirect all DNS (UDP 53) to router - forces all clients through router DNS
add chain=dstnat protocol=udp dst-port=53 action=redirect to-ports=53 \
    comment="Force DNS UDP to router"

# Redirect all DNS (TCP 53) to router - forces all clients through router DNS
add chain=dstnat protocol=tcp dst-port=53 action=redirect to-ports=53 \
    comment="Force DNS TCP to router"


# ============================================
# SECTION 4: IPv4 Firewall Rules - Block DoT/DoH Bypass
# ============================================

/ip firewall filter

# Accept DoT to allowed providers
add chain=forward protocol=tcp dst-port=853 dst-address-list=allowed-dns-providers \
    action=accept comment="Allow DoT TCP to trusted DNS providers"

add chain=forward protocol=udp dst-port=853 dst-address-list=allowed-dns-providers \
    action=accept comment="Allow DoT UDP to trusted DNS providers"

# Accept QUIC/DoH to allowed providers
add chain=forward protocol=udp dst-port=443 dst-address-list=allowed-dns-providers \
    action=accept comment="Allow QUIC/DoH to trusted DNS providers"

# Drop all other DoT traffic (TCP 853)
add chain=forward protocol=tcp dst-port=853 action=drop \
    comment="Block DoT TCP bypass attempts"

# Drop all other DoT traffic (UDP 853)
add chain=forward protocol=udp dst-port=853 action=drop \
    comment="Block DoT UDP bypass attempts"

# Drop all other QUIC/DoH traffic (UDP 443)
add chain=forward protocol=udp dst-port=443 action=drop \
    comment="Block QUIC/DoH bypass attempts"


# ============================================
# SECTION 5: IPv6 Firewall Rules - Block DoT/DoH Bypass
# ============================================

/ipv6 firewall filter

# Accept DoT to allowed providers
add chain=forward protocol=tcp dst-port=853 dst-address-list=allowed-dns-providers-v6 \
    action=accept comment="Allow DoT TCP to trusted DNS providers (IPv6)"

add chain=forward protocol=udp dst-port=853 dst-address-list=allowed-dns-providers-v6 \
    action=accept comment="Allow DoT UDP to trusted DNS providers (IPv6)"

# Accept QUIC/DoH to allowed providers
add chain=forward protocol=udp dst-port=443 dst-address-list=allowed-dns-providers-v6 \
    action=accept comment="Allow QUIC/DoH to trusted DNS providers (IPv6)"

# Drop all other DoT traffic (TCP 853)
add chain=forward protocol=tcp dst-port=853 action=drop \
    comment="Block DoT TCP bypass attempts (IPv6)"

# Drop all other DoT traffic (UDP 853)
add chain=forward protocol=udp dst-port=853 action=drop \
    comment="Block DoT UDP bypass attempts (IPv6)"

# Drop all other QUIC/DoH traffic (UDP 443)
add chain=forward protocol=udp dst-port=443 action=drop \
    comment="Block QUIC/DoH bypass attempts (IPv6)"


# ============================================
# END OF CONFIGURATION
# ============================================
# To verify configuration after import:
#   /ip dns print
#   /ip firewall address-list print where list~"dns"
#   /ip firewall nat print where comment~"DNS"
#   /ip firewall filter print where comment~"DoT" or comment~"DoH" or comment~"QUIC"
#   /ipv6 firewall address-list print where list~"dns"
#   /ipv6 firewall filter print where comment~"DoT" or comment~"DoH" or comment~"QUIC"
