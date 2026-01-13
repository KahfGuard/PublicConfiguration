# MikroTik Multi-WAN Architecture Plan

## Overview

Triple WAN setup with per-port routing and ingress via static IP.

## WAN Interfaces

| WAN | Interface | Physical | Type | Role |
|-----|-----------|----------|------|------|
| BDCOM | PPPoE | ether3 | Static IP | Primary IPv4, Ingress |
| DOT | PPPoE | ether1 | Dynamic | IPv6 + Failover |
| MAZEDA | PPPoE | ether2 | Dynamic | ether4 primary, last failover |

## LAN Interfaces

| Port | Use | IPv4 Routing | IPv6 |
|------|-----|--------------|------|
| ether4 | TV/Media AP | MAZEDA → DOT | None |
| ether5 | Work AP | BDCOM → DOT → MAZEDA | DOT |

## Traffic Flow

### Outbound

```
ether4 (Media):
  IPv4: MAZEDA (primary) → DOT (failover)
  IPv6: None

ether5 (Work):
  IPv4: BDCOM (primary) → DOT (failover) → MAZEDA (last resort)
  IPv6: DOT
```

### Inbound (via BDCOM Static IP)

| External Port | Destination | Purpose |
|---------------|-------------|---------|
| 22 | Router (10.0.0.1) | Router SSH |
| 2222 | Jump Host (TBD) | Server SSH |
| 80 | Web Server (TBD) | HTTP |
| 443 | Web Server (TBD) | HTTPS |

## Implementation Phases

### Phase 1: Add BDCOM WAN

```routeros
# Remove ether3 from bridge
/interface bridge port remove [find where interface=ether3]

# Create BDCOM PPPoE
/interface pppoe-client add name=BDCOM interface=ether3 \
    user="<username>" password="<password>" \
    add-default-route=no use-peer-dns=no disabled=no

# Add masquerade NAT
/ip firewall nat add chain=srcnat out-interface=BDCOM action=masquerade \
    comment="BDCOM masquerade"
```

### Phase 2: WAN Priority Routes

```routeros
# Set route distances (lower = preferred)
/ip route
add dst-address=0.0.0.0/0 gateway=BDCOM distance=1 comment="Primary: BDCOM"
# Modify existing DOT route
set [find where gateway=DOT and dst-address=0.0.0.0/0] distance=2 comment="Secondary: DOT"
# Modify existing MAZEDA route
set [find where gateway=MAZEDA and dst-address=0.0.0.0/0] distance=3 comment="Failover: MAZEDA"
```

### Phase 3: Per-Port Routing

```routeros
# Enable bridge firewall (required for in-bridge-port matching)
/interface bridge settings set use-ip-firewall=yes

# Connection marks for each WAN
# ether4 → MAZEDA
/ip firewall mangle add chain=prerouting in-bridge-port=ether4 \
    connection-mark=no-mark action=mark-connection \
    new-connection-mark=wan_mazeda passthrough=no \
    comment="ether4 → MAZEDA"

# ether5 → BDCOM
/ip firewall mangle add chain=prerouting in-bridge-port=ether5 \
    connection-mark=no-mark action=mark-connection \
    new-connection-mark=wan_bdcom passthrough=no \
    comment="ether5 → BDCOM"

# Routing mark routes
/ip route
add dst-address=0.0.0.0/0 gateway=MAZEDA routing-mark=wan_mazeda distance=1 \
    comment="PBR: wan_mazeda via MAZEDA"
add dst-address=0.0.0.0/0 gateway=DOT routing-mark=wan_mazeda distance=2 \
    comment="PBR: wan_mazeda failover to DOT"

add dst-address=0.0.0.0/0 gateway=BDCOM routing-mark=wan_bdcom distance=1 \
    comment="PBR: wan_bdcom via BDCOM"
add dst-address=0.0.0.0/0 gateway=DOT routing-mark=wan_bdcom distance=2 \
    comment="PBR: wan_bdcom failover to DOT"
add dst-address=0.0.0.0/0 gateway=MAZEDA routing-mark=wan_bdcom distance=3 \
    comment="PBR: wan_bdcom last resort MAZEDA"
```

### Phase 4: Ingress Rules (BDCOM Static IP)

```routeros
# Variables - update when known
# BDCOM_IP = <static-ip>
# JUMP_HOST = <internal-ip>
# WEB_SERVER = <internal-ip>

# Firewall - accept ingress
/ip firewall filter
add chain=input protocol=tcp dst-port=22 in-interface=BDCOM action=accept \
    comment="Allow SSH to router via BDCOM"
add chain=forward protocol=tcp dst-port=2222 in-interface=BDCOM action=accept \
    comment="Allow SSH to jump host via BDCOM"
add chain=forward protocol=tcp dst-port=80,443 in-interface=BDCOM action=accept \
    comment="Allow HTTP/HTTPS to web server via BDCOM"

# NAT - dst-nat for port forwarding
/ip firewall nat
add chain=dstnat in-interface=BDCOM protocol=tcp dst-port=2222 \
    action=dst-nat to-addresses=<JUMP_HOST> to-ports=22 \
    comment="DNAT: 2222 → Jump host SSH"
add chain=dstnat in-interface=BDCOM protocol=tcp dst-port=80 \
    action=dst-nat to-addresses=<WEB_SERVER> to-ports=80 \
    comment="DNAT: 80 → Web server"
add chain=dstnat in-interface=BDCOM protocol=tcp dst-port=443 \
    action=dst-nat to-addresses=<WEB_SERVER> to-ports=443 \
    comment="DNAT: 443 → Web server"
```

### Phase 5: IPv6 for ether5

```routeros
# Assuming DOT provides DHCPv6-PD
# Get prefix from DOT
/ipv6 dhcp-client add interface=DOT request=prefix pool-name=dot-pool \
    add-default-route=yes use-peer-dns=no

# Assign /64 from pool to bridge (for ether5 clients)
/ipv6 address add interface=bridge from-pool=dot-pool

# Enable neighbor discovery
/ipv6 nd set [find interface=bridge] advertise-dns=yes
```

## Netwatch for Faster Failover

```routeros
# Monitor BDCOM connectivity
/tool netwatch add host=8.8.8.8 interval=10s timeout=2s \
    up-script="" down-script="/log warning \"BDCOM appears down\""

# Monitor DOT connectivity
/tool netwatch add host=1.1.1.1 interval=10s timeout=2s \
    up-script="" down-script="/log warning \"DOT appears down\""
```

## Drawbacks & Considerations

### Performance
- Bridge fast-path disabled (higher CPU)
- Triple PPPoE overhead

### Reliability
- Ingress only via BDCOM (no failover for external access)
- IPv6 only via DOT
- Failover not instant (5-30 sec)

### Complexity
- Complex mangle rules
- Harder to troubleshoot
- Future changes need care

## Checklist

- [ ] BDCOM PPPoE credentials obtained
- [ ] BDCOM static IP known
- [ ] Jump host internal IP decided
- [ ] Web server internal IP decided
- [ ] Phase 1 implemented
- [ ] Phase 2 implemented
- [ ] Phase 3 implemented
- [ ] Phase 4 implemented
- [ ] Phase 5 implemented
- [ ] Failover tested
- [ ] Ingress tested
- [ ] IPv6 tested
