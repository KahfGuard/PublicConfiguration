# Router Config Deployment

Centralized deployment of KahfGuard DNS filtering config to ISP MikroTik routers via GitHub Actions.

## Architecture

```
GitHub Repo (router-config/*.rsc)
        │
        ▼
GitHub Actions (deploy-router-config.yml)
        │
        ├── SSH to Router 1 ──▶ /import file=kahf-dns-v2.rsc
        ├── SSH to Router 2 ──▶ /import file=kahf-dns-v2.rsc
        └── SSH to Router N ──▶ /import file=kahf-dns-v2.rsc
```

## How It Works

1. **Push to `main`** — Changes to `router-config/` trigger automatic deployment
2. **Manual dispatch** — Deploy to specific environments (test/staging/production)
3. **Idempotent** — Cleanup script removes old rules before importing new ones
4. **Rollback** — Restore previous config from backup

## Setup

### 1. Add Router to Inventory

Edit `router-inventory.yml`:

```yaml
routers:
  - name: "isp-dhaka"
    host: "${{ secrets.ROUTER_ISP_DHAKA_HOST }}"
    ssh_key: "${{ secrets.ROUTER_ISP_DHAKA_SSH_KEY }}"
    user: "${{ secrets.ROUTER_ISP_DHAKA_USER || 'admin' }}"
    port: "${{ secrets.ROUTER_ISP_DHAKA_PORT || '22' }}"
    tags: ["production", "dhaka"]
```

### 2. Add GitHub Secrets

For each router, add these secrets in GitHub → Settings → Secrets:

| Secret | Description |
|--------|-------------|
| `ROUTER_<NAME>_HOST` | Router IP address |
| `ROUTER_<NAME>_SSH_KEY` | SSH private key (full PEM/OPENSSH) |
| `ROUTER_<NAME>_USER` | SSH username (default: admin) |
| `ROUTER_<NAME>_PORT` | SSH port (default: 22) |

**Example:**
```
ROUTER_ISP_DHAKA_HOST     = 103.25.100.1
ROUTER_ISP_DHAKA_SSH_KEY  = -----BEGIN OPENSSH PRIVATE KEY-----\n...
ROUTER_ISP_DHAKA_USER     = admin
ROUTER_ISP_DHAKA_PORT     = 22
```

### 3. Generate SSH Key for Router

```bash
# Generate ed25519 key (recommended)
ssh-keygen -t ed25519 -f ~/.ssh/mikrotik_deploy -C "kahfguard-deploy"

# Copy public key to router
scp ~/.ssh/mikrotik_deploy.pub admin@ROUTER_IP:/
ssh admin@ROUTER_IP "/user ssh-keys import public-key-file=mikrotik_deploy.pub user=admin"
```

## Deployment

### Automatic (on push)
```bash
git push origin main
# GitHub Actions deploys to all routers in inventory
```

### Manual
1. Go to GitHub → Actions → Deploy Router Config
2. Click "Run workflow"
3. Select environment (test/staging/production)
4. Optionally enable dry-run or rollback
5. Click "Run workflow"

### Manual (CLI)
```bash
# Deploy to a specific router
./scripts/deploy-router.sh \
  --host 103.25.100.1 \
  --ssh-key ~/.ssh/mikrotik_deploy \
  --cleanup \
  --verify

# Dry run
./scripts/deploy-router.sh \
  --host 103.25.100.1 \
  --ssh-key ~/.ssh/mikrotik_deploy \
  --dry-run

# Rollback
./scripts/deploy-router.sh \
  --host 103.25.100.1 \
  --ssh-key ~/.ssh/mikrotik_deploy \
  --rollback
```

## Idempotency

Both scripts are idempotent:

1. **Cleanup script** (`forwarder-router-cleanup.rsc`)
   - Removes ALL `KAHF-*` rules and address lists
   - Safe to run multiple times (no-op if nothing to remove)

2. **v2 config** (`forwarder-router-dns-v2.rsc`)
   - Starts with cleanup (removes old rules before importing)
   - Safe to run multiple times

**Deployment flow:**
```
SSH to router → Upload scripts → Run cleanup → Import v2 → Verify
```

## Rollback

If deployment fails:

```bash
# Rollback via script
./scripts/deploy-router.sh \
  --host 103.25.100.1 \
  --ssh-key ~/.ssh/mikrotik_deploy \
  --rollback

# Or rollback via GitHub Actions
# Actions → Deploy Router Config → Run workflow → Check "Rollback"
```

## Monitoring

After deployment, verify on router:

```bash
# Check DNS rules
/ip firewall nat print where comment~"DNS to Core"
/ip firewall filter print where comment~"KAHF-DNS"

# Check VPN rules
/ip firewall filter print where comment~"KAHF-VPN"

# Check TOR rules
/ip firewall filter print where comment~"KAHF-TOR"

# Check DoH blocklist
/ip firewall address-list print where list=DoH_Providers

# Check IPv6 rules
/ipv6 firewall nat print where comment~"DNS to Core"
/ipv6 firewall filter print where comment~"KAHF-DNS"
```
