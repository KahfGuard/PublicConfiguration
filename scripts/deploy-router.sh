#!/usr/bin/env bash
# =====================================================================
#  Deploy Router Config to MikroTik Routers via SSH
#  VERSION 1.0 — Idempotent deployment with rollback support
# =====================================================================
#
#  Usage:
#    ./deploy-router.sh --host <IP> --ssh-key <KEY_FILE> --user <USER> [OPTIONS]
#
#  Options:
#    --host         Router IP address (required)
#    --ssh-key      Path to SSH private key file (required)
#    --ssh-port     SSH port (default: 22)
#    --user         SSH username (default: admin)
#    --rsc-file     RSC file to deploy (default: router-config/forwarder-router-dns-v2.rsc)
#    --cleanup      Run cleanup script before deploying new config
#    --dry-run      Show what would be done without executing
#    --verify       Verify deployment after import
#    --rollback     Rollback to previous config
#    --timeout      SSH connection timeout in seconds (default: 30)
#
#  Examples:
#    # Deploy v2 config to a router
#    ./deploy-router.sh --host 103.25.100.1 --ssh-key ~/.ssh/mikrotik_ed25519 --cleanup
#
#    # Dry run (show commands without executing)
#    ./deploy-router.sh --host 103.25.100.1 --ssh-key ~/.ssh/mikrotik_ed25519 --dry-run
#
#    # Rollback to previous config
#    ./deploy-router.sh --host 103.25.100.1 --ssh-key ~/.ssh/mikrotik_ed25519 --rollback
#
#  Idempotency:
#    - Cleanup script removes ALL KAHF-* rules before re-importing
#    - Safe to run multiple times (no duplicate rules)
#    - Rollback restores the previous config from backup
# =====================================================================

set -euo pipefail

# ---- Defaults ----
SSH_PORT=22
SSH_USER="admin"
RSC_FILE="router-config/forwarder-router-dns-v2.rsc"
CLEANUP_FILE="router-config/forwarder-router-cleanup.rsc"
CLEANUP=false
DRY_RUN=false
VERIFY=false
ROLLBACK=false
TIMEOUT=30
VERBOSE=false

# ---- Colors ----
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# ---- Logging ----
log_info()    { echo -e "${BLUE}[INFO]${NC}    $*"; }
log_success() { echo -e "${GREEN}[SUCCESS]${NC} $*"; }
log_warn()    { echo -e "${YELLOW}[WARN]${NC}    $*"; }
log_error()   { echo -e "${RED}[ERROR]${NC}   $*"; }

# ---- Usage ----
usage() {
    head -30 "$0" | grep "^#" | sed 's/^# \?//'
    exit 1
}

# ---- Parse arguments ----
while [[ $# -gt 0 ]]; do
    case $1 in
        --host)      ROUTER_HOST="$2"; shift 2 ;;
        --ssh-key)   SSH_KEY="$2"; shift 2 ;;
        --ssh-port)  SSH_PORT="$2"; shift 2 ;;
        --user)      SSH_USER="$2"; shift 2 ;;
        --rsc-file)  RSC_FILE="$2"; shift 2 ;;
        --cleanup)   CLEANUP=true; shift ;;
        --dry-run)   DRY_RUN=true; shift ;;
        --verify)    VERIFY=true; shift ;;
        --rollback)  ROLLBACK=true; shift ;;
        --timeout)   TIMEOUT="$2"; shift 2 ;;
        --verbose)   VERBOSE=true; shift ;;
        -h|--help)   usage ;;
        *)           log_error "Unknown option: $1"; usage ;;
    esac
done

# ---- Validate ----
if [[ -z "${ROUTER_HOST:-}" ]]; then
    log_error "--host is required"
    usage
fi

if [[ -z "${SSH_KEY:-}" ]]; then
    log_error "--ssh-key is required"
    usage
fi

if [[ ! -f "$SSH_KEY" ]]; then
    log_error "SSH key file not found: $SSH_KEY"
    exit 1
fi

# ---- SSH options ----
SSH_OPTS=(
    -o StrictHostKeyChecking=no
    -o UserKnownHostsFile=/dev/null
    -o ConnectTimeout="$TIMEOUT"
    -o BatchMode=yes
    -i "$SSH_KEY"
    -p "$SSH_PORT"
)

# ---- Helper: Run command on router ----
run_on_router() {
    local cmd="$1"
    if [[ "$DRY_RUN" == true ]]; then
        log_info "[DRY-RUN] SSH $SSH_USER@$ROUTER_HOST: $cmd"
        return 0
    fi
    if [[ "$VERBOSE" == true ]]; then
        log_info "Running: $cmd"
    fi
    ssh "${SSH_OPTS[@]}" "${SSH_USER}@${ROUTER_HOST}" "$cmd"
}

# ---- Helper: Upload file to router ----
upload_to_router() {
    local local_file="$1"
    local remote_file="$2"
    if [[ "$DRY_RUN" == true ]]; then
        log_info "[DRY-RUN] SCP $local_file -> $SSH_USER@$ROUTER_HOST:$remote_file"
        return 0
    fi
    scp "${SSH_OPTS[@]}" "$local_file" "${SSH_USER}@${ROUTER_HOST}:$remote_file"
}

# ---- Helper: Check if command succeeded ----
check_result() {
    local desc="$1"
    local exit_code="$2"
    if [[ "$exit_code" -eq 0 ]]; then
        log_success "$desc"
    else
        log_error "$desc (exit code: $exit_code)"
        return 1
    fi
}

# ====================================================================
#  MAIN
# ====================================================================

echo "=============================================="
echo "  KahfGuard Router Config Deployment"
echo "  Router: $ROUTER_HOST"
echo "  User:   $SSH_USER"
echo "  Port:   $SSH_PORT"
echo "=============================================="
echo ""

# ---- Step 1: Test SSH connection ----
log_info "Step 1: Testing SSH connection..."
if run_on_router "/system identity get name" > /dev/null 2>&1; then
    ROUTER_NAME=$(run_on_router "/system identity get name")
    ROUTER_VERSION=$(run_on_router "/system package get [find where name=routeros] version")
    log_success "Connected to: $ROUTER_NAME (RouterOS $ROUTER_VERSION)"
else
    log_error "Cannot connect to router $ROUTER_HOST"
    exit 1
fi

# ---- Step 2: Backup current config ----
log_info "Step 2: Backing up current config..."
BACKUP_FILE="/tmp/router-backup-$(date +%Y%m%d-%H%M%S).rsc"
if [[ "$DRY_RUN" == false ]]; then
    run_on_router "/export" > "$BACKUP_FILE" 2>/dev/null || true
    if [[ -s "$BACKUP_FILE" ]]; then
        log_success "Backup saved to: $BACKUP_FILE"
    else
        log_warn "Backup may be empty (export might not work on all RouterOS versions)"
    fi
fi

# ---- Step 3: Rollback if requested ----
if [[ "$ROLLBACK" == true ]]; then
    log_info "Step 3: Rolling back to previous config..."
    # Look for the most recent backup in /tmp/router-backup-*.rsc
    LATEST_BACKUP=$(ls -t /tmp/router-backup-*.rsc 2>/dev/null | head -1)
    if [[ -z "$LATEST_BACKUP" ]]; then
        log_error "No backup found to rollback to"
        exit 1
    fi
    upload_to_router "$LATEST_BACKUP" "rollback-config.rsc"
    run_on_router "/import file=rollback-config.rsc"
    log_success "Rollback completed"
    exit 0
fi

# ---- Step 4: Upload scripts ----
log_info "Step 3: Uploading scripts..."
upload_to_router "$CLEANUP_FILE" "kahf-cleanup.rsc"
check_result "Uploaded cleanup script" $?

upload_to_router "$RSC_FILE" "kahf-dns-v2.rsc"
check_result "Uploaded v2 config" $?

# ---- Step 5: Run cleanup (idempotent) ----
if [[ "$CLEANUP" == true ]]; then
    log_info "Step 4: Running cleanup (removing old rules)..."
    run_on_router "/import file=kahf-cleanup.rsc"
    check_result "Cleanup completed" $?
    sleep 2
fi

# ---- Step 6: Import new config ----
log_info "Step 5: Importing v2 config..."
run_on_router "/import file=kahf-dns-v2.rsc"
IMPORT_EXIT=$?
check_result "Config imported" $IMPORT_EXIT

if [[ "$IMPORT_EXIT" -ne 0 ]]; then
    log_error "Import failed! Consider rolling back with --rollback"
    exit 1
fi

# ---- Step 7: Verify deployment ----
if [[ "$VERIFY" == true ]]; then
    log_info "Step 6: Verifying deployment..."

    # Check DNS NAT rules
    DNS_NAT=$(run_on_router "/ip firewall nat print count-only where comment~\"DNS to Core\"")
    log_info "IPv4 DNS NAT rules: $DNS_NAT"

    # Check DoH rules
    DOH_RULES=$(run_on_router "/ip firewall filter print count-only where comment~\"KAHF-DNS\"")
    log_info "IPv4 DNS filter rules: $DOH_RULES"

    # Check VPN rules
    VPN_RULES=$(run_on_router "/ip firewall filter print count-only where comment~\"KAHF-VPN\"")
    log_info "IPv4 VPN rules: $VPN_RULES"

    # Check TOR rules
    TOR_RULES=$(run_on_router "/ip firewall filter print count-only where comment~\"KAHF-TOR\"")
    log_info "IPv4 TOR rules: $TOR_RULES"

    # Check DoH address list count
    DOH_IPS=$(run_on_router "/ip firewall address-list print count-only where list=DoH_Providers")
    log_info "DoH provider IPs blocked: $DOH_IPS"

    # Check IPv6 rules if enabled
    IPV6_NAT=$(run_on_router "/ipv6 firewall nat print count-only where comment~\"DNS to Core\" 2>/dev/null || echo 0")
    log_info "IPv6 DNS NAT rules: $IPV6_NAT"

    log_success "Verification complete"
fi

# ---- Step 7: Cleanup uploaded files ----
log_info "Step 7: Cleaning up uploaded files..."
run_on_router "/file remove kahf-cleanup.rsc" 2>/dev/null || true
run_on_router "/file remove kahf-dns-v2.rsc" 2>/dev/null || true

echo ""
echo "=============================================="
log_success "Deployment completed successfully!"
echo "  Router: $ROUTER_HOST ($ROUTER_NAME)"
echo "  Config: $RSC_FILE"
echo "  Backup: $BACKUP_FILE"
echo "=============================================="
