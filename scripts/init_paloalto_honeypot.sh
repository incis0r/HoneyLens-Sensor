#!/usr/bin/env bash
# =============================================================================
# init_paloalto_honeypot.sh — per-instance identity generator for the PAN-OS decoy
# =============================================================================
# The decoy refuses to start without this: honeypot_paloalto.py exits 1 when
# $PANOS_DATA_DIR/tls/management.{crt,key} is missing, and honeypot_paloalto_ssh.py
# exits 1 without $PANOS_DATA_DIR/tls/ssh_host_rsa_key. Both print "Run:
# scripts/init_paloalto_honeypot.sh" — a script the 1.0 port never carried over. Under
# Restart=always that is not a failed start but a silent permanent one: the pair restarts
# every few seconds indefinitely, with both decoy port groups dark. This is that script,
# ported from 0.9.
#
# WHERE IT RUNS: on the sensor host, as the user that owns the rootless containers —
# NOT inside the container (its root filesystem is read-only). The quadlet bind-mounts
# a host directory into the container:
#
#     Volume=.../honeylens-state/identity/paloalto:/var/lib/honeylens/identity:Z
#     Environment=PANOS_DATA_DIR=/var/lib/honeylens/identity
#
# so the host path is what this script writes and $PANOS_DATA_DIR is how the decoy sees
# it. The default below is the host side of that mount; --data-dir overrides it.
#
# Give every sensor its OWN identity. Serial, MAC, hostname, PAN-OS version and the
# certificate subjects are all derived here, so two sensors running the same image are
# not one fingerprint shared across the fleet.
#
# Differences from the 0.9 original, all deliberate:
#   * Serial numbers are 12 decimal digits. 0.9 emitted 4+2+8 = 14 characters with hex
#     letters in them; a real PAN-OS serial is 12 digits, so the old format was itself a
#     tell that the box was fake.
#   * No GlobalProtect keypair. 1.0 serves management (4443) and captive portal only —
#     nothing reads globalprotect.{crt,key}, and an unused private key on disk is a
#     liability, not realism. Re-add it here if a GP endpoint ever lands.
#   * An identity directory that exists but has no management certificate is REPAIRED
#     rather than refused. That is the state a half-finished deployment leaves behind,
#     and refusing it is how the crash loop above stayed unfixed.
#
# Usage:
#   ./scripts/init_paloalto_honeypot.sh                         # random identity
#   ./scripts/init_paloalto_honeypot.sh --model PA-460          # pick the model
#   ./scripts/init_paloalto_honeypot.sh --hostname FW-CORE-01   # pick the hostname
#   ./scripts/init_paloalto_honeypot.sh --version 11.2.3        # pick the PAN-OS release
#   ./scripts/init_paloalto_honeypot.sh --data-dir DIR          # host side of the mount
#   ./scripts/init_paloalto_honeypot.sh --info                  # show what is there
#   ./scripts/init_paloalto_honeypot.sh --regen-certs           # new certs, same identity
# =============================================================================

set -euo pipefail

# Host side of the identity mount. HONEYLENS_STATE_DIR follows the same convention as
# INGEST_STATE_DIR in the unit files; PANOS_DATA_DIR wins when set, so running this with
# the decoy's own environment also works.
STATE_DIR="${HONEYLENS_STATE_DIR:-$HOME/honeylens-state}"
DATA_DIR="${PANOS_DATA_DIR:-$STATE_DIR/identity/paloalto}"
IDENTITY_DIR="$DATA_DIR/identity"
TLS_DIR="$DATA_DIR/tls"
TEMPLATE_DIR="$DATA_DIR/templates"

# ---------------------------------------------------------------------------
# Model definitions
# ---------------------------------------------------------------------------
HARDWARE_MODELS=("PA-220" "PA-440" "PA-450" "PA-460" "PA-820" "PA-850" "PA-3200" "PA-3400" "PA-5200" "PA-5400")
VIRTUAL_MODELS=("VM-50" "VM-100" "VM-300" "VM-500" "VM-700")
ALL_MODELS=("${HARDWARE_MODELS[@]}" "${VIRTUAL_MODELS[@]}")

# Serial number prefixes by model family (first four digits of a real serial).
declare -A SERIAL_PREFIX=(
    ["PA-220"]="0110" ["PA-440"]="0124" ["PA-450"]="0124" ["PA-460"]="0124"
    ["PA-820"]="0151" ["PA-850"]="0151"
    ["PA-3200"]="0180" ["PA-3400"]="0180"
    ["PA-5200"]="0190" ["PA-5400"]="0190"
    ["VM-50"]="0007" ["VM-100"]="0007" ["VM-300"]="0007" ["VM-500"]="0007" ["VM-700"]="0007"
)

declare -A MODEL_FAMILY=(
    ["PA-220"]="200" ["PA-440"]="400" ["PA-450"]="400" ["PA-460"]="400"
    ["PA-820"]="800" ["PA-850"]="800"
    ["PA-3200"]="3000" ["PA-3400"]="3000"
    ["PA-5200"]="5000" ["PA-5400"]="5000"
    ["VM-50"]="vm" ["VM-100"]="vm" ["VM-300"]="vm" ["VM-500"]="vm" ["VM-700"]="vm"
)

declare -A IFACE_COUNT=(
    ["PA-220"]="4" ["PA-440"]="6" ["PA-450"]="6" ["PA-460"]="8"
    ["PA-820"]="8" ["PA-850"]="12"
    ["PA-3200"]="16" ["PA-3400"]="24"
    ["PA-5200"]="24" ["PA-5400"]="32"
    ["VM-50"]="2" ["VM-100"]="4" ["VM-300"]="4" ["VM-500"]="8" ["VM-700"]="8"
)

# PAN-OS release metadata. The content-pack versions have to match the release, because
# "show system info" prints them together and a mismatched pair is a tell.
declare -A VERSION_APP=(
    ["10.1.14"]="8835-8652" ["10.2.12"]="8890-8810" ["11.0.6"]="8910-8856"
    ["11.1.4"]="8933-8901"  ["11.2.3"]="8950-8920"
)
declare -A VERSION_AV=(
    ["10.1.14"]="4750-5180" ["10.2.12"]="4790-5240" ["11.0.6"]="4800-5260"
    ["11.1.4"]="4820-5290"  ["11.2.3"]="4840-5310"
)
declare -A VERSION_THREAT=(
    ["10.1.14"]="8835-8652" ["10.2.12"]="8890-8810" ["11.0.6"]="8910-8856"
    ["11.1.4"]="8933-8901"  ["11.2.3"]="8950-8920"
)
declare -A VERSION_ETAG_EPOCH=(
    ["10.1.14"]="1710460800" ["10.2.12"]="1722470400" ["11.0.6"]="1726704000"
    ["11.1.4"]="1731628800"  ["11.2.3"]="1738368000"
)
KNOWN_VERSIONS=("10.1.14" "10.2.12" "11.0.6" "11.1.4" "11.2.3")

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
rand_hex() { openssl rand -hex "$1" 2>/dev/null || head -c "$1" /dev/urandom | xxd -p; }
rand_int() { shuf -i "$1-$2" -n 1; }
# Zero-padded decimal run of $1 digits, for serials that have to look like serials.
rand_digits() { local n="$1"; printf "%0${n}d" "$(shuf -i "0-$(( 10 ** n - 1 ))" -n 1)"; }
pick_random() { local arr=("$@"); echo "${arr[$((RANDOM % ${#arr[@]}))]}" ; }

log() { echo "[init] $*"; }
err() { echo "[ERROR] $*" >&2; exit 1; }

# ---------------------------------------------------------------------------
# Parse arguments
# ---------------------------------------------------------------------------
ARG_MODEL="" ARG_HOSTNAME="" ARG_VERSION=""
DO_INFO=false DO_REGEN_CERTS=false

while [[ $# -gt 0 ]]; do
    case "$1" in
        --model)       ARG_MODEL="$2"; shift 2 ;;
        --hostname)    ARG_HOSTNAME="$2"; shift 2 ;;
        --version)     ARG_VERSION="$2"; shift 2 ;;
        --data-dir)    DATA_DIR="$2"; IDENTITY_DIR="$DATA_DIR/identity"; TLS_DIR="$DATA_DIR/tls"; TEMPLATE_DIR="$DATA_DIR/templates"; shift 2 ;;
        --info)        DO_INFO=true; shift ;;
        --regen-certs) DO_REGEN_CERTS=true; shift ;;
        -h|--help)
            echo "Usage: $0 [--model MODEL] [--hostname NAME] [--version VER] [--data-dir DIR] [--info] [--regen-certs]"
            echo "Data dir: $DATA_DIR"
            echo "Models:   ${ALL_MODELS[*]}"
            echo "Versions: ${KNOWN_VERSIONS[*]}"
            exit 0 ;;
        *) err "Unknown argument: $1" ;;
    esac
done

# ---------------------------------------------------------------------------
# --info: show the current identity and exit
# ---------------------------------------------------------------------------
if $DO_INFO; then
    if [[ ! -d "$IDENTITY_DIR" ]]; then
        echo "No identity found at $IDENTITY_DIR. Run init first."
        exit 1
    fi
    echo "=== PAN-OS decoy identity ==="
    echo "Data dir:  $DATA_DIR"
    for f in serial model hostname mac etag_seed init_timestamp; do
        [[ -f "$IDENTITY_DIR/$f" ]] && printf "%-12s %s\n" "$f:" "$(cat "$IDENTITY_DIR/$f")"
    done
    [[ -f "$IDENTITY_DIR/version.json" ]] && echo "version:     $(tr -d '\n ' < "$IDENTITY_DIR/version.json")"
    echo ""
    echo "=== TLS ==="
    for cert in management captive; do
        if [[ -f "$TLS_DIR/${cert}.crt" ]]; then
            CN=$(openssl x509 -in "$TLS_DIR/${cert}.crt" -noout -subject 2>/dev/null | sed 's/.*CN *= *//')
            EXP=$(openssl x509 -in "$TLS_DIR/${cert}.crt" -noout -enddate 2>/dev/null | cut -d= -f2)
            printf "%-16s CN=%-30s expires: %s\n" "${cert}:" "$CN" "$EXP"
        else
            printf "%-16s MISSING\n" "${cert}:"
        fi
    done
    if [[ -f "$TLS_DIR/ssh_host_rsa_key" ]]; then
        echo "ssh_host:        $(ssh-keygen -lf "$TLS_DIR/ssh_host_rsa_key" 2>/dev/null | awk '{print $2}')"
    else
        echo "ssh_host:        MISSING"
    fi
    echo ""
    echo "=== templates ==="
    for t in show_system_info.txt show_interface_all.txt show_security_policy.txt; do
        if [[ -f "$TEMPLATE_DIR/$t" ]]; then printf "  %-28s %s bytes\n" "$t" "$(wc -c < "$TEMPLATE_DIR/$t")"
        else printf "  %-28s MISSING\n" "$t"; fi
    done
    exit 0
fi

# ---------------------------------------------------------------------------
# Certificates and host key
# ---------------------------------------------------------------------------
# management.{crt,key} is the hard requirement — without it honeypot_paloalto.py exits 1.
# captive.{crt,key} backs the captive-portal listener and is optional there.
# ssh_host_rsa_key is the hard requirement for honeypot_paloalto_ssh.py.
generate_certs() {
    local serial hostname
    serial=$(cat "$IDENTITY_DIR/serial")
    hostname=$(cat "$IDENTITY_DIR/hostname")

    mkdir -p "$TLS_DIR"

    # PAN-OS issues the management certificate to the serial number, not the hostname.
    log "management TLS certificate (CN=$serial)"
    openssl req -x509 -newkey rsa:2048 -nodes \
        -keyout "$TLS_DIR/management.key" -out "$TLS_DIR/management.crt" \
        -days 3650 -subj "/CN=$serial" 2>/dev/null

    log "captive portal TLS certificate (CN=${hostname}-captive)"
    openssl req -x509 -newkey rsa:2048 -nodes \
        -keyout "$TLS_DIR/captive.key" -out "$TLS_DIR/captive.crt" \
        -days 365 -subj "/CN=${hostname}-captive" 2>/dev/null

    log "SSH host key"
    rm -f "$TLS_DIR/ssh_host_rsa_key" "$TLS_DIR/ssh_host_rsa_key.pub"
    ssh-keygen -t rsa -b 2048 -f "$TLS_DIR/ssh_host_rsa_key" -N "" -q

    chmod 600 "$TLS_DIR"/*.key "$TLS_DIR/ssh_host_rsa_key"
    chmod 644 "$TLS_DIR"/*.crt "$TLS_DIR/ssh_host_rsa_key.pub"
}

if $DO_REGEN_CERTS; then
    [[ -d "$IDENTITY_DIR" ]] || err "No identity at $IDENTITY_DIR. Run a full init first."
    generate_certs
    log "Certificates regenerated. Restart hp-paloalto and hp-paloalto-ssh."
    exit 0
fi

# An identity that exists but has lost (or never had) its certificates is the state a
# half-finished deployment leaves behind. Repair it instead of refusing, so the decoy
# stops crash-looping; a COMPLETE identity is still left alone.
if [[ -d "$IDENTITY_DIR" ]]; then
    if [[ -f "$TLS_DIR/management.crt" && -f "$TLS_DIR/management.key" && -f "$TLS_DIR/ssh_host_rsa_key" ]]; then
        log "Identity at $IDENTITY_DIR is already complete — nothing to do."
        log "  new certificates, same identity: $0 --regen-certs"
        log "  start over:                      rm -rf $DATA_DIR && $0"
        exit 0
    fi
    log "Identity exists at $IDENTITY_DIR but its certificates are incomplete — repairing."
    [[ -f "$IDENTITY_DIR/serial" && -f "$IDENTITY_DIR/model" && -f "$IDENTITY_DIR/hostname" ]] \
        || err "Identity is too damaged to repair (serial/model/hostname missing). Remove $DATA_DIR and re-run."
    generate_certs
    log "Certificates restored. Restart hp-paloalto and hp-paloalto-ssh."
    exit 0
fi

# ---------------------------------------------------------------------------
# Full initialisation
# ---------------------------------------------------------------------------
# Validate every argument BEFORE creating anything. Creating the directories first and
# validating after leaves an empty identity tree behind when an argument is rejected,
# and the next run then sees "identity exists but incomplete" and refuses to repair it —
# one typo and the data directory has to be removed by hand before you can retry.
if [[ -n "$ARG_MODEL" ]]; then
    MODEL="$ARG_MODEL"
    found=false
    for m in "${ALL_MODELS[@]}"; do [[ "$m" == "$MODEL" ]] && found=true && break; done
    $found || err "Unknown model: $MODEL. Valid: ${ALL_MODELS[*]}"
else
    MODEL=$(pick_random "${ALL_MODELS[@]}")
fi

if [[ -n "$ARG_VERSION" ]]; then
    VERSION="$ARG_VERSION"
    found=false
    for v in "${KNOWN_VERSIONS[@]}"; do [[ "$v" == "$VERSION" ]] && found=true && break; done
    $found || err "Unknown version: $VERSION. Valid: ${KNOWN_VERSIONS[*]}"
else
    VERSION=$(pick_random "${KNOWN_VERSIONS[@]}")
fi

mkdir -p "$IDENTITY_DIR" "$TLS_DIR" "$TEMPLATE_DIR"

# 1. Model
echo "$MODEL" > "$IDENTITY_DIR/model"
log "Model:    $MODEL"

# 2. Serial — 12 decimal digits: a 4-digit family prefix plus 8 random digits.
PREFIX="${SERIAL_PREFIX[$MODEL]:-0007}"
SERIAL="${PREFIX}$(rand_digits 8)"
echo "$SERIAL" > "$IDENTITY_DIR/serial"
log "Serial:   $SERIAL"

# 3. Hostname
if [[ -n "$ARG_HOSTNAME" ]]; then
    HNAME="$ARG_HOSTNAME"
else
    HNAME="${MODEL}-$(rand_hex 2)"
fi
echo "$HNAME" > "$IDENTITY_DIR/hostname"
log "Hostname: $HNAME"

# 4. MAC address, from the Palo Alto Networks OUI 00:1B:17.
MAC_SUFFIX=$(rand_hex 3 | sed 's/\(..\)/:\1/g')
MAC="00:1b:17${MAC_SUFFIX}"
echo "$MAC" > "$IDENTITY_DIR/mac"
log "MAC:      $MAC"

# 5. PAN-OS release (validated above, before anything was created)
APP_VER="${VERSION_APP[$VERSION]}"
AV_VER="${VERSION_AV[$VERSION]}"
THREAT_VER="${VERSION_THREAT[$VERSION]}"
cat > "$IDENTITY_DIR/version.json" << VEOF
{
    "sw_version": "$VERSION",
    "app_version": "$APP_VER",
    "av_version": "$AV_VER",
    "threat_version": "$THREAT_VER",
    "logdb_version": "$VERSION"
}
VEOF
log "PAN-OS:   $VERSION"

# 6. ETag seed — derived from the release date, so ETags are stable per release.
ETAG_EPOCH="${VERSION_ETAG_EPOCH[$VERSION]}"
printf '%08x\n' "$ETAG_EPOCH" > "$IDENTITY_DIR/etag_seed"

# 7. When this identity was minted
date -u +"%Y-%m-%dT%H:%M:%SZ" > "$IDENTITY_DIR/init_timestamp"

generate_certs

# ---------------------------------------------------------------------------
# Response templates
# ---------------------------------------------------------------------------
# IPv6 link-local from the MAC (EUI-64), so the address matches the interface.
mac_clean=$(echo "$MAC" | tr -d ':')
byte0=$(printf '%02x' $(( 0x${mac_clean:0:2} ^ 0x02 )) )
IPV6_LL="fe80::${byte0}${mac_clean:2:2}:${mac_clean:4:2}ff:fe${mac_clean:6:2}:${mac_clean:8:4}"

UPTIME_DAYS=$(rand_int 7 180)
UPTIME_HOURS=$(rand_int 0 23)
UPTIME_MINS=$(rand_int 0 59)
UPTIME_SECS=$(rand_int 0 59)

FAMILY="${MODEL_FAMILY[$MODEL]:-800}"

cat > "$TEMPLATE_DIR/show_system_info.txt" << SEOF
hostname: $HNAME
ip-address: 10.0.0.1
public-ip-address: unknown
netmask: 255.255.255.0
default-gateway: 10.0.0.254
ip-assignment: static
ipv6-address: unknown
ipv6-link-local-address: ${IPV6_LL}/64
ipv6-default-gateway:
mac-address: $MAC
time: $(date "+%a %b %d %H:%M:%S %Y")
uptime: ${UPTIME_DAYS} days, ${UPTIME_HOURS}:$(printf '%02d' "$UPTIME_MINS"):$(printf '%02d' "$UPTIME_SECS")
family: $FAMILY
model: $MODEL
serial: $SERIAL
cloud-mode: non-cloud
sw-version: $VERSION
global-protect-client-package-version: 6.2.0-33
app-version: $APP_VER
app-release-date: 2026/03/28 14:30:00 CET
av-version: $AV_VER
av-release-date: 2026/03/28 10:05:59 CET
threat-version: $THREAT_VER
threat-release-date: 2026/03/28 14:30:00 CET
wf-private-version: 0
wf-private-release-date: unknown
url-db: paloaltonetworks
wildfire-version: 0
wildfire-release-date: unknown
url-filtering-version: 20260328.20411
logdb-version: $VERSION
platform-family: $FAMILY
vpn-disable-mode: off
multi-vsys: off
operational-mode: normal
SEOF

IFACES="${IFACE_COUNT[$MODEL]:-8}"
{
    printf "%-20s %-6s %-18s %-18s %-10s\n" "Name" "Tag" "IPv4 Address" "IPv6 Address" "State"
    printf "%-20s %-6s %-18s %-18s %-10s\n" "----" "---" "------------" "------------" "-----"
    printf "%-20s %-6s %-18s %-18s %-10s\n" "management" "0" "10.0.0.1/24" "$IPV6_LL/64" "up"
    for i in $(seq 1 "$IFACES"); do
        state="up"
        [[ $i -gt 2 ]] && state="down"
        addr="N/A"
        [[ $i -eq 1 ]] && addr="192.168.1.1/24"
        [[ $i -eq 2 ]] && addr="10.10.10.1/24"
        printf "%-20s %-6s %-18s %-18s %-10s\n" "ethernet1/$i" "0" "$addr" "N/A" "$state"
    done
} > "$TEMPLATE_DIR/show_interface_all.txt"

cat > "$TEMPLATE_DIR/show_security_policy.txt" << 'PEOF'
"Allow DNS" {
        from trust;
        source any;
        to untrust;
        destination any;
        application dns;
        service application-default;
        action allow;
}
"Allow NTP" {
        from trust;
        source any;
        to untrust;
        destination any;
        application ntp;
        service application-default;
        action allow;
}
"Allow Web" {
        from trust;
        source any;
        to untrust;
        destination any;
        application web-browsing ssl;
        service application-default;
        action allow;
        log-end yes;
}
"Allow VPN" {
        from untrust;
        source any;
        to trust;
        destination any;
        application ipsec ssl-vpn;
        service any;
        action allow;
        log-start yes;
        log-end yes;
}
"Deny All" {
        from any;
        source any;
        to any;
        destination any;
        application any;
        service any;
        action deny;
        log-end yes;
}
PEOF

log ""
log "=== PAN-OS decoy identity initialised ==="
log "Data directory: $DATA_DIR"
log "Model:          $MODEL"
log "Serial:         $SERIAL"
log "Hostname:       $HNAME"
log "MAC:            $MAC"
log "PAN-OS:         $VERSION"
log ""
log "Now restart the decoys so they pick it up:"
log "  systemctl --user restart hp-paloalto hp-paloalto-ssh"
