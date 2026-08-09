#!/usr/bin/env bash

set -Eeuo pipefail
IFS=$'\n\t'

readonly SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
readonly DEFAULT_LOGFILE="/tmp/netfast.log"

interface=""
queues=""
workers=""
logfile="$DEFAULT_LOGFILE"
assume_yes=false
skip_deps=false
allow_management_interface=false
allow_existing_xdp=false
dry_run=false

info()
{
    printf '[netfast] %s\n' "$*"
}

warn()
{
    printf '[netfast] warning: %s\n' "$*" >&2
}

die()
{
    printf '[netfast] error: %s\n' "$*" >&2
    exit 1
}

usage()
{
    cat <<'EOF'
Usage: ./setup.sh [options]

Build, configure, and install NetFast on Debian or Ubuntu.

Options:
  -i, --interface IFACE       Dedicated interface for AF_XDP
  -q, --queues COUNT          AF_XDP queue count (1-32)
  -w, --workers COUNT         Worker count (1-64)
      --logfile PATH          Runtime log path (default: /tmp/netfast.log)
  -y, --yes                   Accept non-dangerous prompts
      --skip-deps             Do not install missing build dependencies
      --allow-management-interface
                              Permit the active default/SSH interface
      --allow-existing-xdp    Permit an interface with an XDP program attached
      --dry-run               Check and print the plan without changing files
  -h, --help                  Show this help

Examples:
  ./setup.sh
  ./setup.sh -i ens192 -q 2 -w 2
  ./setup.sh -i ens192 -q 1 -w 1 --skip-deps --dry-run
EOF
}

need_value()
{
    [[ -n "${2:-}" ]] || die "$1 requires a value"
}

while (($#)); do
    case "$1" in
        -i|--interface)
            need_value "$1" "${2:-}"
            interface=$2
            shift 2
            ;;
        -q|--queues)
            need_value "$1" "${2:-}"
            queues=$2
            shift 2
            ;;
        -w|--workers)
            need_value "$1" "${2:-}"
            workers=$2
            shift 2
            ;;
        --logfile)
            need_value "$1" "${2:-}"
            logfile=$2
            shift 2
            ;;
        -y|--yes)
            assume_yes=true
            shift
            ;;
        --skip-deps)
            skip_deps=true
            shift
            ;;
        --allow-management-interface)
            allow_management_interface=true
            shift
            ;;
        --allow-existing-xdp)
            allow_existing_xdp=true
            shift
            ;;
        --dry-run)
            dry_run=true
            shift
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            die "unknown option: $1 (use --help)"
            ;;
    esac
done

if [[ -n "$queues" && ! "$queues" =~ ^[1-9][0-9]*$ ]]; then
    die "queues must be a positive decimal integer"
fi
if [[ -n "$workers" && ! "$workers" =~ ^[1-9][0-9]*$ ]]; then
    die "workers must be a positive decimal integer"
fi

[[ "$(uname -s)" == Linux ]] || die "NetFast requires Linux"
[[ -f "$SCRIPT_DIR/Makefile" && -f "$SCRIPT_DIR/config.example.json" ]] ||
    die "run this script from a complete NetFast source tree"

run_root()
{
    if ((EUID == 0)); then
        "$@"
    elif command -v sudo >/dev/null 2>&1; then
        sudo "$@"
    else
        die "root access is required for package and library installation"
    fi
}

confirm()
{
    local prompt=$1
    if $assume_yes; then
        return 0
    fi
    [[ -t 0 ]] || die "$prompt; rerun interactively or pass --yes"
    local reply
    read -r -p "$prompt [y/N] " reply
    [[ "$reply" == y || "$reply" == Y || "$reply" == yes ||
       "$reply" == YES ]]
}

missing_dependencies()
{
    local missing=()
    local command_name
    for command_name in gcc make clang pkg-config ip ethtool; do
        command -v "$command_name" >/dev/null 2>&1 ||
            missing+=("command:$command_name")
    done

    if command -v pkg-config >/dev/null 2>&1; then
        local module
        for module in libbpf libxdp libelf zlib libcjson; do
            pkg-config --exists "$module" || missing+=("pkg-config:$module")
        done
    fi

    if ((${#missing[@]})); then
        printf '%s\n' "${missing[@]}"
    fi
    return 0
}

mapfile -t missing < <(missing_dependencies)
if ((${#missing[@]})); then
    if $dry_run; then
        printf '[netfast] missing dependencies (dry run will not install them):\n' >&2
        printf '  %s\n' "${missing[@]}" >&2
        die "install the dependencies before running the remaining checks"
    fi
    if $skip_deps; then
        printf '[netfast] missing dependencies:\n' >&2
        printf '  %s\n' "${missing[@]}" >&2
        die "install the dependencies or omit --skip-deps"
    fi

    command -v apt-get >/dev/null 2>&1 || {
        printf '[netfast] missing dependencies:\n' >&2
        printf '  %s\n' "${missing[@]}" >&2
        die "automatic dependency installation currently supports Debian/Ubuntu"
    }

    confirm "Install the missing NetFast build dependencies" ||
        die "dependency installation declined"
    run_root apt-get update
    run_root env DEBIAN_FRONTEND=noninteractive apt-get install -y \
        build-essential clang llvm pkg-config libbpf-dev libxdp-dev \
        libelf-dev zlib1g-dev libcjson-dev iproute2 ethtool

    mapfile -t missing < <(missing_dependencies)
    ((${#missing[@]} == 0)) ||
        die "dependencies are still incomplete: ${missing[*]}"
fi

queue_count()
{
    local ifname=$1
    local direction=$2
    local paths=()
    shopt -s nullglob
    paths=("/sys/class/net/$ifname/queues/$direction-"*)
    shopt -u nullglob
    printf '%u\n' "${#paths[@]}"
}

driver_name()
{
    local driver
    driver=$(ethtool -i "$1" 2>/dev/null |
        awk -F': ' '$1 == "driver" { print $2; exit }' || true)
    printf '%s\n' "${driver:-unknown}"
}

declare -A management_interfaces=()

default_interface=$(ip -o route get 1.1.1.1 2>/dev/null |
    awk '{ for (i=1; i<=NF; i++) if ($i == "dev") { print $(i+1); exit } }' ||
    true)
if [[ -n "$default_interface" ]]; then
    management_interfaces["$default_interface"]="active default route"
fi

main_default_interface=$(ip -o route show default 2>/dev/null |
    awk '{ for (i=1; i<=NF; i++) if ($i == "dev") { print $(i+1); exit } }' ||
    true)
if [[ -n "$main_default_interface" &&
      -z "${management_interfaces[$main_default_interface]:-}" ]]; then
    management_interfaces["$main_default_interface"]="primary default route"
fi

if [[ -n "${SSH_CONNECTION:-}" ]]; then
    ssh_local_ip=$(awk '{print $3}' <<<"$SSH_CONNECTION")
    ssh_interface=$(ip -o addr show | awk -v address="$ssh_local_ip" '
        { split($4, part, "/"); if (part[1] == address) { print $2; exit } }' ||
        true)
    if [[ -n "$ssh_interface" ]]; then
        management_interfaces["$ssh_interface"]="SSH connection"
    fi
fi

show_interfaces()
{
    printf '%-16s %-10s %-8s %-8s %s\n' INTERFACE DRIVER RX-QUEUES TX-QUEUES NOTES
    local path ifname note
    for path in /sys/class/net/*; do
        ifname=${path##*/}
        [[ "$ifname" == lo ]] && continue
        note=${management_interfaces[$ifname]:-}
        printf '%-16s %-10s %-8s %-8s %s\n' \
            "$ifname" "$(driver_name "$ifname")" \
            "$(queue_count "$ifname" rx)" "$(queue_count "$ifname" tx)" \
            "$note"
    done
}

if [[ -z "$interface" ]]; then
    candidates=()
    for path in /sys/class/net/*; do
        candidate=${path##*/}
        [[ "$candidate" == lo ]] && continue
        [[ "$(cat "$path/type" 2>/dev/null || true)" == 1 ]] || continue
        [[ -z "${management_interfaces[$candidate]:-}" ]] || continue
        [[ "$(cat "$path/operstate" 2>/dev/null || true)" == up ]] || continue
        candidates+=("$candidate")
    done

    if ((${#candidates[@]} == 1)); then
        interface=${candidates[0]}
        info "selected the only active non-management interface: $interface"
    elif ((${#candidates[@]} > 1)) && [[ -t 0 ]] && ! $assume_yes; then
        show_interfaces
        printf '\nSelect a dedicated NetFast interface:\n'
        select candidate in "${candidates[@]}"; do
            if [[ -n "${candidate:-}" ]]; then
                interface=$candidate
                break
            fi
        done
    else
        show_interfaces
        die "cannot safely choose an interface; pass --interface IFACE"
    fi
fi

[[ "$interface" =~ ^[[:alnum:]_.:-]+$ ]] ||
    die "invalid interface name: $interface"
[[ -d "/sys/class/net/$interface" ]] || die "interface does not exist: $interface"
[[ "$interface" != lo ]] || die "the loopback interface cannot be used"

if [[ -n "${management_interfaces[$interface]:-}" ]]; then
    reason=${management_interfaces[$interface]}
    $allow_management_interface ||
        die "$interface carries the $reason; use another interface (unsafe override: --allow-management-interface)"
    warn "$interface carries the $reason; loading NetFast may disconnect this machine"
    confirm "Continue with management interface $interface" ||
        die "management interface selection declined"
fi

if ip -o route show default | awk '{for (i=1;i<=NF;i++) if ($i=="dev") print $(i+1)}' |
    grep -Fxq "$interface" && [[ "$interface" != "$default_interface" ]]; then
    warn "$interface also has a lower-priority default route; verify management traffic uses another interface"
fi

if [[ "$(cat "/sys/class/net/$interface/operstate" 2>/dev/null || true)" != up ]]; then
    warn "$interface is not currently up"
    confirm "Continue with interface $interface" || die "interface is down"
fi

if ip -details link show dev "$interface" 2>/dev/null | grep -q 'prog/xdp'; then
    $allow_existing_xdp ||
        die "$interface already has an XDP program; use another interface or pass --allow-existing-xdp"
    warn "$interface already has an XDP program; NetFast may replace it when an application starts"
fi

rx_queues=$(queue_count "$interface" rx)
tx_queues=$(queue_count "$interface" tx)
((rx_queues > 0 && tx_queues > 0)) ||
    die "$interface exposes no usable RX/TX queues"

hardware_queues=$rx_queues
((tx_queues < hardware_queues)) && hardware_queues=$tx_queues
((hardware_queues > 32)) && hardware_queues=32

cpu_count=$(getconf _NPROCESSORS_ONLN 2>/dev/null || printf '1\n')
[[ "$cpu_count" =~ ^[1-9][0-9]*$ ]] || cpu_count=1

if [[ -z "$queues" ]]; then
    queues=$hardware_queues
    ((cpu_count < queues)) && queues=$cpu_count
    [[ -n "$workers" ]] && ((workers < queues)) && queues=$workers
fi
if [[ -z "$workers" ]]; then
    workers=$queues
fi

((queues >= 1 && queues <= 32)) || die "queues must be in [1, 32]"
((workers >= 1 && workers <= 64)) || die "workers must be in [1, 64]"
((queues <= hardware_queues)) ||
    die "$interface currently exposes only $hardware_queues usable queue(s)"
if ((workers > queues)); then
    warn "workers exceeds hardware queues; additional workers rely on software flow steering"
fi

[[ "$logfile" == /* ]] || die "logfile must be an absolute path"
[[ ${#logfile} -lt 256 ]] || die "logfile must be shorter than 256 bytes"
case "$logfile" in
    *\"*|*\\*) die "logfile must not contain quotes or backslashes" ;;
esac

rss_key=$(awk -F'"' '/"toeplitz_rss_key"/ { print $4; exit }' \
    "$SCRIPT_DIR/config.example.json")
[[ "$rss_key" =~ ^[[:xdigit:]]{80}$ ]] ||
    die "config.example.json contains an invalid Toeplitz RSS key"

info "installation plan"
printf '  interface : %s (driver=%s, rx=%s, tx=%s)\n' \
    "$interface" "$(driver_name "$interface")" "$rx_queues" "$tx_queues"
printf '  workers   : %s\n' "$workers"
printf '  queues    : %s\n' "$queues"
printf '  logfile   : %s\n' "$logfile"
printf '  install   : /usr/local\n'
warn "zero-copy support can only be confirmed when an AF_XDP socket is created"

if $dry_run; then
    info "dry run complete; no files were changed"
    exit 0
fi

confirm "Build and install NetFast with this configuration" ||
    die "installation declined"

config_path="$SCRIPT_DIR/config.json"
if [[ -e "$config_path" ]]; then
    backup_dir="$SCRIPT_DIR/build/setup"
    mkdir -p "$backup_dir"
    backup_path="$backup_dir/config.json.$(date +%Y%m%d-%H%M%S).bak"
    cp -p -- "$config_path" "$backup_path"
    info "saved previous configuration to $backup_path"
fi

config_tmp=$(mktemp "$SCRIPT_DIR/.config.json.XXXXXX")
trap 'rm -f -- "${config_tmp:-}"' EXIT
cat >"$config_tmp" <<EOF
{
  "thread_num": $workers,
  "open_if": [
    {
      "name": "$interface",
      "queues": $queues
    }
  ],
  "ipv4_forward": true,
  "ipv6_forward": true,
  "toeplitz_rss_key": "$rss_key",
  "logfile": "$logfile"
}
EOF
mv -f -- "$config_tmp" "$config_path"
config_tmp=""

jobs=$cpu_count
((jobs > 32)) && jobs=32
make -C "$SCRIPT_DIR" PROFILE=release -j"$jobs" build
run_root make -C "$SCRIPT_DIR" PROFILE=release \
    CONFIG_FILE="$config_path" install

[[ -r /usr/local/lib/libnetfast.so ]] || die "installed library is missing"
[[ -r /usr/local/include/netfast.h ]] || die "installed public header is missing"
[[ -r /usr/local/lib/bpf/xdp_redirect.bpf.o ]] || die "installed XDP object is missing"
[[ -r /usr/local/etc/netfast/config.json ]] || die "installed configuration is missing"

info "installation complete"
printf '  configuration: /usr/local/etc/netfast/config.json\n'
printf '  log:           %s\n' "$logfile"
printf '\nNetFast does not attach XDP during setup. The first root process that loads\n'
printf 'libnetfast.so initializes the stack and attaches XDP to %s.\n' "$interface"
printf 'Stopping that process normally detaches the NetFast XDP program.\n'
