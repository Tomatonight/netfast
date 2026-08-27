#!/usr/bin/env bash

set -Eeuo pipefail
IFS=$'\n\t'

readonly SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"

assume_yes=false
dry_run=false

info()
{
    printf '[netfast] %s\n' "$*"
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

Check dependencies, build the release profile, and install NetFast.

Options:
  -y, --yes       Accept installation prompts
      --dry-run   Check dependencies and print the commands without running them
  -h, --help      Show this help
EOF
}

while (($#)); do
    case "$1" in
        -y|--yes)
            assume_yes=true
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
    for command_name in gcc make clang pkg-config; do
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
}

mapfile -t missing < <(missing_dependencies)
if ((${#missing[@]})); then
    printf '[netfast] missing dependencies:\n' >&2
    printf '  %s\n' "${missing[@]}" >&2

    if $dry_run; then
        die "dry run cannot install missing dependencies"
    fi

    command -v apt-get >/dev/null 2>&1 ||
        die "automatic dependency installation currently supports Debian/Ubuntu"
    confirm "Install the missing NetFast build dependencies" ||
        die "dependency installation declined"

    run_root apt-get update
    run_root env DEBIAN_FRONTEND=noninteractive apt-get install -y \
        build-essential clang llvm pkg-config libbpf-dev libxdp-dev \
        libelf-dev zlib1g-dev libcjson-dev

    mapfile -t missing < <(missing_dependencies)
    ((${#missing[@]} == 0)) ||
        die "dependencies are still incomplete: ${missing[*]}"
fi

jobs=$(getconf _NPROCESSORS_ONLN 2>/dev/null || printf '1\n')
[[ "$jobs" =~ ^[1-9][0-9]*$ ]] || jobs=1
((jobs > 32)) && jobs=32

info "build and installation plan"
printf '  make -C %s -j%s\n' "$SCRIPT_DIR" "$jobs"
printf '  make -C %s install\n' "$SCRIPT_DIR"

if $dry_run; then
    info "dry run complete; no commands were run"
    exit 0
fi

confirm "Build and install NetFast" || die "installation declined"

make -C "$SCRIPT_DIR" -j"$jobs"
run_root make -C "$SCRIPT_DIR" install

[[ -r /usr/local/lib/libnetfast.so ]] || die "installed library is missing"
[[ -r /usr/local/include/netfast.h ]] || die "installed public header is missing"
[[ -r /usr/local/lib/bpf/xdp_redirect.bpf.o ]] ||
    die "installed XDP object is missing"
[[ -r /usr/local/etc/netfast/netfast_config.json ]] ||
    die "installed configuration is missing"

info "installation complete"
printf '  library:       /usr/local/lib/libnetfast.so\n'
printf '  header:        /usr/local/include/netfast.h\n'
printf '  configuration: /usr/local/etc/netfast/netfast_config.json\n'
