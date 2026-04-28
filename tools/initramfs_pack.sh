#!/usr/bin/env bash
#
# initramfs_pack.sh — unpack and repack a Linux initramfs image.
#
# A Linux initramfs is a concatenation:
#   [optional uncompressed cpio archive (early: microcode, etc.)]
#   [optional padding to 4-byte alignment]
#   [compressed cpio archive: zstd | gzip | xz | lz4 | bzip2]
#
# The early section, padding, and compression algorithm are all auto-detected
# — no hardcoded offsets per kernel version. Pack preserves the original
# early-cpio bytes for a clean round-trip.

set -euo pipefail

usage() {
    cat <<EOF
Usage: $(basename "$0") <command> [args]

Commands:
  info   <image>             Print layout info (offsets, compression, sizes).
  unpack <image> <workdir>   Unpack <image> into a fresh <workdir>.
  pack   <workdir> <out>     Repack <workdir> into a new initramfs at <out>.

Workdir layout produced by 'unpack':
  early.cpio       Raw bytes of the early section (only if present).
  main/            Files extracted from the main archive.
  .compression     Algorithm name used for the main archive (used by pack).

Requires: cpio, python3 (for offset detection), and the relevant
compressor (zstd, gzip, xz, lz4, or bzip2) for the image's main archive.
EOF
}

die()  { echo "error: $*" >&2; exit 1; }
note() { echo "$*" >&2; }

# Hex-dump first N bytes of a file (or stdin if file is "-").
hex_head_n() {
    local file=$1 n=$2
    if [[ $file == "-" ]]; then
        od -An -tx1 -N "$n" | tr -d ' \n'
    else
        od -An -tx1 -N "$n" "$file" | tr -d ' \n'
    fi
}

# Map a hex magic prefix to a compression algorithm name, or "cpio"/"unknown".
algo_from_hex() {
    case "$1" in
        28b52ffd*)    echo zstd ;;
        1f8b*)        echo gzip ;;
        fd377a585a00) echo xz   ;;
        04224d18*)    echo lz4  ;;
        02214c18*)    echo lz4  ;;
        425a68*)      echo bz2  ;;
        303730373031*|303730373032*) echo cpio ;;   # ASCII "070701"/"070702"
        *)            echo unknown ;;
    esac
}

decompress_cmd() {
    case "$1" in
        zstd) echo "zstd -d -c -q"  ;;
        gzip) echo "gzip -d -c"     ;;
        xz)   echo "xz -d -c"       ;;
        lz4)  echo "lz4 -d -c -q"   ;;
        bz2)  echo "bzip2 -d -c"    ;;
        cpio) echo "cat"            ;;
        *) die "unsupported compression: $1" ;;
    esac
}

compress_cmd() {
    case "$1" in
        zstd) echo "zstd -19 -c -q"  ;;
        gzip) echo "gzip -9 -c"      ;;
        xz)   echo "xz -c -T0"       ;;
        lz4)  echo "lz4 -9 -c -q"    ;;
        bz2)  echo "bzip2 -9 -c"     ;;
        cpio) echo "cat"             ;;
        *) die "unsupported compression: $1" ;;
    esac
}

# Find the byte offset of the first compression magic in the image (>0).
# Echoes the offset, or returns nonzero if no compression magic is found.
find_main_offset() {
    local image=$1
    python3 - "$image" <<'PY'
import sys
magics = [
    b"\x28\xb5\x2f\xfd",   # zstd
    b"\x1f\x8b",           # gzip
    b"\xfd7zXZ\x00",       # xz
    b"\x04\x22\x4d\x18",   # lz4 frame
    b"\x02\x21\x4c\x18",   # lz4 legacy
    b"BZh",                # bzip2
]
with open(sys.argv[1], "rb") as f:
    data = f.read()
best = None
for m in magics:
    i = data.find(m, 1)  # skip offset 0
    if i != -1 and (best is None or i < best):
        best = i
if best is None:
    sys.exit(1)
print(best)
PY
}

# Echo "<algo> <offset>" where offset is the start of the main archive
# (0 if there is no early section). Sets algo=cpio if the whole image is a
# single uncompressed cpio.
inspect_image() {
    local image=$1
    local first; first=$(algo_from_hex "$(hex_head_n "$image" 6)")
    if [[ $first == cpio ]]; then
        local offset
        if offset=$(find_main_offset "$image"); then
            local main_hex
            main_hex=$(tail -c +$((offset + 1)) "$image" | hex_head_n - 6)
            local algo; algo=$(algo_from_hex "$main_hex")
            [[ $algo == unknown ]] && die "unrecognized main compression at offset $offset (magic: $main_hex)"
            echo "$algo $offset"
        else
            echo "cpio 0"
        fi
    elif [[ $first == unknown ]]; then
        die "unrecognized image format (magic: $(hex_head_n "$image" 6))"
    else
        echo "$first 0"
    fi
}

cmd_info() {
    [[ $# -eq 1 ]] || { usage; exit 1; }
    local image=$1
    [[ -f $image ]] || die "not a file: $image"

    local total; total=$(stat -c '%s' "$image")
    read -r algo offset < <(inspect_image "$image")

    printf "image:        %s\n" "$image"
    printf "total size:   %s bytes\n" "$total"
    if (( offset > 0 )); then
        printf "early-cpio:   bytes 0..%d (%d bytes)\n" "$offset" "$offset"
        printf "main archive: %s, bytes %d..%d (%d bytes)\n" \
            "$algo" "$offset" "$total" $((total - offset))
    else
        printf "main archive: %s (whole image)\n" "$algo"
    fi
}

cmd_unpack() {
    [[ $# -eq 2 ]] || { usage; exit 1; }
    local image=$1 workdir=$2
    [[ -f $image ]] || die "not a file: $image"
    [[ -e $workdir ]] && die "workdir already exists: $workdir"

    read -r algo offset < <(inspect_image "$image")

    mkdir -p "$workdir/main"
    if (( offset > 0 )); then
        head -c "$offset" "$image" > "$workdir/early.cpio"
    fi

    local cmd; cmd=$(decompress_cmd "$algo")
    if (( offset > 0 )); then
        # shellcheck disable=SC2086
        tail -c +$((offset + 1)) "$image" | $cmd | \
            ( cd "$workdir/main" && cpio -idm --quiet \
                --no-absolute-filenames --no-preserve-owner )
    else
        # shellcheck disable=SC2086
        $cmd "$image" | \
            ( cd "$workdir/main" && cpio -idm --quiet \
                --no-absolute-filenames --no-preserve-owner )
    fi

    echo "$algo" > "$workdir/.compression"
    if [[ -f $workdir/early.cpio ]]; then
        printf 'unpacked: %d-byte early section + %s main archive\n  workdir: %s\n' \
            "$offset" "$algo" "$workdir"
    else
        printf 'unpacked: single %s archive\n  workdir: %s\n' "$algo" "$workdir"
    fi
}

cmd_pack() {
    [[ $# -eq 2 ]] || { usage; exit 1; }
    local workdir=$1 out=$2
    [[ -d $workdir ]]              || die "not a directory: $workdir"
    [[ -d $workdir/main ]]         || die "missing $workdir/main"
    [[ -f $workdir/.compression ]] || die "missing $workdir/.compression"

    local algo; algo=$(<"$workdir/.compression")
    local cmd;  cmd=$(compress_cmd "$algo")

    local tmp; tmp=$(mktemp -d)
    # shellcheck disable=SC2064
    trap "rm -rf '$tmp'" EXIT

    # Build and compress the main archive. LC_ALL=C sort gives reproducible
    # cpio entry ordering so identical trees produce identical archives.
    # shellcheck disable=SC2086
    ( cd "$workdir/main" && find . -mindepth 1 -printf '%P\n' | LC_ALL=C sort | \
        cpio -o -H newc -R 0:0 --quiet ) | $cmd > "$tmp/main"

    if [[ -f $workdir/early.cpio ]]; then
        cat "$workdir/early.cpio" "$tmp/main" > "$out"
    else
        cp "$tmp/main" "$out"
    fi

    printf 'packed: %s (%s bytes, main: %s)\n' \
        "$out" "$(stat -c '%s' "$out")" "$algo"
}

main() {
    [[ $# -ge 1 ]] || { usage; exit 1; }
    local cmd=$1; shift
    case "$cmd" in
        -h|--help|help) usage ;;
        info)   cmd_info   "$@" ;;
        unpack) cmd_unpack "$@" ;;
        pack)   cmd_pack   "$@" ;;
        *) usage; exit 1 ;;
    esac
}

main "$@"
