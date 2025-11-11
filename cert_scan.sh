#!/usr/bin/env bash
set -euo pipefail

DIR="${1:-.}"                               # directory to scan (default: current)
TS="$(date -u +%Y%m%d_%H%M%S)"
OUTFILE="${2:-cert_report_${TS}.csv}"       # output CSV path (default uses timestamp)

# CSV header
echo 'Path,IndexInFile,Format,Subject,Issuer,NotBefore,NotAfter,DaysLeft,Serial,SHA256Fingerprint' > "$OUTFILE"

tmpdir="$(mktemp -d)"
trap 'rm -rf "$tmpdir"' EXIT

to_epoch() {
  # Expects something like: "Nov  9 12:34:56 2026 GMT"
  # GNU date on RHEL: use -u to avoid TZ surprises
  date -ud "$1" +%s 2>/dev/null || echo 0
}

emit_row() {
  local path="$1" idx="$2" fmt="$3" certfile="$4"

  # Collect fields (RFC2253 flattens commas/quotes better for CSV usage)
  local subject issuer start end serial fp
  subject="$(openssl x509 -in "$certfile" -noout -subject -nameopt RFC2253 2>/dev/null | sed 's/^subject=//')"
  issuer="$(openssl x509 -in "$certfile" -noout -issuer  -nameopt RFC2253 2>/dev/null | sed 's/^issuer=//')"
  start="$(openssl  x509 -in "$certfile" -noout -startdate 2>/dev/null | cut -d= -f2)"
  end="$(openssl    x509 -in "$certfile" -noout -enddate   2>/dev/null | cut -d= -f2)"
  serial="$(openssl x509 -in "$certfile" -noout -serial    2>/dev/null | cut -d= -f2)"
  fp="$(openssl     x509 -in "$certfile" -noout -fingerprint -sha256 2>/dev/null | cut -d= -f2)"

  local now end_epoch days_left
  now="$(date -u +%s)"
  end_epoch="$(to_epoch "$end")"
  if [[ "$end_epoch" -gt 0 ]]; then
    days_left="$(( (end_epoch - now) / 86400 ))"
  else
    days_left=""
  fi

  # CSV-escape by wrapping fields in double-quotes and doubling any inner quotes
  csv_escape() {
    echo "$1" | sed 's/"/""/g'
  }

  printf '"%s","%s","%s","%s","%s","%s","%s","%s","%s","%s"\n' \
    "$(csv_escape "$path")" \
    "$(csv_escape "$idx")" \
    "$(csv_escape "$fmt")" \
    "$(csv_escape "$subject")" \
    "$(csv_escape "$issuer")" \
    "$(csv_escape "$start")" \
    "$(csv_escape "$end")" \
    "$(csv_escape "$days_left")" \
    "$(csv_escape "$serial")" \
    "$(csv_escape "$fp")" \
    >> "$OUTFILE"
}

process_pem_bundle() {
  local file="$1"
  local base="$tmpdir/$(basename "$file").split"
  # Split by cert boundaries; create parts base.partNN.pem
  awk '
    /-----BEGIN CERTIFICATE-----/ { n++; fn=sprintf("'"$base"'.part%02d.pem", n) }
    { if(fn!=""){ print >> fn } }
    /-----END CERTIFICATE-----/   { close(fn) }
  ' "$file"

  shopt -s nullglob
  local parts=("$base".part*.pem)
  local idx=0
  for p in "${parts[@]}"; do
    idx=$((idx+1))
    emit_row "$file" "$idx" "PEM" "$p"
  done
  shopt -u nullglob
}

process_file() {
  local file="$1"
  # Try PEM first
  if openssl x509 -in "$file" -noout -enddate >/dev/null 2>&1; then
    # If it's a bundle (multiple certs), split; else just emit as single
    local count
    count="$(grep -c '-----BEGIN CERTIFICATE-----' "$file" || true)"
    if [[ "${count:-0}" -gt 1 ]]; then
      process_pem_bundle "$file"
    else
      emit_row "$file" "1" "PEM" "$file"
    fi
    return
  fi

  # Try DER
  local dercopy="$tmpdir/der.tmp"
  if openssl x509 -in "$file" -inform der -noout -enddate >/dev/null 2>&1; then
    # Create a PEM copy in tmp so downstream commands are consistent
    openssl x509 -in "$file" -inform der -out "$dercopy" >/dev/null 2>&1 || true
    emit_row "$file" "1" "DER" "${dercopy}"
    return
  fi

  # Not a cert (or unsupported encoding)
  printf 'WARN: Skipping non-certificate file: %s\n' "$file" >&2
}

# Main scan
# - follow symlinks to files
# - case-insensitive match for .pem/.crt
while IFS= read -r -d '' f; do
  process_file "$f"
done < <(find -L "$DIR" -type f \( -iname '*.pem' -o -iname '*.crt' \) -print0)

echo "Done. CSV saved to: $OUTFILE"
