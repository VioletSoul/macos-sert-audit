#!/bin/sh

set -u

SECURITY=/usr/bin/security
OPENSSL=/usr/bin/openssl
LOGIN_KEYCHAIN="$HOME/Library/Keychains/login.keychain-db"
SYSTEM_KEYCHAIN=/Library/Keychains/System.keychain
SYSTEM_ROOTS=/System/Library/Keychains/SystemRootCertificates.keychain

TMP_DIR=$(mktemp -d "${TMPDIR:-/tmp}/macos-cert-audit.XXXXXX") || {
    echo "failed to create temporary directory" >&2
    exit 1
}

CERT_DB="$TMP_DIR/certificates.tsv"
TRUST_DB="$TMP_DIR/trust.tsv"
WARN_DB="$TMP_DIR/warnings.log"

trap 'rm -rf "$TMP_DIR"' EXIT INT TERM HUP

if [ -t 1 ]; then
    RED=$(printf '\033[31m')
    GREEN=$(printf '\033[32m')
    YELLOW=$(printf '\033[33m')
    BLUE=$(printf '\033[34m')
    CYAN=$(printf '\033[36m')
    BOLD=$(printf '\033[1m')
    RESET=$(printf '\033[0m')
else
    RED=
    GREEN=
    YELLOW=
    BLUE=
    CYAN=
    BOLD=
    RESET=
fi

COMPACT=0
SCAN_ROOTS=1
OUTPUT=report

usage()
{
    cat <<EOF
usage: $0 [options]

  --compact           compact certificate output
  --no-system-roots   skip Apple's System Root store
  --expired           show expired certificates
  --roots             show CA certificates
  --user              show Login Keychain certificates
  --interesting       show potentially interesting certificates
  --data              print collected TSV data
  --trust             print explicit trust settings
  --help              show this help
EOF
    exit 0
}

header()
{
    printf '\n%s== %s ==%s\n' "$CYAN" "$1" "$RESET"
}

warn()
{
    printf '%s\n' "$1" >> "$WARN_DB"
}

split_pem()
{
    input=$1
    output=$2

    mkdir -p "$output" || return 1

    awk -v output="$output" '
        /-----BEGIN CERTIFICATE-----/ {
            n++
            file=sprintf("%s/cert_%05d.pem", output, n)
        }
        file != "" {
            print > file
        }
        /-----END CERTIFICATE-----/ {
            close(file)
            file=""
        }
    ' "$input"
}

collect_keychain()
{
    keychain=$1
    store=$2

    [ -f "$keychain" ] || return 0

    pem="$TMP_DIR/$(basename "$keychain").pem"
    dir="$TMP_DIR/$(basename "$keychain")"

    if ! "$SECURITY" find-certificate -a -p "$keychain" > "$pem" 2>/dev/null; then
        warn "Could not read certificate store: $store ($keychain)"
        return 0
    fi

    [ -s "$pem" ] || return 0

    if ! split_pem "$pem" "$dir"; then
        warn "Could not split PEM output for store: $store"
        return 0
    fi

    for cert in "$dir"/cert_*.pem; do
        [ -f "$cert" ] || continue

        subject=$(
            "$OPENSSL" x509 -in "$cert" -noout -subject 2>/dev/null |
            sed 's/^subject=//'
        )

        issuer=$(
            "$OPENSSL" x509 -in "$cert" -noout -issuer 2>/dev/null |
            sed 's/^issuer=//'
        )

        serial=$(
            "$OPENSSL" x509 -in "$cert" -noout -serial 2>/dev/null |
            sed 's/^serial=//'
        )

        not_before=$(
            "$OPENSSL" x509 -in "$cert" -noout -startdate 2>/dev/null |
            sed 's/^notBefore=//'
        )

        not_after=$(
            "$OPENSSL" x509 -in "$cert" -noout -enddate 2>/dev/null |
            sed 's/^notAfter=//'
        )

        sha256=$(
            "$OPENSSL" x509 -in "$cert" -noout -fingerprint -sha256 2>/dev/null |
            sed 's/^.*Fingerprint=//'
        )

        cert_text=$(
            "$OPENSSL" x509 -in "$cert" -noout -text 2>/dev/null
        ) || {
            warn "Could not parse certificate in store: $store"
            continue
        }

        constraints=$(
            printf '%s\n' "$cert_text" |
            awk '
                /X509v3 Basic Constraints:/ {
                    getline
                    gsub(/^[[:space:]]+|[[:space:]]+$/, "")
                    print
                    exit
                }
            '
        )

        key_usage=$(
            printf '%s\n' "$cert_text" |
            awk '
                /X509v3 Key Usage:/ {
                    getline
                    gsub(/^[[:space:]]+|[[:space:]]+$/, "")
                    print
                    exit
                }
            '
        )

        ca=0
        self_issued=0
        expired=0

        case "$constraints" in
            *CA:TRUE*) ca=1 ;;
        esac

        # Same subject and issuer means self-issued.
        # This does not by itself prove that the certificate is self-signed.
        [ "$subject" = "$issuer" ] && self_issued=1

        "$OPENSSL" x509 -in "$cert" -noout -checkend 0 >/dev/null 2>&1 ||
            expired=1

        printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
            "$store" \
            "$subject" \
            "$issuer" \
            "$serial" \
            "$not_before" \
            "$not_after" \
            "$sha256" \
            "$ca" \
            "$self_issued" \
            "$expired" \
            "$key_usage" >> "$CERT_DB"
    done
}

collect_trust()
{
    : > "$TRUST_DB"

    "$SECURITY" dump-trust-settings 2>/dev/null |
    awk '
        /Cert  [0-9]+:/ { cert=$0 }
        /Number of trust settings/ { print "USER\t" cert "\t" $0 }
        /Policy OID/ { print "USER\t" cert "\t" $0 }
        /Result Type/ { print "USER\t" cert "\t" $0 }
    ' >> "$TRUST_DB"

    "$SECURITY" dump-trust-settings -d 2>/dev/null |
    awk '
        /Cert  [0-9]+:/ { cert=$0 }
        /Number of trust settings/ { print "ADMIN\t" cert "\t" $0 }
        /Policy OID/ { print "ADMIN\t" cert "\t" $0 }
        /Result Type/ { print "ADMIN\t" cert "\t" $0 }
    ' >> "$TRUST_DB"

    "$SECURITY" dump-trust-settings -s 2>/dev/null |
    awk '
        /Cert  [0-9]+:/ { cert=$0 }
        /Number of trust settings/ { print "SYSTEM\t" cert "\t" $0 }
        /Policy OID/ { print "SYSTEM\t" cert "\t" $0 }
        /Result Type/ { print "SYSTEM\t" cert "\t" $0 }
    ' >> "$TRUST_DB"
}

report_all()
{
    header "Certificates"

    if [ "$COMPACT" -eq 1 ]; then
        awk -F '\t' '
            NR > 1 {
                printf "%-24s %-60s CA=%s SELF_ISSUED=%s EXPIRED=%s\n",
                    $1, substr($2, 1, 60), $8, $9, $10
            }
        ' "$CERT_DB"
        return
    fi

    count=0

    tail -n +2 "$CERT_DB" |
    while IFS="$(printf '\t')" read -r store subject issuer serial not_before not_after sha256 ca self_issued expired key_usage
    do
        count=$((count + 1))

        printf '\n%s[%s]%s\n' "$BOLD" "$count" "$RESET"
        printf 'Store       : %s\n' "$store"
        printf 'Subject     : %s\n' "$subject"
        printf 'Issuer      : %s\n' "$issuer"
        printf 'Serial      : %s\n' "$serial"
        printf 'From        : %s\n' "$not_before"
        printf 'Until       : %s\n' "$not_after"
        printf 'SHA-256     : %s\n' "$sha256"
        printf 'CA          : %s\n' "$ca"
        printf 'Self-issued : %s\n' "$self_issued"

        if [ "$expired" -eq 1 ]; then
            printf '%sStatus      : EXPIRED%s\n' "$RED" "$RESET"
        else
            printf '%sStatus      : VALID%s\n' "$GREEN" "$RESET"
        fi

        [ -n "$key_usage" ] &&
            printf 'Key Usage   : %s\n' "$key_usage"
    done
}

report_expired()
{
    header "Expired Certificates"

    awk -F '\t' '
        NR > 1 && $10 == 1 {
            printf "%-24s %s\n", $1, $2
        }
    ' "$CERT_DB"
}

report_roots()
{
    header "CA Certificates"

    awk -F '\t' '
        NR > 1 && $8 == 1 {
            printf "%-24s %s\n", $1, $2
        }
    ' "$CERT_DB"
}

report_user()
{
    header "Login Keychain Certificates"

    awk -F '\t' '
        NR > 1 && $1 == "Login Keychain" {
            printf "%s | CA=%s | SELF_ISSUED=%s | EXPIRED=%s\n",
                $2, $8, $9, $10
        }
    ' "$CERT_DB"
}

report_interesting()
{
    header "Interesting Certificates"

    awk -F '\t' '
        NR > 1 {
            if ($10 == 1)
                printf "[EXPIRED] %s | %s\n", $1, $2

            if ($1 == "Login Keychain" && $8 == 1)
                printf "[USER_CA] %s | %s\n", $1, $2

            if ($1 == "Login Keychain" && $9 == 1 && $8 == 0)
                printf "[USER_SELF_ISSUED] %s | %s\n", $1, $2

            if ($1 == "System Keychain" && $8 == 1 && $9 == 1)
                printf "[SYSTEM_SELF_ISSUED_CA] %s | %s\n", $1, $2
        }
    ' "$CERT_DB"
}

report_data()
{
    cat "$CERT_DB"
}

report_trust()
{
    header "Explicit Trust Settings"

    if [ -s "$TRUST_DB" ]; then
        cat "$TRUST_DB"
    else
        echo "No explicit trust settings found."
    fi
}

report_warnings()
{
    if [ -s "$WARN_DB" ]; then
        header "Warnings"
        cat "$WARN_DB"
    fi
}

while [ $# -gt 0 ]; do
    case "$1" in
        --compact) COMPACT=1 ;;
        --no-system-roots) SCAN_ROOTS=0 ;;
        --expired) OUTPUT=expired ;;
        --roots) OUTPUT=roots ;;
        --user) OUTPUT=user ;;
        --interesting) OUTPUT=interesting ;;
        --data) OUTPUT=data ;;
        --trust) OUTPUT=trust ;;
        --help) usage ;;
        *)
            echo "unknown option: $1" >&2
            usage
            ;;
    esac
    shift
done

[ -x "$SECURITY" ] || {
    echo "security command not found: $SECURITY" >&2
    exit 1
}

[ -x "$OPENSSL" ] || {
    echo "openssl command not found: $OPENSSL" >&2
    exit 1
}

: > "$WARN_DB"

printf 'store\tsubject\tissuer\tserial\tnot_before\tnot_after\tsha256\tca\tself_issued\texpired\tkey_usage\n' \
    > "$CERT_DB"

if [ "$SCAN_ROOTS" -eq 1 ]; then
    collect_keychain "$SYSTEM_ROOTS" "System Root Certificates"
fi

collect_keychain "$SYSTEM_KEYCHAIN" "System Keychain"
collect_keychain "$LOGIN_KEYCHAIN" "Login Keychain"

collect_trust

case "$OUTPUT" in
    report)
        printf '%s\n' 'macOS Certificate Audit'
        printf '%s\n' '-----------------------'

        HOST=$(scutil --get ComputerName 2>/dev/null || hostname)
        HOST=$(printf '%s' "$HOST" | sed 's/^"//;s/"$//')

        printf 'Host : %s\n' "$HOST"
        printf 'macOS: %s (%s)\n' \
            "$(sw_vers -productVersion 2>/dev/null)" \
            "$(sw_vers -buildVersion 2>/dev/null)"
        printf 'Arch : %s\n' "$(uname -m)"
        printf 'Date : %s\n' "$(date '+%Y-%m-%d %H:%M:%S %Z')"

        report_all
        ;;
    expired)
        report_expired
        ;;
    roots)
        report_roots
        ;;
    user)
        report_user
        ;;
    interesting)
        report_interesting
        ;;
    data)
        report_data
        ;;
    trust)
        report_trust
        ;;
esac

if [ "$OUTPUT" = "report" ]; then
    header "Profiles / MDM"

    if command -v profiles >/dev/null 2>&1; then
        profiles status -type enrollment 2>/dev/null || true
        echo
        profiles list -type configuration 2>/dev/null || true
    else
        echo "profiles command not found."
    fi

    header "Summary"

    ROOT_COUNT=$(
        awk -F '\t' '
            NR > 1 && $1 == "System Root Certificates" { n++ }
            END { print n+0 }
        ' "$CERT_DB"
    )

    SYSTEM_COUNT=$(
        awk -F '\t' '
            NR > 1 && $1 == "System Keychain" { n++ }
            END { print n+0 }
        ' "$CERT_DB"
    )

    LOGIN_COUNT=$(
        awk -F '\t' '
            NR > 1 && $1 == "Login Keychain" { n++ }
            END { print n+0 }
        ' "$CERT_DB"
    )

    CA_COUNT=$(
        awk -F '\t' '
            NR > 1 && $8 == 1 { n++ }
            END { print n+0 }
        ' "$CERT_DB"
    )

    SELF_ISSUED_COUNT=$(
        awk -F '\t' '
            NR > 1 && $9 == 1 { n++ }
            END { print n+0 }
        ' "$CERT_DB"
    )

    EXPIRED_COUNT=$(
        awk -F '\t' '
            NR > 1 && $10 == 1 { n++ }
            END { print n+0 }
        ' "$CERT_DB"
    )

    printf 'System Roots : %s\n' "$ROOT_COUNT"
    printf 'System       : %s\n' "$SYSTEM_COUNT"
    printf 'Login        : %s\n' "$LOGIN_COUNT"
    printf 'CA           : %s\n' "$CA_COUNT"
    printf 'Self-issued  : %s\n' "$SELF_ISSUED_COUNT"
    printf 'Expired      : %s\n' "$EXPIRED_COUNT"

    if [ "$EXPIRED_COUNT" -gt 0 ]; then
        printf '%s[!] expired certificates present; review trust and usage before taking action%s\n' \
            "$YELLOW" "$RESET"
    else
        printf '%s[+] no expired certificates%s\n' "$GREEN" "$RESET"
    fi

    report_warnings

    printf '\nNo changes were made.\n'
fi
