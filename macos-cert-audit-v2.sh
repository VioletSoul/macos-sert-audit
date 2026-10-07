#!/bin/sh
#
# macOS Certificate Audit v2
# Read-only certificate / trust / profile audit.
#
# Structural note: self-issued-but-not-self-signed is inventory metadata, not
# a security finding by itself; it is intentionally kept out of findings.
#
# Canonical certificate identity: SHA-256 fingerprint.
# Designed for macOS /bin/sh (POSIX shell).
#

VERSION="2"
PROG="macOS Certificate Audit"

SECURITY=/usr/bin/security
OPENSSL=/usr/bin/openssl
DATE=/bin/date
SW_VERS=/usr/bin/sw_vers
HOSTNAME=/bin/hostname
UNAME=/usr/bin/uname
SYSTEM_PROFILER=/usr/sbin/system_profiler
SED=/usr/bin/sed
AWK=/usr/bin/awk
GREP=/usr/bin/grep
SORT=/usr/bin/sort
UNIQ=/usr/bin/uniq
WC=/usr/bin/wc
TR=/usr/bin/tr
CUT=/usr/bin/cut
HEAD=/usr/bin/head
MKDIR=/bin/mkdir
RM=/bin/rm
MKDTEMP=/usr/bin/mktemp
CAT=/bin/cat
PRINTF=/usr/bin/printf
MV=/bin/mv
BASENAME=/usr/bin/basename

ROOT_STORE="/System/Library/Keychains/SystemRootCertificates.keychain"
SYSTEM_STORE="/Library/Keychains/System.keychain"
LOGIN_STORE="$HOME/Library/Keychains/login.keychain-db"

MODE="all"
TMPDIR_AUDIT=""
CERT_DIR=""
PEM_DIR=""
CERT_TSV=""
FINDINGS_TSV=""
TRUST_TSV=""
PROFILES_TSV=""

# ---------------------------------------------------------------------------
# Terminal colors. printf creates a real ESC byte; no literal "\\033" output.
# ---------------------------------------------------------------------------

if [ -t 1 ]; then
    C_RESET=$(printf '\033[0m')
    C_BOLD=$(printf '\033[1m')
    C_DIM=$(printf '\033[2m')
    C_RED=$(printf '\033[31m')
    C_GREEN=$(printf '\033[32m')
    C_YELLOW=$(printf '\033[33m')
    C_BLUE=$(printf '\033[34m')
    C_MAGENTA=$(printf '\033[35m')
    C_CYAN=$(printf '\033[36m')
    C_WHITE=$(printf '\033[37m')
else
    C_RESET=''
    C_BOLD=''
    C_DIM=''
    C_RED=''
    C_GREEN=''
    C_YELLOW=''
    C_BLUE=''
    C_MAGENTA=''
    C_CYAN=''
    C_WHITE=''
fi

cleanup()
{
    if [ -n "$TMPDIR_AUDIT" ] && [ -d "$TMPDIR_AUDIT" ]; then
        "$RM" -rf "$TMPDIR_AUDIT"
    fi
}

trap 'cleanup' 0 1 2 3 15

usage()
{
    "$PRINTF" '%s\n' \
        "Usage: $0 [--all|--inventory|--trust|--forensic|--json]" \
        "" \
        "Modes:" \
        "  --all         Full human-readable audit (default)" \
        "  --inventory   Certificate inventory" \
        "  --trust       Trust configuration" \
        "  --forensic    Detailed certificate inventory" \
        "  --json        Machine-readable JSON" \
        "  -h, --help    Show this help"
}

while [ "$#" -gt 0 ]; do
    case "$1" in
        --all) MODE="all" ;;
        --inventory) MODE="inventory" ;;
        --trust) MODE="trust" ;;
        --forensic) MODE="forensic" ;;
        --json) MODE="json" ;;
        -h|--help) usage; exit 0 ;;
        *)
            "$PRINTF" '%s\n' "Unknown option: $1" >&2
            usage >&2
            exit 2
            ;;
    esac
    shift
 done

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

one_line()
{
    "$TR" '\n\r\t' '   ' | "$SED" 's/[ ][ ]*/ /g; s/^ *//; s/ *$//'
}

json_escape()
{
    "$SED" 's/\\/\\\\/g; s/"/\\"/g; s/\t/\\t/g' | "$TR" '\n\r' '  '
}

now_string()
{
    "$DATE" '+%Y-%m-%d %H:%M:%S %Z'
}

sha256_of_pem()
{
    "$OPENSSL" x509 -in "$1" -noout -fingerprint -sha256 2>/dev/null \
        | "$SED" 's/^SHA256 Fingerprint=//' \
        | "$TR" ':' ':' \
        | "$TR" '[:lower:]' '[:upper:]'
}

sha1_of_pem()
{
    "$OPENSSL" x509 -in "$1" -noout -fingerprint -sha1 2>/dev/null \
        | "$SED" 's/^SHA1 Fingerprint=//' \
        | "$TR" '[:lower:]' '[:upper:]'
}

field_of()
{
    field="$1"
    "$OPENSSL" x509 -in "$2" -noout "$field" 2>/dev/null \
        | "$SED" "s/^[^=]*=//" \
        | one_line
}

subject_of() { field_of -subject "$1"; }
issuer_of() { field_of -issuer "$1"; }
serial_of() { field_of -serial "$1"; }
not_after_of() { field_of -enddate "$1"; }
not_before_of() { field_of -startdate "$1"; }

signature_alg_of()
{
    "$OPENSSL" x509 -in "$1" -noout -text 2>/dev/null \
        | "$AWK" '/Signature Algorithm:/{print $3; exit}' \
        | one_line
}

basic_constraints_of()
{
    "$OPENSSL" x509 -in "$1" -noout -text 2>/dev/null \
        | "$AWK" '
            /X509v3 Basic Constraints:/{seen=1; next}
            seen && /^[[:space:]]/ {gsub(/^[[:space:]]+/, ""); print; exit}
            seen {exit}
        ' | one_line
}

ca_flag_of()
{
    bc=$(basic_constraints_of "$1")
    case "$bc" in
        *CA:TRUE*|*CA:true*) printf '%s\n' yes ;;
        *) printf '%s\n' no ;;
    esac
}

pathlen_of()
{
    bc=$(basic_constraints_of "$1")
    printf '%s\n' "$bc" | "$SED" -n 's/.*pathlen:\([0-9][0-9]*\).*/\1/p'
}

key_usage_of()
{
    "$OPENSSL" x509 -in "$1" -noout -text 2>/dev/null \
        | "$AWK" '
            /X509v3 Key Usage:/{seen=1; next}
            seen && /^[[:space:]]/ {gsub(/^[[:space:]]+/, ""); print; exit}
            seen {exit}
        ' | one_line
}

ek_usage_of()
{
    "$OPENSSL" x509 -in "$1" -noout -text 2>/dev/null \
        | "$AWK" '
            /X509v3 Extended Key Usage:/{seen=1; next}
            seen && /^[[:space:]]/ {gsub(/^[[:space:]]+/, ""); print; exit}
            seen {exit}
        ' | one_line
}

san_of()
{
    "$OPENSSL" x509 -in "$1" -noout -text 2>/dev/null \
        | "$AWK" '
            /X509v3 Subject Alternative Name:/{seen=1; next}
            seen && /^[[:space:]]/ {gsub(/^[[:space:]]+/, ""); print; exit}
            seen {exit}
        ' | one_line
}

ski_of()
{
    "$OPENSSL" x509 -in "$1" -noout -text 2>/dev/null \
        | "$AWK" '
            /X509v3 Subject Key Identifier:/{seen=1; next}
            seen && /^[[:space:]]/ {gsub(/^[[:space:]]+/, ""); print; exit}
            seen {exit}
        ' | one_line
}

aki_of()
{
    "$OPENSSL" x509 -in "$1" -noout -text 2>/dev/null \
        | "$AWK" '
            /X509v3 Authority Key Identifier:/{seen=1; next}
            seen && /^[[:space:]]/ {gsub(/^[[:space:]]+/, ""); print; exit}
            seen {exit}
        ' | one_line
}

policies_of()
{
    "$OPENSSL" x509 -in "$1" -noout -text 2>/dev/null \
        | "$AWK" '
            /X509v3 Certificate Policies:/{seen=1; next}
            seen && /^[[:space:]]/ {gsub(/^[[:space:]]+/, ""); print; exit}
            seen {exit}
        ' | one_line
}

key_info_of()
{
    "$OPENSSL" x509 -in "$1" -noout -text 2>/dev/null \
        | "$AWK" '
            /Public Key Algorithm:/{alg=$0; sub(/^.*Public Key Algorithm: /, "", alg); next}
            /Public-Key:/{bits=$0; sub(/^.*Public-Key: /, "", bits); print alg "; " bits; exit}
        ' | one_line
}

ec_curve_of()
{
    "$OPENSSL" x509 -in "$1" -noout -text 2>/dev/null \
        | "$AWK" '/ASN1 OID:/{print $3; exit}' | one_line
}

is_expired()
{
    "$OPENSSL" x509 -in "$1" -checkend 0 -noout >/dev/null 2>&1
    if [ "$?" -eq 0 ]; then
        printf '%s\n' no
    else
        printf '%s\n' yes
    fi
}

is_not_yet_valid()
{
    nb=$(not_before_of "$1")
    if [ -z "$nb" ]; then
        printf '%s\n' no
        return
    fi
    ts=$($DATE -j -f '%b %e %T %Y %Z' "$nb" '+%s' 2>/dev/null)
    now=$($DATE '+%s' 2>/dev/null)
    case "$ts" in
        ''|*[!0-9]*) printf '%s\n' no ;;
        *)
            if [ "$ts" -gt "$now" ]; then
                printf '%s\n' yes
            else
                printf '%s\n' no
            fi
            ;;
    esac
}

is_self_issued()
{
    subj=$(subject_of "$1")
    issuer=$(issuer_of "$1")
    if [ -n "$subj" ] && [ -n "$issuer" ] && [ "$subj" = "$issuer" ]; then
        printf '%s\n' yes
    else
        printf '%s\n' no
    fi
}

is_self_signed()
{
    "$OPENSSL" verify -CAfile "$1" "$1" >/dev/null 2>&1
    if [ "$?" -eq 0 ]; then
        printf '%s\n' yes
    else
        printf '%s\n' no
    fi
}

vendor_of()
{
    subject_of "$1" | "$GREP" -Eqi '(^|[ /])O *= *Apple( Inc\.| Computer Inc\.)' && {
        printf '%s\n' Apple
        return
    }
    issuer_of "$1" | "$GREP" -Eqi '(^|[ /])O *= *Apple( Inc\.| Computer Inc\.)' && {
        printf '%s\n' Apple
        return
    }
    printf '%s\n' Non-Apple
}

role_of()
{
    ca="$2"
    selfsigned="$3"
    if [ "$ca" = yes ] && [ "$selfsigned" = yes ]; then
        printf '%s\n' 'ROOT CA'
    elif [ "$ca" = yes ]; then
        printf '%s\n' 'INTERMEDIATE CA'
    else
        printf '%s\n' LEAF
    fi
}

signature_is_sha1()
{
    alg=$(signature_alg_of "$1")
    case "$alg" in
        *sha1*|*SHA1*) printf '%s\n' yes ;;
        *) printf '%s\n' no ;;
    esac
}

rsa_bits_of()
{
    key=$(key_info_of "$1")
    printf '%s\n' "$key" | "$SED" -n 's/.*(\([0-9][0-9]*\) bit).*/\1/p'
}

key_alg_of()
{
    key_info_of "$1" | "$SED" 's/;.*//'
}

is_weak_rsa()
{
    alg=$(key_alg_of "$1")
    case "$alg" in
        rsaEncryption|RSA|rsaEncryption,*)
            bits=$(rsa_bits_of "$1")
            case "$bits" in
                ''|*[!0-9]*) printf '%s\n' no ;;
                *)
                    if [ "$bits" -lt 1024 ]; then
                        printf '%s\n' critical
                    elif [ "$bits" -lt 2048 ]; then
                        printf '%s\n' warning
                    else
                        printf '%s\n' no
                    fi
                    ;;
            esac
            ;;
        *) printf '%s\n' no ;;
    esac
}

find_cert_by_sha()
{
    "$AWK" -F '\t' -v s="$1" '$6 == s {print; exit}' "$CERT_TSV"
}

store_has()
{
    printf '%s\n' "$1" | "$AWK" -F ';' -v x="$2" '{for (i=1;i<=NF;i++) if ($i==x) found=1} END{if(found) print "yes"; else print "no"}'
}

append_store_membership()
{
    sha="$1"
    store="$2"
    path="$3"
    tmp="$TMPDIR_AUDIT/membership.$$.tmp"
    "$AWK" -F '\t' -v sha="$sha" -v store="$store" -v path="$path" '
        BEGIN {OFS="\t"}
        $6 == sha {
            ns=$2; np=$3
            has=0; n=split(ns,a,";"); for(i=1;i<=n;i++) if(a[i]==store) has=1
            if(!has) ns=ns=="" ? store : ns ";" store
            has=0; n=split(np,b,";"); for(i=1;i<=n;i++) if(b[i]==path) has=1
            if(!has) np=np=="" ? path : np ";" path
            $2=ns; $3=np
        }
        {print}
    ' "$CERT_TSV" > "$tmp" && "$MV" "$tmp" "$CERT_TSV"
}

record_finding()
{
    # sha severity code category subject store role detail action
    "$PRINTF" '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' "$1" "$2" "$3" "$4" "$5" "$6" "$7" "$8" "$9" >> "$FINDINGS_TSV"
}

# ---------------------------------------------------------------------------
# Store scanner
# ---------------------------------------------------------------------------

scan_store()
{
    store_name="$1"
    store_path="$2"
    outdir="$PEM_DIR/$store_name"
    "$MKDIR" -p "$outdir"

    if [ ! -r "$store_path" ]; then
        return
    fi

    raw="$TMPDIR_AUDIT/$store_name.pem"
    "$SECURITY" find-certificate -a -p "$store_path" > "$raw" 2>/dev/null || return

    "$AWK" -v dir="$outdir" '
        /-----BEGIN CERTIFICATE-----/ {
            n++
            file=sprintf("%s/cert-%04d.pem", dir, n)
        }
        file != "" {print > file}
        /-----END CERTIFICATE-----/ {close(file)}
    ' "$raw"

    for pem in "$outdir"/*.pem; do
        [ -f "$pem" ] || continue

        sha256=$(sha256_of_pem "$pem")
        [ -n "$sha256" ] || continue

        existing=$(find_cert_by_sha "$sha256")
        if [ -n "$existing" ]; then
            append_store_membership "$sha256" "$store_name" "$store_path"
            continue
        fi

        sha1=$(sha1_of_pem "$pem")
        subject=$(subject_of "$pem")
        issuer=$(issuer_of "$pem")
        serial=$(serial_of "$pem")
        not_before=$(not_before_of "$pem")
        not_after=$(not_after_of "$pem")
        ca=$(ca_flag_of "$pem")
        pathlen=$(pathlen_of "$pem")
        self_issued=$(is_self_issued "$pem")
        self_signed=$(is_self_signed "$pem")
        expired=$(is_expired "$pem")
        not_yet=$(is_not_yet_valid "$pem")
        vendor=$(vendor_of "$pem")
        key_alg=$(key_alg_of "$pem")
        key_strength=$(key_info_of "$pem" | "$SED" 's/^[^;]*; *//')
        signature_alg=$(signature_alg_of "$pem")
        basic_constraints=$(basic_constraints_of "$pem")
        key_usage=$(key_usage_of "$pem")
        eku=$(ek_usage_of "$pem")
        san=$(san_of "$pem")
        ski=$(ski_of "$pem")
        aki=$(aki_of "$pem")
        policies=$(policies_of "$pem")
        ec_curve=$(ec_curve_of "$pem")
        role=$(role_of "$pem" "$ca" "$self_signed")

        "$PRINTF" '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
            "$sha256" "$store_name" "$store_path" "$subject" "$issuer" "$sha256" "$sha1" "$role" "$ca" "$pathlen" \
            "$self_issued" "$self_signed" "$expired" "$not_yet" "$vendor" "$key_alg" "$key_strength" "$signature_alg" \
            "$basic_constraints" "$key_usage" "$eku" "$san" "$ski" "$aki" "$policies" "$ec_curve" >> "$CERT_TSV"

        if [ "$expired" = yes ]; then
            if [ "$vendor" = Apple ]; then
                record_finding "$sha256" INFO EXPIRED_APPLE STALE "$subject" "$store_name" "$role" "Expired Apple certificate." "Usually stale; do not remove blindly."
            elif [ "$store_name" = 'System Keychain' ] && [ "$role" != 'ROOT CA' ]; then
                record_finding "$sha256" WARNING EXPIRED_CUSTOM_SYSTEM STALE "$subject" "$store_name" "$role" "Expired non-Apple certificate in System Keychain." "Identify owner/application before removal."
            elif [ "$store_name" = 'System Keychain' ] && [ "$role" = 'ROOT CA' ]; then
                record_finding "$sha256" WARNING EXPIRED_CUSTOM_SYSTEM_CA STALE "$subject" "$store_name" "$role" "Expired non-Apple CA in System Keychain." "Verify whether intentionally installed."
            elif [ "$store_name" = 'Login Keychain' ] && [ "$vendor" != Apple ]; then
                record_finding "$sha256" INFO EXPIRED_LOGIN STALE "$subject" "$store_name" "$role" "Expired non-Apple certificate in Login Keychain." "Identify owner before removal."
            fi
        fi

        if [ "$not_yet" = yes ]; then
            record_finding "$sha256" WARNING NOT_YET_VALID SECURITY "$subject" "$store_name" "$role" "Certificate is not yet valid." "Check system time and certificate deployment."
        fi

        weak=$(is_weak_rsa "$pem")
        if [ "$weak" = critical ]; then
            record_finding "$sha256" CRITICAL WEAK_RSA SECURITY "$subject" "$store_name" "$role" "RSA key is below 1024 bits." "Replace the certificate and key."
        elif [ "$weak" = warning ]; then
            record_finding "$sha256" WARNING WEAK_RSA SECURITY "$subject" "$store_name" "$role" "RSA key is below 2048 bits." "Replace the certificate and key."
        fi

        sha1sig=$(signature_is_sha1 "$pem")
        if [ "$sha1sig" = yes ] && [ "$role" != 'ROOT CA' ]; then
            record_finding "$sha256" WARNING SHA1_SIGNATURE LEGACY_CRYPTO "$subject" "$store_name" "$role" "Certificate signature uses SHA-1." "Prefer a SHA-256-or-better replacement where supported."
        fi

        if [ "$ca" = yes ] && [ "$vendor" != Apple ] && { [ "$store_name" = 'System Keychain' ] || [ "$store_name" = 'Login Keychain' ]; }; then
            if [ "$store_name" = 'System Keychain' ]; then
                record_finding "$sha256" WARNING CUSTOM_CA_SYSTEM CUSTOM "$subject" "$store_name" "$role" "Non-Apple CA installed in System Keychain." "Verify that the CA is intentional and required."
            else
                record_finding "$sha256" INFO CUSTOM_CA_LOGIN CUSTOM "$subject" "$store_name" "$role" "Non-Apple CA installed in Login Keychain." "Verify that the CA is intentional and required."
            fi
        fi

            done
}

scan_all()
{
    scan_store 'System Root Certificates' "$ROOT_STORE"
    scan_store 'System Keychain' "$SYSTEM_STORE"
    scan_store 'Login Keychain' "$LOGIN_STORE"
}

# ---------------------------------------------------------------------------
# Trust settings
# ---------------------------------------------------------------------------

scan_trust_domain()
{
    domain="$1"
    args=''
    if [ "$domain" = admin ]; then
        args='-d'
    fi

    raw="$TMPDIR_AUDIT/trust-$domain.txt"
    if [ "$domain" = admin ]; then
        "$SECURITY" dump-trust-settings -d > "$raw" 2>/dev/null || :
    else
        "$SECURITY" dump-trust-settings > "$raw" 2>/dev/null || :
    fi

    if [ ! -s "$raw" ]; then
        return
    fi

    # Keep a normalized record for every certificate block. The exact textual
    # representation differs across macOS releases, so we retain the useful
    # trust terms without inventing certificate identities.
    current=''
    result=''
    policy=''
    rules=0
    while IFS= read -r line; do
        case "$line" in
            Cert\ *)
                if [ -n "$current" ]; then
                    "$PRINTF" '%s\t%s\t%s\t%s\t%s\n' "$domain" "$current" "$result" "$policy" "$rules" >> "$TRUST_TSV"
                fi
                current=$(printf '%s\n' "$line" | one_line)
                result=''
                policy=''
                rules=0
                ;;
            *Result[[:space:]]Type[[:space:]]*:[[:space:]]*)
                result=$(printf '%s\n' "$line" | one_line)
                rules=$((rules + 1))
                ;;
            *Policy[[:space:]]OID[[:space:]]*:[[:space:]]*|*Policy[[:space:]]String[[:space:]]*:[[:space:]]*)
                p=$(printf '%s\n' "$line" | one_line)
                if [ -z "$policy" ]; then policy="$p"; else policy="$policy; $p"; fi
                ;;
        esac
    done < "$raw"

    if [ -n "$current" ]; then
        "$PRINTF" '%s\t%s\t%s\t%s\t%s\n' "$domain" "$current" "$result" "$policy" "$rules" >> "$TRUST_TSV"
    fi
}

scan_trust()
{
    : > "$TRUST_TSV"
    scan_trust_domain user
    scan_trust_domain admin
}

# ---------------------------------------------------------------------------
# Profiles / enrollment
# ---------------------------------------------------------------------------

scan_profiles()
{
    : > "$PROFILES_TSV"
    if command -v profiles >/dev/null 2>&1; then
        if profiles status -type enrollment > "$TMPDIR_AUDIT/enrollment.txt" 2>&1; then
            "$CAT" "$TMPDIR_AUDIT/enrollment.txt" | one_line > "$PROFILES_TSV"
        else
            "$CAT" "$TMPDIR_AUDIT/enrollment.txt" | one_line > "$PROFILES_TSV"
        fi

        profiles list -type configuration > "$TMPDIR_AUDIT/profiles.txt" 2>&1 || :
        "$AWK" '
            /profileIdentifier:/ {
                sub(/^.*profileIdentifier:[[:space:]]*/, "")
                gsub(/[[:space:]]+$/, "")
                if ($0 != "") print $0
            }
        ' "$TMPDIR_AUDIT/profiles.txt" | "$SORT" -u >> "$PROFILES_TSV"
    fi
}

# ---------------------------------------------------------------------------
# Counts
# ---------------------------------------------------------------------------

count_lines()
{
    "$AWK" 'END{print NR+0}' "$1"
}

count_field()
{
    "$AWK" -F '\t' -v col="$1" -v val="$2" '$col==val{n++} END{print n+0}' "$3"
}

count_store()
{
    "$AWK" -F '\t' -v s="$1" '$2==s{n++} END{print n+0}' "$CERT_TSV"
}

count_store_expired()
{
    "$AWK" -F '\t' -v s="$1" '$2==s && $13=="yes"{n++} END{print n+0}' "$CERT_TSV"
}

count_vendor_expired()
{
    "$AWK" -F '\t' -v v="$1" '$13=="yes" && $15==v{n++} END{print n+0}' "$CERT_TSV"
}

count_actionable_expired()
{
    "$AWK" -F '\t' '($13=="yes" && $15!="Apple" && ($2=="System Keychain" || $2=="Login Keychain")){n++} END{print n+0}' "$CERT_TSV"
}

count_stale_expired()
{
    total=$(count_field 13 yes "$CERT_TSV")
    actionable=$(count_actionable_expired)
    printf '%s\n' $((total-actionable))
}

count_role()
{
    count_field 8 "$1" "$CERT_TSV"
}

count_sha1_role()
{
    "$AWK" -F '\t' -v role="$1" 'tolower($18) ~ /sha1/ && $8==role{n++} END{print n+0}' "$CERT_TSV"
}

# ---------------------------------------------------------------------------
# Rendering
# ---------------------------------------------------------------------------

section()
{
    "$PRINTF" '\n%s%s== %s ==%s\n' "$C_BOLD" "$C_BLUE" "$1" "$C_RESET"
}

kv()
{
    label="$1"
    value="$2"
    width=30
    "$PRINTF" '  %s%-30s%s %s\n' "$C_DIM" "$label" "$C_RESET" "$value"
}

severity_color()
{
    case "$1" in
        CRITICAL) printf '%s' "$C_RED" ;;
        WARNING) printf '%s' "$C_YELLOW" ;;
        INFO) printf '%s' "$C_CYAN" ;;
        *) printf '%s' "$C_WHITE" ;;
    esac
}

print_header()
{
    model=$($SYSTEM_PROFILER SPHardwareDataType 2>/dev/null | "$AWK" -F ': ' '/Model Name:/{print $2; exit}')
    [ -n "$model" ] || model=$($SYSTEM_PROFILER SPHardwareDataType 2>/dev/null | "$AWK" -F ': ' '/Model Identifier:/{print $2; exit}')
    os=$($SW_VERS -productVersion 2>/dev/null)
    build=$($SW_VERS -buildVersion 2>/dev/null)
    host=$($HOSTNAME 2>/dev/null)
    arch=$($UNAME -m 2>/dev/null)
    openssl_version=$($OPENSSL version 2>/dev/null)

    "$PRINTF" '%s%s%s%s\n' "$C_BOLD" "$C_CYAN" "$PROG v$VERSION" "$C_RESET"
    "$PRINTF" '%s%s%s\n' "$C_CYAN" '================================' "$C_RESET"
    kv 'Host' "$host"
    kv 'Model' "$model"
    kv 'macOS' "$os ($build)"
    kv 'Architecture' "$arch"
    kv 'OpenSSL' "$openssl_version"
    kv 'Date' "$(now_string)"
    "$PRINTF" '\n%sMode        :%s %sREAD-ONLY%s\n' "$C_DIM" "$C_RESET" "$C_GREEN" "$C_RESET"
    "$PRINTF" '%sArchitecture:%s %scanonical certificate model%s\n' "$C_DIM" "$C_RESET" "$C_GREEN" "$C_RESET"
}

render_inventory()
{
    section 'Certificate Inventory'
    total=$(count_lines "$CERT_TSV")
    roots=$(count_store 'System Root Certificates')
    system=$(count_store 'System Keychain')
    login=$(count_store 'Login Keychain')
    ca=$(count_field 9 yes "$CERT_TSV")
    roots_self=$(count_role 'ROOT CA')
    inter=$(count_role 'INTERMEDIATE CA')
    leaf=$(count_role LEAF)
    self_issued=$(count_field 11 yes "$CERT_TSV")
    self_signed=$(count_field 12 yes "$CERT_TSV")
    not_selfsigned=$((self_issued-self_signed))

    kv 'Certificate entries scanned' "$total"
    kv 'Unique certificates' "$total"
    kv '  System Root Certificates' "$roots"
    kv '  System Keychain' "$system"
    kv '  Login Keychain' "$login"
    kv 'CA certificates' "$ca"
    kv 'Self-signed roots' "$roots_self"
    kv 'Intermediate CAs' "$inter"
    kv 'Leaf certificates' "$leaf"
    kv 'Self-issued' "$self_issued"
    kv 'Cryptographically self-signed' "$self_signed"
    kv 'Self-issued, not self-signed' "$not_selfsigned"
}

render_expiration()
{
    section 'Expiration'
    total=$(count_field 13 yes "$CERT_TSV")
    future=$(count_field 14 yes "$CERT_TSV")
    roots=$(count_store_expired 'System Root Certificates')
    system=$(count_store_expired 'System Keychain')
    login=$(count_store_expired 'Login Keychain')
    apple=$(count_vendor_expired Apple)
    nonapple=$(count_vendor_expired Non-Apple)
    actionable=$(count_actionable_expired)
    stale=$(count_stale_expired)

    kv 'Total expired' "${C_YELLOW}${total}${C_RESET}"
    kv 'Not yet valid' "${C_GREEN}${future}${C_RESET}"
    kv '  System Root Certificates' "$roots"
    kv '  System Keychain' "$system"
    kv '  Login Keychain' "$login"
    kv 'Apple' "$apple"
    kv 'Non-Apple' "$nonapple"
    kv 'Actionable expired' "$actionable"
    kv 'Stale / informational expired' "${C_CYAN}${stale}${C_RESET}"
}

render_crypto()
{
    section 'Cryptography'
    roots_sha1=$(count_sha1_role 'ROOT CA')
    inter_sha1=$(count_sha1_role 'INTERMEDIATE CA')
    leaf_sha1=$(count_sha1_role LEAF)
    weak=$($AWK -F '\t' '
        $17 ~ /^rsa/i {
            if ($18 ~ /\([0-9]+ bit\)/) {
                s=$18
                sub(/^.*\(/,"",s); sub(/ bit\).*$/,"",s)
                if ((s+0)<2048) n++
            }
        }
        END{print n+0}
    ' "$CERT_TSV")

    kv 'Legacy SHA-1 roots' "${C_CYAN}${roots_sha1}${C_RESET}"
    kv 'SHA-1 intermediates' "$inter_sha1"
    kv 'SHA-1 leaf certificates' "$leaf_sha1"
    kv 'Weak RSA keys (<2048)' "$weak"
    "$PRINTF" '\n  %sNote:%s SHA-1 roots are legacy inventory, not individual security findings.\n' "$C_DIM" "$C_RESET"
}

render_custom()
{
    section 'Custom / Non-Apple CAs'
    system=$(count_field 6 'System Keychain' "$FINDINGS_TSV")
    login=$(count_field 6 'Login Keychain' "$FINDINGS_TSV")
    # Findings can include more than one code per cert, so calculate directly
    # from the canonical certificate DB as well.
    system_ca=$($AWK -F '\t' '$2=="System Keychain" && $9=="yes" && $15!="Apple"{n++} END{print n+0}' "$CERT_TSV")
    login_ca=$($AWK -F '\t' '$2=="Login Keychain" && $9=="yes" && $15!="Apple"{n++} END{print n+0}' "$CERT_TSV")
    kv 'System Keychain' "$system_ca"
    kv 'Login Keychain' "$login_ca"
}

render_trust()
{
    section 'Trust Configuration'
    user=$(count_field 1 user "$TRUST_TSV")
    admin=$(count_field 1 admin "$TRUST_TSV")
    user_rules=$($AWK -F '\t' '$1=="user" {n += $5} END{print n+0}' "$TRUST_TSV")
    admin_rules=$($AWK -F '\t' '$1=="admin" {n += $5} END{print n+0}' "$TRUST_TSV")

    if [ "$user" -eq 0 ]; then
        kv 'User trust entries' 'none'
    else
        kv 'User trust entries' "$user"
        kv 'User explicit rules' "$user_rules"
    fi

    if [ "$admin" -eq 0 ]; then
        kv 'Admin trust entries' 'none'
    else
        kv 'Admin trust entries' "$admin"
        kv 'Admin explicit rules' "$admin_rules"
    fi

    kv 'System trust' 'built-in root store'
}

render_profiles()
{
    section 'Configuration Profiles / MDM'
    if [ ! -s "$PROFILES_TSV" ]; then
        kv 'Profiles data' 'unavailable'
        return
    fi
    if "$GREP" -qi 'MDM enrollment: Yes\|MDM enrollment: true\|Enrolled via DEP: Yes' "$PROFILES_TSV"; then
        kv 'Enrollment' 'detected'
    else
        kv 'Enrollment' 'not detected'
    fi
    ids=$("GREP" -E '^[^ ]+\.[^ ]+\.[^ ]+$' "$PROFILES_TSV" 2>/dev/null | "$SORT" -u)
    if [ -n "$ids" ]; then
        n=$(printf '%s\n' "$ids" | "$WC" -l | "$SED" 's/ //g')
        kv 'Configuration profile identifiers' "$n"
        printf '%s\n' "$ids" | while IFS= read -r id; do
            [ -n "$id" ] && "$PRINTF" '    %s%s%s\n' "$C_DIM" "$id" "$C_RESET"
        done
    fi
}

render_findings()
{
    section 'Findings'
    if [ ! -s "$FINDINGS_TSV" ]; then
        "$PRINTF" '  %sNo findings recorded.%s\n' "$C_GREEN" "$C_RESET"
        return
    fi

    # Aggregate findings by canonical SHA-256 and render directly from awk.
    # This avoids shell IFS/read portability problems with tab-separated data.
    "$AWK" -F '\t' \
        -v red="$C_RED" \
        -v yellow="$C_YELLOW" \
        -v cyan="$C_CYAN" \
        -v white="$C_WHITE" \
        -v reset="$C_RESET" \
        -v dim="$C_DIM" \
    '
        function rank(s) {
            if (s == "CRITICAL") return 3
            if (s == "WARNING") return 2
            return 1
        }
        function maxsev(a,b) {
            return rank(b) > rank(a) ? b : a
        }
        {
            sha=$1
            if (!(sha in seen)) {
                seen[sha]=1
                order[++n]=sha
                subject[sha]=$5
                store[sha]=$6
                role[sha]=$7
                severity[sha]=$2
            } else {
                severity[sha]=maxsev(severity[sha], $2)
            }

            if (codes[sha] != "") codes[sha]=codes[sha] ", " $3
            else codes[sha]=$3

            if (details[sha] != "") details[sha]=details[sha] " | " $8
            else details[sha]=$8

            if (actions[sha] != "") actions[sha]=actions[sha] " | " $9
            else actions[sha]=$9
        }
        END {
            for (i=1; i<=n; i++) {
                sha=order[i]
                sev=severity[sha]
                color=white
                if (sev == "CRITICAL") color=red
                else if (sev == "WARNING") color=yellow
                else if (sev == "INFO") color=cyan

                printf "\n  %s[%s]%s %s\n", color, sev, reset, subject[sha]
                printf "    %sSHA-256:%s %s\n", dim, reset, sha
                printf "    %sStore:%s    %s\n", dim, reset, store[sha]
                printf "    %sRole:%s     %s\n", dim, reset, role[sha]
                printf "    %sCodes:%s    %s\n", dim, reset, codes[sha]
                printf "    %sDetails:%s  %s\n", dim, reset, details[sha]
                printf "    %sAction:%s   %s\n", dim, reset, actions[sha]
            }
        }
    ' "$FINDINGS_TSV"
}

render_legacy_roots()
{
    count=$(count_sha1_role 'ROOT CA')
    section 'Legacy SHA-1 Root Inventory'
    kv 'Count' "$count"
    [ "$MODE" = forensic ] || return
    "$AWK" -F '\t' '$8=="ROOT CA" && tolower($18) ~ /sha1/ {print "  " $4 " | " $6}' "$CERT_TSV"
}

render_forensic()
{
    section 'Forensic Certificate Inventory'
    "$AWK" -F '\t' 'BEGIN{OFS="\n"} {
        print "  Subject: " $4,
        "  Issuer: " $5,
        "  SHA-256: " $6,
        "  SHA-1: " $7,
        "  Role: " $8,
        "  CA: " $9,
        "  Self-issued: " $11,
        "  Self-signed: " $12,
        "  Expired: " $13,
        "  Not yet valid: " $14,
        "  Vendor: " $15,
        "  Key: " $16 " / " $17,
        "  Signature: " $18,
        "  Basic Constraints: " $19,
        "  Key Usage: " $20,
        "  EKU: " $21,
        "  SAN: " $22,
        "  SKI: " $23,
        "  AKI: " $24,
        "  Policies: " $25,
        "  EC curve: " $26,
        "  Stores: " $2,
        "  Paths: " $3,
        ""
    }' "$CERT_TSV"
}

# ---------------------------------------------------------------------------
# JSON
# ---------------------------------------------------------------------------

render_json()
{
    printf '{\n'
    printf '  "version": "%s",\n' "$VERSION"
    printf '  "mode": "read-only",\n'
    printf '  "certificates": [\n'
    first=1
    while IFS=$(printf '\t') read -r sha256 stores paths subject issuer sha256_dup sha1 role ca pathlen self_issued self_signed expired not_yet vendor key_alg key_strength signature_alg bc ku eku san ski aki policies ec_curve; do
        [ -n "$sha256" ] || continue
        [ "$first" -eq 1 ] || printf ',\n'
        first=0
        printf '    {"sha256":"%s","sha1":"%s","subject":"%s","issuer":"%s","role":"%s","ca":%s,"self_issued":%s,"self_signed":%s,"expired":%s,"not_yet_valid":%s,"vendor":"%s","stores":"%s"}' \
            "$(printf '%s' "$sha256" | json_escape)" \
            "$(printf '%s' "$sha1" | json_escape)" \
            "$(printf '%s' "$subject" | json_escape)" \
            "$(printf '%s' "$issuer" | json_escape)" \
            "$(printf '%s' "$role" | json_escape)" \
            "$( [ "$ca" = yes ] && printf true || printf false )" \
            "$( [ "$self_issued" = yes ] && printf true || printf false )" \
            "$( [ "$self_signed" = yes ] && printf true || printf false )" \
            "$( [ "$expired" = yes ] && printf true || printf false )" \
            "$( [ "$not_yet" = yes ] && printf true || printf false )" \
            "$(printf '%s' "$vendor" | json_escape)" \
            "$(printf '%s' "$stores" | json_escape)"
    done < "$CERT_TSV"
    printf '\n  ],\n  "findings": [\n'
    first=1
    while IFS=$(printf '\t') read -r sha severity code category subject store role detail action; do
        [ -n "$sha" ] || continue
        [ "$first" -eq 1 ] || printf ',\n'
        first=0
        printf '    {"sha256":"%s","severity":"%s","code":"%s","category":"%s","subject":"%s","store":"%s","role":"%s","detail":"%s","action":"%s"}' \
            "$(printf '%s' "$sha" | json_escape)" "$severity" "$code" "$category" \
            "$(printf '%s' "$subject" | json_escape)" "$(printf '%s' "$store" | json_escape)" "$role" \
            "$(printf '%s' "$detail" | json_escape)" "$(printf '%s' "$action" | json_escape)"
    done < "$FINDINGS_TSV"
    printf '\n  ]\n}\n'
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

TMPDIR_AUDIT=$($MKDTEMP -d "${TMPDIR:-/tmp}/macos-cert-audit.XXXXXX") || exit 1
CERT_DIR="$TMPDIR_AUDIT/certs"
PEM_DIR="$TMPDIR_AUDIT/pems"
CERT_TSV="$TMPDIR_AUDIT/certificates.tsv"
FINDINGS_TSV="$TMPDIR_AUDIT/findings.tsv"
TRUST_TSV="$TMPDIR_AUDIT/trust.tsv"
PROFILES_TSV="$TMPDIR_AUDIT/profiles.tsv"

$MKDIR -p "$CERT_DIR" "$PEM_DIR"
: > "$CERT_TSV"
: > "$FINDINGS_TSV"
: > "$TRUST_TSV"
: > "$PROFILES_TSV"

scan_all
scan_trust
scan_profiles

case "$MODE" in
    json)
        render_json
        ;;
    inventory)
        print_header
        render_inventory
        render_expiration
        render_crypto
        render_custom
        ;;
    trust)
        print_header
        render_trust
        ;;
    forensic)
        print_header
        render_inventory
        render_expiration
        render_crypto
        render_custom
        render_trust
        render_profiles
        render_legacy_roots
        render_forensic
        ;;
    all)
        print_header
        section 'Executive Assessment'
        critical=$(count_field 2 CRITICAL "$FINDINGS_TSV")
        warnings=$(count_field 2 WARNING "$FINDINGS_TSV")
        info=$(count_field 2 INFO "$FINDINGS_TSV")
        actionable=$(count_actionable_expired)
        if [ "$critical" -gt 0 ]; then
            assessment="CRITICAL"
            assessment_color="$C_RED"
        elif [ "$warnings" -gt 0 ]; then
            assessment="REVIEW"
            assessment_color="$C_YELLOW"
        else
            assessment="PASS"
            assessment_color="$C_GREEN"
        fi
        kv 'Security assessment' "${assessment_color}${assessment}${C_RESET}"
        kv 'Critical findings' "$critical"
        kv 'Review / warnings' "$warnings"
        kv 'Informational items' "$info"
        kv 'Actionable objects' "$actionable"
        render_inventory
        render_expiration
        render_crypto
        render_custom
        render_trust
        render_profiles
        render_findings
        ;;
esac
