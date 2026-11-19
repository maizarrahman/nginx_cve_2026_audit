#!/usr/bin/env bash
# Read-only audit for NGINX CVEs. Detect package source and compare each CVE
# against its own upstream fixed-version threshold. Ubuntu backport caveat is
# shown only for Ubuntu-origin packages with versions below upstream fix.
set -u
NGINX_BIN="${NGINX_BIN:-nginx}"
RED='\033[0;31m'; YELLOW='\033[1;33m'; GREEN='\033[0;32m'; CYAN='\033[0;36m'; RESET='\033[0m'
WARNINGS=0; INFO=0
info(){ echo -e "${CYAN}[INFO]${RESET} $*"; ((INFO+=1)); }
warn(){ echo -e "${YELLOW}[WARN]${RESET} $*"; ((WARNINGS+=1)); }
critical(){ echo -e "${RED}[RISK]${RESET} $*"; ((WARNINGS+=1)); }
ok(){ echo -e "${GREEN}[OK]${RESET} $*"; }
section(){ echo; echo '------------------------------------------------------------'; echo "$*"; echo '------------------------------------------------------------'; }
# Compare dotted numeric versions (ignores package epoch/revision when passed clean versions).
version_ge(){ awk -v a="$1" -v b="$2" 'BEGIN { split(a,A,"."); split(b,B,"."); for(i=1;i<=4;i++){x=A[i]+0;y=B[i]+0;if(x>y)exit 0;if(x<y)exit 1}exit 0 }'; }
version_lt(){ if version_ge "$1" "$2"; then return 1; else return 0; fi; }
extract_version(){ printf '%s\n' "$1" | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1; }
clean_pkg_version(){ # strip epoch and Debian revision, then extract upstream dotted version
  local v="$1"; v="${v#*:}"; v="${v%%-*}"; extract_version "$v"
}

printf '%s\n' '============================================================' ' NGINX CVE AUDIT (read-only)' '============================================================'
section '1. NGINX BINARY'
if ! command -v "$NGINX_BIN" >/dev/null 2>&1; then critical "NGINX binary not found: $NGINX_BIN (set NGINX_BIN=/path/to/nginx)"; exit 1; fi
NGINX_PATH="$(command -v "$NGINX_BIN")"
NGINX_V="$("$NGINX_BIN" -v 2>&1)"; NGINX_VV="$("$NGINX_BIN" -V 2>&1)"
echo "$NGINX_V"
VERSION="$(extract_version "$NGINX_V")"
if [[ -z "$VERSION" ]]; then critical 'Unable to parse upstream version.'; VERSION=unknown; else info "Parsed upstream version: $VERSION"; fi
echo 'Build flags:'; echo "$NGINX_VV" | grep -oE -- '--with-[^ ]+|--without-[^ ]+' || true

section '2. PACKAGE INFORMATION / REPOSITORY ORIGIN'
PKG_NAME=''; PKG_VERSION=''; PKG_SOURCE='unknown'; REPO_POLICY=''
if command -v dpkg-query >/dev/null 2>&1; then
  OWNER_LINE="$(dpkg-query -S "$NGINX_PATH" 2>/dev/null | head -1 || true)"
  PKG_NAME="${OWNER_LINE%%:*}"
  if [[ -n "$OWNER_LINE" && "$OWNER_LINE" != "$NGINX_PATH" ]]; then
    PKG_VERSION="$(dpkg-query -W -f='${Version}' "$PKG_NAME" 2>/dev/null || true)"
    echo "Package: $PKG_NAME"; echo "Package version: $PKG_VERSION"
    if command -v apt-cache >/dev/null 2>&1; then REPO_POLICY="$(apt-cache policy "$PKG_NAME" 2>/dev/null || true)"; fi
    # Only inspect repository entries associated with the installed version, not all configured repos.
    INSTALLED_ORIGINS="$(echo "$REPO_POLICY" | awk -v v="$PKG_VERSION" '($1==v || $2==v) {found=1; next} found && /^[[:space:]]*\*?\*?\*?[[:space:]]*[0-9]+\.[0-9]+\.[0-9]+/ {exit} found && /https?:\/\// {print}')"
    if echo "$INSTALLED_ORIGINS" | grep -qi 'nginx\.org'; then PKG_SOURCE='nginx.org'
    elif echo "$INSTALLED_ORIGINS" | grep -Eqi 'archive\.ubuntu\.com|security\.ubuntu\.com|ubuntu|launchpad'; then PKG_SOURCE='Ubuntu'
    elif echo "$INSTALLED_ORIGINS" | grep -Eqi 'deb\.debian\.org|debian'; then PKG_SOURCE='Debian'
    elif [[ -n "$INSTALLED_ORIGINS" ]]; then PKG_SOURCE='other APT repository'
    else PKG_SOURCE='unknown APT origin'; fi
    echo "Repository origin (heuristic): $PKG_SOURCE"
    echo 'APT policy:'; echo "$REPO_POLICY" | sed -n '1,12p'
  fi
fi
if [[ -z "$PKG_VERSION" ]] && command -v rpm >/dev/null 2>&1; then
  PKG_NAME="$(rpm -qf "$NGINX_PATH" 2>/dev/null || true)"
  PKG_VERSION="$(rpm -q --qf '%{VERSION}-%{RELEASE}' "$PKG_NAME" 2>/dev/null || true)"
  [[ -n "$PKG_VERSION" ]] && echo "Package: $PKG_NAME" && echo "Package version: $PKG_VERSION"
  PKG_SOURCE='RPM repository (not classified)'
fi
[[ -n "$PKG_VERSION" ]] || info 'No OS package metadata detected (possibly custom/source install).'

section '3. ACTIVE CONFIGURATION DUMP'
NGINX_CONFIG="$($NGINX_BIN -T 2>&1)"
if [[ $? -ne 0 ]]; then critical 'nginx -T failed; check permissions/config.'; echo "$NGINX_CONFIG"; exit 1; fi
CONFIG_ACTIVE="$(echo "$NGINX_CONFIG" | sed '/^[[:space:]]*#/d' | sed '/^[[:space:]]*$/d')"
echo 'Included configuration files:'; echo "$NGINX_CONFIG" | grep -E '^# configuration file ' || true

section '4. HTTP/2 AND HTTP/3 DETECTION'
HTTP2_ACTIVE=0; HTTP3_ACTIVE=0
if echo "$CONFIG_ACTIVE" | grep -Eq 'listen[^;]*http2|http2[[:space:]]+on[[:space:]]*;'; then HTTP2_ACTIVE=1; critical 'HTTP/2 activation pattern found.'; else ok 'No HTTP/2 activation pattern found.'; fi
if echo "$CONFIG_ACTIVE" | grep -Eq 'listen[^;]*quic|http3[[:space:]]+on[[:space:]]*;'; then HTTP3_ACTIVE=1; critical 'HTTP/3/QUIC activation pattern found.'; else ok 'No HTTP/3/QUIC activation pattern found.'; fi

section '5. FEATURE HEURISTICS'
RESOLVER_ACTIVE=0; DYNAMIC_PROXY=0; MIRROR_ACTIVE=0; MIRROR_BODY_OFF=0; SSI_ACTIVE=0; MAIL_BLOCK=0; MAIL_PROXY=0; AUTH_HTTP=0; PROXY_ACTIVE=0
if echo "$CONFIG_ACTIVE" | grep -Eq '^[[:space:]]*resolver[[:space:]]'; then RESOLVER_ACTIVE=1; warn 'resolver directive found.'; else ok 'No resolver directive detected.'; fi
if echo "$CONFIG_ACTIVE" | grep -Eq 'proxy_pass[[:space:]]+[^;]*\$'; then DYNAMIC_PROXY=1; warn 'Variable-based proxy_pass detected.'; else ok 'No variable-based proxy_pass detected.'; fi
if echo "$CONFIG_ACTIVE" | grep -Eq '^[[:space:]]*proxy_pass[[:space:]]'; then PROXY_ACTIVE=1; fi
if echo "$CONFIG_ACTIVE" | grep -Eq '^[[:space:]]*mirror[[:space:]]+[^;]*;'; then MIRROR_ACTIVE=1; warn 'mirror directive found.'; fi
if echo "$CONFIG_ACTIVE" | grep -Eq 'mirror_request_body[[:space:]]+off[[:space:]]*;'; then MIRROR_BODY_OFF=1; warn 'mirror_request_body off found.'; fi
if echo "$CONFIG_ACTIVE" | grep -Eq '^[[:space:]]*ssi[[:space:]]+on[[:space:]]*;'; then SSI_ACTIVE=1; warn 'SSI enabled.'; fi
if echo "$CONFIG_ACTIVE" | grep -Eq '^[[:space:]]*mail[[:space:]]*\{'; then MAIL_BLOCK=1; warn 'mail{} block detected.'; fi
if echo "$CONFIG_ACTIVE" | grep -Eq '^[[:space:]]*proxy[[:space:]]+on[[:space:]]*;'; then MAIL_PROXY=1; warn 'mail proxy on detected.'; fi
if echo "$CONFIG_ACTIVE" | grep -Eq '^[[:space:]]*auth_http[[:space:]]'; then AUTH_HTTP=1; warn 'auth_http directive detected.'; fi

section '6. PER-CVE VERSION COMPARISON'
# nginx.org advisory: stable fixed 1.30.7+, mainline fixed 1.31.9+.
# CVE-specific minimum affected versions are reflected in feature checks below.
FIX_STABLE='1.30.7'; FIX_MAINLINE='1.31.9'
if [[ "$VERSION" == unknown ]]; then UPSTREAM_FIXED=0; warn 'Unable to determine upstream version for comparisons.'
elif { version_ge "$VERSION" "$FIX_STABLE" && version_lt "$VERSION" '1.31.0'; } || version_ge "$VERSION" "$FIX_MAINLINE"; then UPSTREAM_FIXED=1; ok "Version $VERSION meets upstream fixed thresholds ($FIX_STABLE stable / $FIX_MAINLINE mainline)."
else UPSTREAM_FIXED=0; warn "Version $VERSION is below upstream fixed thresholds."; fi

assess_cve(){ # name, minimum affected upstream, feature-exposure flag, description
  local cve="$1" min="$2" exposed="$3" label="$4"
  echo "[$cve] $label"
  if [[ "$VERSION" == unknown ]]; then warn "$cve: version comparison unavailable; manual assessment required."; return; fi
  if [[ "$UPSTREAM_FIXED" -eq 1 ]]; then ok "$cve: version $VERSION is upstream-fixed."; return; fi
  if version_lt "$VERSION" "$min"; then ok "$cve: version $VERSION predates affected range ($min); version-based not affected."; return; fi
  if [[ "$exposed" -eq 0 ]]; then ok "$cve: affected version range, but configuration trigger not detected."; return; fi
  critical "$cve: version $VERSION is in affected range and configuration trigger detected. Upgrade recommended." 
}

section '7. CVE ASSESSMENT (version + configuration)'
assess_cve 'CVE-2026-123007' '1.9.5' "$HTTP2_ACTIVE" 'HTTP/2 flow-control memory corruption'
assess_cve 'CVE-2026-123633' '1.19.7' "$((HTTP2_ACTIVE && PROXY_ACTIVE))" 'HTTP/2 use-after-free (proxying condition heuristic)'
assess_cve 'CVE-2026-121810' '1.25.0' "$HTTP3_ACTIVE" 'HTTP/3 / QUIC use-after-free'
# Resolver flaw: dynamic proxy target and mirror subrequest with request body disabled,
# OR SSI subrequest path; SSI detection is a heuristic, not proof of same-name resolution.
RESOLVER_TRIGGER=0
if [[ "$RESOLVER_ACTIVE" -eq 1 && "$DYNAMIC_PROXY" -eq 1 && ( ( "$MIRROR_ACTIVE" -eq 1 && "$MIRROR_BODY_OFF" -eq 1 ) || "$SSI_ACTIVE" -eq 1 ) ]]; then RESOLVER_TRIGGER=1; fi
assess_cve 'CVE-2026-123634' '0.6.18' "$RESOLVER_TRIGGER" 'Resolver use-after-free (resolver + variable proxy + mirror/body-off or SSI heuristic)'
assess_cve 'CVE-2026-113425' '0.5.33' "$((MAIL_BLOCK && MAIL_PROXY && AUTH_HTTP))" 'Mail proxy use-after-free (mail + proxy + auth_http)'

section '8. PACKAGE BACKPORT NOTE (CONDITIONAL)'
case "$PKG_SOURCE" in
  Ubuntu)
    if [[ "$UPSTREAM_FIXED" -eq 0 ]]; then warn 'Ubuntu-origin package detected. Ubuntu may backport security fixes; this script does not query Ubuntu CVE status/changelog, so upstream version alone is not definitive.'
    else ok 'Ubuntu-origin package version meets upstream fixed threshold; no backport caveat needed for these CVEs.'; fi
    ;;
  nginx.org)
    ok 'nginx.org repository detected. Ubuntu backport caveat suppressed; compare against nginx.org upstream fixed versions.'
    ;;
  Debian)
    if [[ "$UPSTREAM_FIXED" -eq 0 ]]; then warn 'Debian-origin package detected. Debian may backport fixes; this script does not query Debian tracker/changelog.'; fi
    ;;
  *) info "Repository origin '$PKG_SOURCE'; no distro-specific backport caveat generated." ;;
esac

section '9. RECOMMENDATIONS'
echo '1) Upgrade to nginx.org fixed stable 1.30.7+ or mainline 1.31.9+ (or vendor-fixed package).'
echo '2) Interim mitigation: disable HTTP/2 and HTTP/3/QUIC if not required.'
echo '3) Review resolver + request-derived proxy_pass + mirror/body-off or SSI subrequest combination.'
echo '4) Disable mail proxy/auth_http if unused; otherwise restrict access.'
echo '5) Restart NGINX after patch so old worker processes are replaced.'
echo '6) Review logs for worker exits/crashes; this audit is not proof of exploitation.'
section 'SUMMARY'
echo "Package origin: $PKG_SOURCE | Package version: ${PKG_VERSION:-unknown} | Upstream version: $VERSION"
echo "Warnings: $WARNINGS | Info: $INFO"
echo 'Audit completed; no config changes were made.'
