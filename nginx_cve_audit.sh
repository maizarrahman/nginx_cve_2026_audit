#!/usr/bin/env bash
# Read-only audit for five NGINX CVEs discussed:
# CVE-2026-123007, CVE-2026-123633, CVE-2026-121810,
# CVE-2026-123634, CVE-2026-113425
set -u
NGINX_BIN="${NGINX_BIN:-nginx}"
RED='\033[0;31m'; YELLOW='\033[1;33m'; GREEN='\033[0;32m'; CYAN='\033[0;36m'; RESET='\033[0m'
WARNINGS=0; INFO=0
info(){ echo -e "${CYAN}[INFO]${RESET} $*"; ((INFO++)); }
warn(){ echo -e "${YELLOW}[WARN]${RESET} $*"; ((WARNINGS++)); }
critical(){ echo -e "${RED}[RISK]${RESET} $*"; ((WARNINGS++)); }
ok(){ echo -e "${GREEN}[OK]${RESET} $*"; }
section(){ echo; echo '------------------------------------------------------------'; echo "$*"; echo '------------------------------------------------------------'; }
# Return success if dotted numeric version $1 >= $2
version_ge(){ awk -v a="$1" -v b="$2" 'BEGIN { split(a,A,"."); split(b,B,"."); for(i=1;i<=4;i++){x=A[i]+0;y=B[i]+0;if(x>y)exit 0;if(x<y)exit 1}exit 0 }'; }
version_lt(){ if version_ge "$1" "$2"; then return 1; else return 0; fi; }
extract_version(){ echo "$1" | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1; }

echo '============================================================'
echo ' NGINX CVE AUDIT (read-only)'
echo '============================================================'
section '1. NGINX BINARY'
if ! command -v "$NGINX_BIN" >/dev/null 2>&1; then
  critical "NGINX binary not found: $NGINX_BIN (set NGINX_BIN=/path/to/nginx)"; exit 1
fi
NGINX_V="$("$NGINX_BIN" -v 2>&1)"
NGINX_VV="$("$NGINX_BIN" -V 2>&1)"
echo "$NGINX_V"
VERSION="$(extract_version "$NGINX_V")"
if [[ -z "$VERSION" ]]; then critical 'Unable to parse upstream version.'; VERSION=unknown; else info "Parsed upstream version: $VERSION"; fi
echo 'Build flags:'; echo "$NGINX_VV" | grep -oE -- '--with-[^ ]+|--without-[^ ]+' || true

section '2. PACKAGE INFORMATION'
PKG_VERSION=''; PKG_NAME='unknown'
if command -v dpkg-query >/dev/null 2>&1; then
  PKG_NAME="$(dpkg-query -S "$(command -v "$NGINX_BIN")" 2>/dev/null | head -1 | cut -d: -f1 || true)"
  if [[ -n "$PKG_NAME" ]]; then PKG_VERSION="$(dpkg-query -W -f='${Version}' "$PKG_NAME" 2>/dev/null || true)"; echo "Package: $PKG_NAME"; echo "Package version: $PKG_VERSION"; fi
fi
if [[ -z "$PKG_VERSION" ]] && command -v rpm >/dev/null 2>&1; then
  PKG_NAME="$(rpm -qf "$(command -v "$NGINX_BIN")" 2>/dev/null || true)"
  PKG_VERSION="$(rpm -q --qf '%{VERSION}-%{RELEASE}' "$PKG_NAME" 2>/dev/null || true)"
  [[ -n "$PKG_VERSION" ]] && echo "Package: $PKG_NAME" && echo "Package version: $PKG_VERSION"
fi
[[ -n "$PKG_VERSION" ]] || info 'No OS package metadata detected (possibly custom/source install).'

section '3. ACTIVE CONFIGURATION DUMP'
NGINX_CONFIG="$("$NGINX_BIN" -T 2>&1)"
if [[ $? -ne 0 ]]; then critical 'nginx -T failed; check permissions/config.'; echo "$NGINX_CONFIG"; exit 1; fi
CONFIG_ACTIVE="$(echo "$NGINX_CONFIG" | sed '/^[[:space:]]*#/d' | sed '/^[[:space:]]*$/d')"
echo 'Included configuration files:'; echo "$NGINX_CONFIG" | grep -E '^# configuration file ' || true

section '4. HTTP/2 AND HTTP/3 DETECTION'
HTTP2_ACTIVE=0; HTTP3_ACTIVE=0
if echo "$CONFIG_ACTIVE" | grep -Eq 'listen[^;]*http2|http2[[:space:]]+on[[:space:]]*;'; then HTTP2_ACTIVE=1; critical 'HTTP/2 activation pattern found.'; else ok 'No HTTP/2 activation pattern found.'; fi
if echo "$CONFIG_ACTIVE" | grep -Eq 'listen[^;]*quic|http3[[:space:]]+on[[:space:]]*;'; then HTTP3_ACTIVE=1; critical 'HTTP/3/QUIC activation pattern found.'; else ok 'No HTTP/3/QUIC activation pattern found.'; fi

section '5. FEATURE HEURISTICS'
RESOLVER_ACTIVE=0; DYNAMIC_PROXY=0; MIRROR_ACTIVE=0; MIRROR_BODY_OFF=0; SSI_ACTIVE=0; MAIL_BLOCK=0; MAIL_PROXY=0; AUTH_HTTP=0
if echo "$CONFIG_ACTIVE" | grep -Eq '^[[:space:]]*resolver[[:space:]]'; then RESOLVER_ACTIVE=1; warn 'resolver directive found.'; else ok 'No resolver directive detected.'; fi
if echo "$CONFIG_ACTIVE" | grep -Eq 'proxy_pass[[:space:]]+[^;]*\$'; then DYNAMIC_PROXY=1; warn 'Variable-based proxy_pass detected.'; else ok 'No variable-based proxy_pass detected.'; fi
if echo "$CONFIG_ACTIVE" | grep -Eq '^[[:space:]]*mirror[[:space:]]+[^;]*;'; then MIRROR_ACTIVE=1; warn 'mirror directive found.'; fi
if echo "$CONFIG_ACTIVE" | grep -Eq 'mirror_request_body[[:space:]]+off[[:space:]]*;'; then MIRROR_BODY_OFF=1; warn 'mirror_request_body off found.'; fi
if echo "$CONFIG_ACTIVE" | grep -Eq '^[[:space:]]*ssi[[:space:]]+on[[:space:]]*;'; then SSI_ACTIVE=1; warn 'SSI enabled.'; fi
if echo "$CONFIG_ACTIVE" | grep -Eq '^[[:space:]]*mail[[:space:]]*\{'; then MAIL_BLOCK=1; warn 'mail{} block detected.'; fi
if echo "$CONFIG_ACTIVE" | grep -Eq '^[[:space:]]*proxy[[:space:]]+on[[:space:]]*;'; then MAIL_PROXY=1; warn 'mail proxy on detected.'; fi
if echo "$CONFIG_ACTIVE" | grep -Eq '^[[:space:]]*auth_http[[:space:]]'; then AUTH_HTTP=1; warn 'auth_http directive detected.'; fi

section '6. UPSTREAM VERSION THRESHOLD'
PATCHED=0
if [[ "$VERSION" != unknown ]]; then
  if { version_ge "$VERSION" 1.30.7 && version_lt "$VERSION" 1.31.0; } || version_ge "$VERSION" 1.31.9; then PATCHED=1; ok "Version $VERSION is at/above upstream fixed threshold."; else warn "Version $VERSION is below upstream fixed thresholds (backport may exist)."; fi
else warn 'Version comparison unavailable.'; fi

section '7. CVE ASSESSMENT'
echo '[CVE-2026-123007] HTTP/2 flow-control memory corruption'
if [[ $HTTP2_ACTIVE -eq 1 ]]; then if [[ $PATCHED -eq 1 ]]; then ok 'HTTP/2 active, version meets upstream fixed threshold.'; else critical 'HTTP/2 active on a version below upstream fixed threshold.'; echo '  Mitigation: disable HTTP/2; upgrade to patched vendor package or upstream 1.30.7/1.31.9.'; fi; else ok 'HTTP/2 not detected; feature-based mitigation appears in place.'; fi

echo '[CVE-2026-123633] HTTP/2 use-after-free'
if [[ $HTTP2_ACTIVE -eq 1 && $DYNAMIC_PROXY -eq 1 ]]; then if [[ $PATCHED -eq 1 ]]; then ok 'HTTP/2 + variable proxy pattern found; version meets upstream fixed threshold.'; else critical 'HTTP/2 + variable proxy pattern found on older upstream version.'; echo '  Mitigation: disable HTTP/2; upgrade. Review proxy/upstream and worker connection capacity.'; fi; elif [[ $HTTP2_ACTIVE -eq 1 ]]; then warn 'HTTP/2 is enabled, but proxy condition was not detected; manual review advised.'; else ok 'HTTP/2 not detected; feature-based mitigation appears in place.'; fi

echo '[CVE-2026-121810] HTTP/3 / QUIC use-after-free'
if [[ $HTTP3_ACTIVE -eq 1 && $DYNAMIC_PROXY -eq 1 ]]; then if [[ $PATCHED -eq 1 ]]; then ok 'HTTP/3 + proxy pattern found; version meets upstream fixed threshold.'; else critical 'HTTP/3 + proxy pattern found on older upstream version.'; echo '  Mitigation: disable HTTP/3/QUIC; upgrade.'; fi; elif [[ $HTTP3_ACTIVE -eq 1 ]]; then warn 'HTTP/3 enabled, proxy condition not detected; manual review advised.'; else ok 'HTTP/3 not detected; feature-based mitigation appears in place.'; fi

echo '[CVE-2026-123634] DNS resolver use-after-free'
if [[ $RESOLVER_ACTIVE -eq 1 && $DYNAMIC_PROXY -eq 1 && $MIRROR_ACTIVE -eq 1 && $MIRROR_BODY_OFF -eq 1 ]]; then if [[ $PATCHED -eq 1 ]]; then ok 'Resolver + variable proxy + mirror/body-off patterns found; version meets fixed threshold.'; else critical 'Resolver/dynamic proxy/mirror pattern appears to match exposure conditions.'; echo '  Mitigation: upgrade; review/remove request-derived proxy target and mirror_request_body off combination.'; fi; else ok 'Full resolver + variable proxy + mirror + mirror_request_body off pattern not detected.'; echo "  Flags: resolver=$RESOLVER_ACTIVE dynamic_proxy=$DYNAMIC_PROXY mirror=$MIRROR_ACTIVE mirror_body_off=$MIRROR_BODY_OFF SSI=$SSI_ACTIVE"; fi

echo '[CVE-2026-113425] Mail proxy use-after-free'
if [[ $MAIL_BLOCK -eq 1 && $MAIL_PROXY -eq 1 && $AUTH_HTTP -eq 1 ]]; then if [[ $PATCHED -eq 1 ]]; then ok 'mail{} + proxy on + auth_http detected; version meets upstream fixed threshold.'; else critical 'mail proxy + auth_http patterns found on older upstream version.'; echo '  Mitigation: upgrade; disable mail proxy/auth_http if not needed, or restrict listener access.'; fi; else ok 'mail{} + proxy on + auth_http full condition set not detected.'; echo "  Flags: mail_block=$MAIL_BLOCK mail_proxy=$MAIL_PROXY auth_http=$AUTH_HTTP"; fi

section '8. IMPORTANT PACKAGE BACKPORT CAVEAT'
if [[ -n "$PKG_VERSION" ]]; then warn "Package version is $PKG_VERSION. Upstream version alone cannot confirm distro backported security fixes."; fi
echo 'Confirm patch status in the OS/vendor security tracker or package changelog.'

section '9. RECOMMENDATIONS'
echo '1) Patch/upgrade NGINX to vendor-fixed package as soon as possible.'
echo '2) Upstream thresholds: stable 1.30.7+, mainline 1.31.9+.'
echo '3) Interim: disable HTTP/2 and HTTP/3/QUIC if not required.'
echo '4) Review resolver + request-derived proxy_pass + mirror/body-off combination.'
echo '5) Disable mail proxy/auth_http if unused; otherwise restrict access.'
echo '6) Restart NGINX after patch so old worker processes are replaced.'
echo '7) Review logs for worker exits/crashes; this is not proof of exploitation.'
section 'SUMMARY'
echo "Warnings: $WARNINGS | Info: $INFO"
echo 'Audit completed; no config changes were made.'
