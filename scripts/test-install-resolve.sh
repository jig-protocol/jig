#!/usr/bin/env bash
# test-install-resolve.sh: which release install.sh picks for JIG_VERSION,
# checked against a stub `curl` that plays the GitHub API. Needs only bash.
#
#   - "latest" with a final release: that release, even when a newer
#     prerelease exists;
#   - "latest" with no final (/releases/latest is 404): the newest non-draft
#     release, prerelease or not;
#   - "latest" when /releases/latest fails any other way: an error, with no
#     fallback;
#   - an explicit tag: that tag, with no API call.
set -euo pipefail
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
t="$(mktemp -d)"
trap 'rm -rf "$t"' EXIT
mkdir -p "$t/fakebin"

# Serves STUB_LATEST_CODE for /releases/latest (200 → STUB_LATEST_TAG) and a
# fixed list for /releases: a draft, a newer prerelease, then older ones.
cat > "$t/fakebin/curl" <<'STUB'
#!/usr/bin/env bash
out="" wfmt="" fail=0 url=""
while [ $# -gt 0 ]; do
  case "$1" in
    -o) out="$2"; shift ;;
    -w) wfmt="$2"; shift ;;
    -H|--retry|--connect-timeout) shift ;;
    -*f*) fail=1 ;;
    http*) url="$1" ;;
  esac
  shift
done
echo "$url" >> "$STUB_LOG"
case "$url" in
  */releases/latest)
    code="$STUB_LATEST_CODE"
    [ "$code" = 200 ] && printf '{"url":"x","tag_name": "%s","draft":false,"prerelease":false}\n' "$STUB_LATEST_TAG" > "$out"
    [ "$code" = 000 ] && { [ -n "$wfmt" ] && printf 000; exit 7; } ;;
  */releases\?per_page=20)
    code=200
    cat > "$out" <<'JSON'
[{"tag_name": "v0.3.0-alpha.2","draft": true},
 {"tag_name": "v0.3.0-alpha.1","draft": false},
 {"tag_name": "v0.2.0-alpha.8","draft": false}]
JSON
    ;;
  *) code=404 ;;
esac
[ -n "$wfmt" ] && printf '%s' "$code"
if [ "$fail" = 1 ] && [ "$code" -ge 400 ]; then exit 22; fi
exit 0
STUB
chmod +x "$t/fakebin/curl"

{ sed '$d' "$root/install.sh"; cat <<'RUN'
mkdir -p "$STUB_TMP"
resolve_release "$STUB_TMP"
echo "RELEASE_TAG=$RELEASE_TAG"
RUN
} > "$t/run.sh"

fails=0
# case <name> <JIG_VERSION> <latest code> <latest tag> <want: tag or "error">
case_() {
  local name="$1" version="$2" code="$3" ltag="$4" want="$5" got rc=0
  : > "$t/log"
  got="$(env -u JIG_GITHUB_TOKEN -u GITHUB_TOKEN PATH="$t/fakebin:$PATH" HOME="$t" \
    JIG_VERSION="$version" STUB_LATEST_CODE="$code" STUB_LATEST_TAG="$ltag" \
    STUB_LOG="$t/log" STUB_TMP="$t/tmp-$RANDOM" bash "$t/run.sh" 2>&1)" || rc=$?
  if [ "$rc" -ne 0 ]; then got="error"; else got="$(sed -n 's/^RELEASE_TAG=//p' <<<"$got")"; fi
  if [ "$got" = "$want" ]; then
    echo "ok: $name -> $got"
  else
    echo "FAIL: $name -> $got, want $want" >&2
    fails=$((fails + 1))
  fi
}

case_ "latest, final exists"        latest 200 v0.2.0 v0.2.0
case_ "latest, no final (404)"      latest 404 ""     v0.3.0-alpha.1
case_ "latest, API error (500)"     latest 500 ""     error
case_ "latest, rate limited (403)"  latest 403 ""     error
case_ "latest, no response"         latest 000 ""     error
case_ "explicit tag"                v0.2.0-alpha.7 200 v0.2.0 v0.2.0-alpha.7

# A non-404 failure must not fall back to the release list.
case_ "latest, API error (500)" latest 500 "" error >/dev/null
if grep -q 'per_page' "$t/log"; then echo "FAIL: a 500 fell back to the release list" >&2; fails=$((fails + 1)); else echo "ok: a 500 does not fall back to the release list"; fi
# An explicit tag makes no API call (no token, so nothing to look up).
case_ "explicit tag" v0.2.0-alpha.7 200 v0.2.0 v0.2.0-alpha.7 >/dev/null
if [ -s "$t/log" ]; then echo "FAIL: an explicit tag called $(cat "$t/log")" >&2; fails=$((fails + 1)); else echo "ok: an explicit tag makes no API call"; fi

[ "$fails" -eq 0 ] || { echo "$fails case(s) failed" >&2; exit 1; }
echo "all resolve_release cases pass"
