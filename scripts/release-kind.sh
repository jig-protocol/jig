#!/usr/bin/env bash
# Print how a release tag publishes: "prerelease" or "final".
#
# Usage: scripts/release-kind.sh TAG
#
# TAG is v<semver>. A pre-release part (v0.2.0-alpha.8) means a GitHub
# prerelease; none (v0.2.0) means a final release, marked latest. Build
# metadata (+...) does not change the kind. Anything that is not v<semver>
# is refused (exit 2), so a typo never publishes as final.
#
# Used by .github/workflows/release.yml (publish) and scripts/verify-release.sh.
# Tests: scripts/test-release-kind.sh.
set -euo pipefail

tag="${1:?usage: $0 TAG}"
n='(0|[1-9][0-9]*)'
id='[0-9A-Za-z-]+'
semver="^v$n\\.$n\\.$n(-($id)(\\.$id)*)?(\\+$id(\\.$id)*)?\$"
if ! [[ "$tag" =~ $semver ]]; then
  echo "release-kind: '$tag' is not v<semver> (e.g. v0.2.0 or v0.2.0-alpha.8)" >&2
  exit 2
fi
# BASH_REMATCH[4] is the pre-release part ('-alpha.8'), empty when there is none.
if [ -n "${BASH_REMATCH[4]}" ]; then
  echo prerelease
else
  echo final
fi
