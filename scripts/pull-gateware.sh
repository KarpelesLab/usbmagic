#!/usr/bin/env bash
#
# Fetch the latest built Cynthion bitstream from the usbmagic-gateware repo into
# firmware/. Prefers a tagged GitHub release; falls back to the most recent
# successful CI build artifact. Requires the `gh` CLI (authenticated).
#
set -euo pipefail

REPO="${GATEWARE_REPO:-KarpelesLab/usbmagic-gateware}"
DEST="${DEST:-firmware}"
mkdir -p "$DEST"

if gh release view --repo "$REPO" >/dev/null 2>&1; then
    echo "Downloading bitstream from the latest release of $REPO ..."
    gh release download --repo "$REPO" --pattern '*.bit' --dir "$DEST" --clobber
    source="release $(gh release view --repo "$REPO" --json tagName -q .tagName)"
else
    echo "No release on $REPO yet; fetching the latest successful CI artifact ..."
    run_id="$(gh run list --repo "$REPO" --workflow build --status success \
                --limit 1 --json databaseId -q '.[0].databaseId')"
    [ -n "${run_id:-}" ] || { echo "ERROR: no successful build run found on $REPO" >&2; exit 1; }
    gh run download "$run_id" --repo "$REPO" --name usbmagic-blinky-bitstream --dir "$DEST"
    source="ci-run $run_id"
fi

# Record provenance.
sha="$(gh api "repos/$REPO/commits/HEAD" -q .sha 2>/dev/null | cut -c1-12 || echo unknown)"
date="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
{
    echo "# Source gateware version for the vendored bitstream(s) in this directory."
    echo "# Updated by scripts/pull-gateware.sh; format: <repo> <git-sha-or-tag> <date>."
    echo "$REPO $sha ($source) $date"
} > "$DEST/VERSION"

echo "Pulled into $DEST/:"
ls -l "$DEST"/*.bit
echo "Remember to commit (the .bit goes to Git LFS automatically)."
