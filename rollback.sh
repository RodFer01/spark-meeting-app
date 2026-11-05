#!/usr/bin/env bash
# rollback.sh — Restore index.html to the pre-sde-intelligence state and redeploy
set -e

ROLLBACK_TAG="pre-sde-intelligence"

echo "==> Rolling back index.html to tag: $ROLLBACK_TAG"
git checkout "$ROLLBACK_TAG" -- index.html
echo "    index.html restored ($(wc -c < index.html | tr -d ' ') bytes)"

echo "==> Verifying CF login..."
cf target

echo "==> Pushing rollback to BTP..."
cf push

echo "==> Done. Production is back to $ROLLBACK_TAG"
