#!/usr/bin/env bash
set -euo pipefail

REMOTE_URL="${REMOTE_URL:-https://github.com/ksudhir/oracle-sso-devtools.git}"
BRANCH="${BRANCH:-main}"
COMMIT_MESSAGE="${*:-Update OAM SAML OAuth DevTools panel}"

cd "$(dirname "$0")/.."

if ! git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
  echo "This folder is not a git repository. Run git init first."
  exit 1
fi

echo "Using remote: $REMOTE_URL"
if git remote get-url origin >/dev/null 2>&1; then
  git remote set-url origin "$REMOTE_URL"
else
  git remote add origin "$REMOTE_URL"
fi

echo "Staging extension files..."
git add \
  README.md \
  manifest.json \
  devtools.html \
  devtools.js \
  panel.html \
  panel.css \
  panel.js \
  icons \
  scripts/push-to-github.sh

if git diff --cached --quiet; then
  echo "No staged changes to commit."
else
  echo "Creating commit: $COMMIT_MESSAGE"
  git commit -m "$COMMIT_MESSAGE"
fi

echo "Pushing to $BRANCH..."
git branch -M "$BRANCH"

if ! git push -u origin "$BRANCH"; then
  cat <<'HELP'

Push failed.

If you see:
  Could not resolve proxy: tw-proxy-sjc.oraclecorp.com

then Git is trying to use a proxy that is not reachable.

Fix options:
  1. Connect to the required corporate network/VPN, then rerun this script.
  2. Or remove the proxy config:
       git config --global --unset http.proxy
       git config --global --unset https.proxy

Then rerun:
  ./scripts/push-to-github.sh

HELP
  exit 1
fi

echo "Done. Pushed to $REMOTE_URL on branch $BRANCH."
