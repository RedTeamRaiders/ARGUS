#!/usr/bin/env bash
#
# install_pre_commit_hook.sh — install a guard hook that blocks the most common
# secret/PII leak patterns from being staged.
#
# Usage:
#   bash scripts/install_pre_commit_hook.sh
#
# The hook checks the diff against the index and refuses to commit if it
# detects API key shapes, private keys, or accidental staging of .env /
# sessions.db / .salt / settings.local.json.

set -euo pipefail

REPO_ROOT="$(git rev-parse --show-toplevel)"
HOOK="$REPO_ROOT/.git/hooks/pre-commit"

cat > "$HOOK" <<'HOOK_END'
#!/usr/bin/env bash
# ARGUS pre-commit secret guard.
# To bypass for an emergency: git commit --no-verify  (USE WITH CAUTION)

set -uo pipefail

FAIL=0
say()  { printf "\033[31m[secret-guard]\033[0m %s\n" "$*" >&2; }
warn() { printf "\033[33m[secret-guard]\033[0m %s\n" "$*" >&2; }

# 1. Block specific files even if user tries to force-add them
BLOCKED_PATHS='^(\.env$|data/sessions\.db$|data/\.salt$|\.claude/settings\.local\.json$|\.claude/audit\.log$|reports/.*)'
staged_files=$(git diff --cached --name-only --diff-filter=ACM 2>/dev/null || true)

while IFS= read -r f; do
  [ -z "$f" ] && continue
  if echo "$f" | grep -qE "$BLOCKED_PATHS"; then
    say "blocked file staged: $f"
    FAIL=1
  fi
done <<< "$staged_files"

# 2. Scan the staged diff for secret-shaped strings
DIFF=$(git diff --cached --no-color -U0 2>/dev/null || true)

declare -a PATTERNS=(
  'sk-ant-api[0-9]+-[A-Za-z0-9_-]{20,}'
  'sk-[A-Za-z0-9]{40,}'
  'ghp_[A-Za-z0-9]{30,}'
  'gho_[A-Za-z0-9]{30,}'
  'AKIA[0-9A-Z]{16}'
  'AIza[0-9A-Za-z_-]{30,}'
  'xox[abpr]-[0-9A-Za-z-]{20,}'
  '-----BEGIN [A-Z ]*PRIVATE KEY-----'
  'aws_secret_access_key[[:space:]]*=[[:space:]]*[A-Za-z0-9/+]{30,}'
)

for pat in "${PATTERNS[@]}"; do
  if echo "$DIFF" | grep -qE -- "$pat"; then
    matches=$(echo "$DIFF" | grep -nE -- "$pat" | head -3)
    say "secret-shaped string in diff matching /$pat/:"
    while IFS= read -r m; do warn "  $m"; done <<< "$matches"
    FAIL=1
  fi
done

# 3. Naive PII patterns — credit-card or SSN
if echo "$DIFF" | grep -qE '\b[0-9]{4}[ -]?[0-9]{4}[ -]?[0-9]{4}[ -]?[0-9]{4}\b'; then
  warn "16-digit number detected — verify it isn't a credit card before committing"
fi

if [ "$FAIL" -ne 0 ]; then
  say "commit blocked. If this is a placeholder/example, rename or sanitize it."
  say "bypass: git commit --no-verify  (only if you are 100% sure)"
  exit 1
fi

exit 0
HOOK_END

chmod +x "$HOOK"
echo "Installed pre-commit hook at $HOOK"
echo "Test it with: git commit --allow-empty -m test"
