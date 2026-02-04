#!/bin/bash
# Install git pre-commit hook for KahfGuard blacklist validation
#
# Usage: ./scripts/install-hooks.sh

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(dirname "$SCRIPT_DIR")"
HOOK_DIR="$REPO_ROOT/.git/hooks"

# Create pre-commit hook
cat > "$HOOK_DIR/pre-commit" << 'EOF'
#!/bin/bash
# KahfGuard pre-commit hook
# Validates domain and IP list files before commit

REPO_ROOT="$(git rev-parse --show-toplevel)"

# Check if any relevant files are staged
STAGED_FILES=$(git diff --cached --name-only --diff-filter=ACM | grep -E '\.(txt)$' | grep -E '(blacklist|whitelist|lists/block)')

if [ -z "$STAGED_FILES" ]; then
    # No relevant files staged, skip validation
    exit 0
fi

echo "Validating blacklist and IP list files..."

# Run validation script
if [ -f "$REPO_ROOT/scripts/validate_lists.py" ]; then
    python3 "$REPO_ROOT/scripts/validate_lists.py"
    exit_code=$?

    if [ $exit_code -ne 0 ]; then
        echo ""
        echo "❌ Commit blocked: Validation failed"
        echo "Run 'python scripts/validate_lists.py --fix' to auto-fix issues"
        exit 1
    fi
fi

echo "✓ Validation passed"
exit 0
EOF

chmod +x "$HOOK_DIR/pre-commit"

echo "✓ Pre-commit hook installed successfully!"
echo ""
echo "The hook will validate:"
echo "  - Domain format in blacklist files"
echo "  - IP/CIDR format in IP list files"
echo "  - Duplicate entries"
echo "  - Alphabetical sorting"
echo ""
echo "To bypass the hook (not recommended):"
echo "  git commit --no-verify"
