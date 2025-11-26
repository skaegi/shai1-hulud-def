#!/bin/bash

# dry-hulud.sh - Security audit tool to assess Shai1-Hulud attack surface
#
# This script simulates what Shai1-Hulud would scan for and reports what
# would have been stolen, WITHOUT actually exfiltrating or modifying anything.
#
# Purpose: Educational/defensive - understand your exposure to supply chain attacks

set -euo pipefail

# Colors for output
RED='\033[0;31m'
YELLOW='\033[1;33m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color
BOLD='\033[1m'

# Counters
FINDINGS=0
CRITICAL=0
HIGH=0
MEDIUM=0
LOW=0

echo -e "${BOLD}==================================================${NC}"
echo -e "${BOLD}  DRY-HULUD - Shai1-Hulud Attack Surface Scanner${NC}"
echo -e "${BOLD}==================================================${NC}"
echo ""
echo "This tool scans for credentials and configurations that"
echo "Shai1-Hulud would target, without actually stealing anything."
echo ""
echo "Date: $(date)"
echo "Hostname: $(hostname)"
echo "User: $(whoami)"
echo "Platform: $(uname -s)"
echo ""

# Helper function to log findings
log_finding() {
    local severity=$1 title=$2 detail=$3
    FINDINGS=$((FINDINGS + 1))
    case $severity in
        CRITICAL) CRITICAL=$((CRITICAL + 1)); COLOR=$RED ;;
        HIGH) HIGH=$((HIGH + 1)); COLOR=$YELLOW ;;
        MEDIUM) MEDIUM=$((MEDIUM + 1)); COLOR=$BLUE ;;
        LOW) LOW=$((LOW + 1)); COLOR=$GREEN ;;
    esac
    echo -e "${COLOR}[${severity}]${NC} ${title}"
    echo "  ${detail}"
    echo ""
}

# Helper to check if file exists with pattern
check_file() {
    local file=$1 pattern=$2 severity=$3 title=$4

    # Check if file exists
    if [[ ! -f "$file" ]]; then
        return 1
    fi

    # Try to read it - if blocked, report as protected
    if ! cat "$file" >/dev/null 2>&1; then
        print_protected "$file"
        return 2  # Special return code: exists but protected
    fi

    # File is readable, check for pattern
    if grep -qE "$pattern" "$file" 2>/dev/null; then
        log_finding "$severity" "$title" "File: $file"
        return 0
    fi

    return 1
}

# Helper to check environment variable
check_env() {
    local pattern=$1 severity=$2 title=$3
    local found=$(printenv | grep -iE "$pattern" | cut -d= -f1 | head -1)
    [[ -n "$found" ]] && log_finding "$severity" "$title" "Found: $found" && return 0
    return 1
}

# Helper to print section success
print_ok() {
    echo -e "${GREEN}✓ $1${NC}"
    echo ""
}

# Helper to report sandbox protection (successful block)
print_protected() {
    local location=$1
    echo -e "${GREEN}✓ Protected by sandbox: $location${NC}"
    echo ""
}

# Helper to safely run find commands that might encounter permission errors
# Returns count of files found, or -1 if blocked by sandbox
safe_find() {
    local dir=$1
    shift
    local count
    if [[ ! -d "$dir" ]]; then
        echo "0"
        return
    fi
    # Try to access the directory first
    if ! ls "$dir" >/dev/null 2>&1; then
        echo "-1"  # Access denied
        return
    fi
    count=$(find "$dir" "$@" 2>/dev/null | wc -l | tr -d ' ') || echo "0"
    echo "$count"
}

# Detect platform
PLATFORM=$(uname -s)

echo -e "${BOLD}[1/13] Scanning Environment Variables...${NC}"
echo "----------------------------------------"

# Check for credentials in environment variables
ENV_CREDS=0
for var in $(env | grep -iE "token|key|secret|password|credential" | cut -d= -f1); do
    value=$(printenv "$var" | head -c 50)
    if [[ ${#value} -gt 10 ]]; then
        log_finding "HIGH" "Credential in environment variable: $var" \
            "Value (truncated): ${value}... (${#value} chars total)"
        ENV_CREDS=$((ENV_CREDS + 1))
    fi
done

if [[ $ENV_CREDS -eq 0 ]]; then
    echo -e "${GREEN}✓ No obvious credentials in environment variables${NC}"
    echo ""
fi

echo -e "${BOLD}[2/13] Scanning GitHub Credentials...${NC}"
echo "----------------------------------------"

GITHUB_CREDS=0
check_env "GITHUB_TOKEN|GH_TOKEN" "CRITICAL" "GitHub token in environment" && GITHUB_CREDS=$((GITHUB_CREDS + 1))
check_file ~/.gitconfig "token|credential" "HIGH" "Potential credentials in ~/.gitconfig" && GITHUB_CREDS=$((GITHUB_CREDS + 1))
check_file ~/.netrc "github\.com|api\.github\.com" "CRITICAL" "GitHub credentials in ~/.netrc" && GITHUB_CREDS=$((GITHUB_CREDS + 1))

# Check GitHub CLI config - try to read it to verify access
if [[ -f ~/.config/gh/hosts.yml ]]; then
    if cat ~/.config/gh/hosts.yml >/dev/null 2>&1; then
        log_finding "HIGH" "GitHub CLI authenticated" "File: ~/.config/gh/hosts.yml (contains OAuth token)"
        GITHUB_CREDS=$((GITHUB_CREDS + 1))
    else
        print_protected "~/.config/gh/hosts.yml"
    fi
fi

[[ $GITHUB_CREDS -eq 0 ]] && print_ok "No GitHub credentials found in common locations"

echo -e "${BOLD}[3/13] Scanning npm Credentials...${NC}"
echo "----------------------------------------"

NPM_CREDS=0
check_env "NPM_TOKEN|NPM_AUTH" "CRITICAL" "npm token in environment" && NPM_CREDS=$((NPM_CREDS + 1))
for npmrc in ~/.npmrc ./.npmrc /etc/npmrc; do
    check_file "$npmrc" "//registry\.npmjs\.org/:_authToken|_auth=" "CRITICAL" "npm authentication in $npmrc" && NPM_CREDS=$((NPM_CREDS + 1))
done

[[ $NPM_CREDS -eq 0 ]] && print_ok "No npm credentials found"

echo -e "${BOLD}[4/13] Scanning AWS Credentials...${NC}"
echo "----------------------------------------"

AWS_CREDS=0
check_env "AWS_ACCESS_KEY_ID|AWS_SECRET_ACCESS_KEY" "CRITICAL" "AWS credentials in environment" && AWS_CREDS=$((AWS_CREDS + 1))

if [[ -f ~/.aws/credentials ]]; then
    profiles=$(grep -c "^\[" ~/.aws/credentials 2>/dev/null || echo "0")
    log_finding "CRITICAL" "AWS credentials file found" "File: ~/.aws/credentials contains $profiles profile(s)"
    AWS_CREDS=$((AWS_CREDS + 1))
    perms=$(stat -f "%Lp" ~/.aws/credentials 2>/dev/null || stat -c "%a" ~/.aws/credentials 2>/dev/null)
    [[ "$perms" != "600" ]] && log_finding "HIGH" "AWS credentials file has weak permissions" "Permissions: $perms (should be 600)"
fi

[[ -f ~/.aws/config ]] && log_finding "MEDIUM" "AWS config file found" "File: ~/.aws/config may contain sensitive configuration" && AWS_CREDS=$((AWS_CREDS + 1))
[[ $AWS_CREDS -eq 0 ]] && print_ok "No AWS credentials found"

echo -e "${BOLD}[5/13] Scanning GCP Credentials...${NC}"
echo "----------------------------------------"

GCP_CREDS=0
check_env "GOOGLE_APPLICATION_CREDENTIALS|GCLOUD" "HIGH" "GCP credential environment variables" && GCP_CREDS=$((GCP_CREDS + 1))
[[ -f ~/.config/gcloud/application_default_credentials.json ]] && log_finding "CRITICAL" "GCP Application Default Credentials" "File: ~/.config/gcloud/application_default_credentials.json" && GCP_CREDS=$((GCP_CREDS + 1))

sa_keys=$(safe_find ~/.config/gcloud -name "*.json" -type f)
if [[ $sa_keys -eq -1 ]]; then
    print_protected "~/.config/gcloud"
elif [[ $sa_keys -gt 0 ]]; then
    log_finding "CRITICAL" "GCP service account key files" "Found $sa_keys JSON file(s) in ~/.config/gcloud"
    GCP_CREDS=$((GCP_CREDS + 1))
fi

[[ $GCP_CREDS -eq 0 ]] && print_ok "No GCP credentials found"

echo -e "${BOLD}[6/13] Scanning Azure Credentials...${NC}"
echo "----------------------------------------"

AZURE_CREDS=0
check_env "AZURE_|ARM_CLIENT" "HIGH" "Azure credential environment variables" && AZURE_CREDS=$((AZURE_CREDS + 1))
[[ -d ~/.azure ]] && log_finding "HIGH" "Azure CLI configuration directory" "Directory: ~/.azure may contain credentials" && AZURE_CREDS=$((AZURE_CREDS + 1))
[[ -f ~/.azure/accessTokens.json ]] && log_finding "CRITICAL" "Azure access tokens file" "File: ~/.azure/accessTokens.json"

[[ $AZURE_CREDS -eq 0 ]] && print_ok "No Azure credentials found"

echo -e "${BOLD}[7/13] Scanning SSH Keys...${NC}"
echo "----------------------------------------"

SSH_KEYS=0

# Count private keys
keys=$(safe_find ~/.ssh -type f \( -name "id_rsa" -o -name "id_ed25519" -o -name "id_ecdsa" -o -name "id_dsa" \))

if [[ $keys -eq -1 ]]; then
    print_protected "~/.ssh"
elif [[ $keys -gt 0 ]]; then
    log_finding "HIGH" "SSH private keys found" \
        "Found $keys private key(s) in ~/.ssh/"
    SSH_KEYS=$((SSH_KEYS + 1))

    # Check for unencrypted keys (dangerous)
    for keyfile in ~/.ssh/id_*; do
        if [[ -f "$keyfile" ]] && [[ ! "$keyfile" == *.pub ]]; then
            if ! grep -q "ENCRYPTED" "$keyfile" 2>/dev/null; then
                log_finding "CRITICAL" "Unencrypted SSH key: $(basename $keyfile)" \
                    "Key has no passphrase protection"
            fi
        fi
    done
fi

if [[ $SSH_KEYS -eq 0 ]]; then
    echo -e "${GREEN}✓ No SSH keys found${NC}"
    echo ""
fi

echo -e "${BOLD}[8/13] Scanning Shell History...${NC}"
echo "----------------------------------------"

HISTORY_CREDS=0

# Check shell history files for credential patterns
for history in ~/.bash_history ~/.zsh_history ~/.python_history ~/.node_repl_history; do
    if [[ -f "$history" ]]; then
        # Look for AWS keys, tokens, passwords in history
        if grep -qiE "ghp_|gho_|AKIA|secret|password|token.*=" "$history" 2>/dev/null; then
            matches=$(grep -ciE "ghp_|gho_|AKIA|secret|password|token.*=" "$history" 2>/dev/null || echo "0")
            if [[ $matches -gt 0 ]]; then
                log_finding "HIGH" "Potential credentials in $(basename $history)" \
                    "Found $matches line(s) with credential patterns"
                HISTORY_CREDS=$((HISTORY_CREDS + 1))
            fi
        fi
    fi
done

if [[ $HISTORY_CREDS -eq 0 ]]; then
    echo -e "${GREEN}✓ No credentials found in shell history${NC}"
    echo ""
fi

echo -e "${BOLD}[9/13] Scanning Container & Orchestration...${NC}"
echo "----------------------------------------"

CONTAINER_CREDS=0
check_file ~/.docker/config.json '"auth":|"auths":' "HIGH" "Docker registry credentials" && CONTAINER_CREDS=$((CONTAINER_CREDS + 1))

if [[ -f ~/.kube/config ]]; then
    if cat ~/.kube/config >/dev/null 2>&1; then
        clusters=$(grep -c "^  name:" ~/.kube/config 2>/dev/null || echo "0")
        if [[ $clusters -gt 0 ]]; then
            log_finding "HIGH" "Kubernetes cluster credentials" "File: ~/.kube/config contains $clusters cluster(s)"
            CONTAINER_CREDS=$((CONTAINER_CREDS + 1))
        fi
    else
        print_protected "~/.kube/config"
    fi
fi

[[ $CONTAINER_CREDS -eq 0 ]] && print_ok "No container/orchestration credentials found"

echo -e "${BOLD}[10/13] Scanning Other Package Managers...${NC}"
echo "----------------------------------------"

OTHER_PKG_CREDS=0
[[ -f ~/.pypirc ]] && log_finding "MEDIUM" "PyPI credentials found" "File: ~/.pypirc contains Python package index credentials" && OTHER_PKG_CREDS=$((OTHER_PKG_CREDS + 1))
[[ -f ~/.cargo/credentials ]] && log_finding "MEDIUM" "Cargo credentials found" "File: ~/.cargo/credentials contains Rust package credentials" && OTHER_PKG_CREDS=$((OTHER_PKG_CREDS + 1))
[[ -f ~/.gem/credentials ]] && log_finding "MEDIUM" "RubyGems credentials found" "File: ~/.gem/credentials contains gem publishing credentials" && OTHER_PKG_CREDS=$((OTHER_PKG_CREDS + 1))

[[ $OTHER_PKG_CREDS -eq 0 ]] && print_ok "No other package manager credentials found"

echo -e "${BOLD}[11/13] Scanning for Malicious Files...${NC}"
echo "----------------------------------------"

MALICIOUS_FILES=0

# Check for known Shai1-Hulud files in likely locations only (fast)
search_paths=(
    "$HOME/Downloads"
    "$HOME/Desktop"
    "$HOME/Documents"
    "."
)

# Search all patterns in one find command for speed
for search_path in "${search_paths[@]}"; do
    if [[ -d "$search_path" ]]; then
        # Check if we can access the directory
        if ! ls "$search_path" >/dev/null 2>&1; then
            print_protected "$search_path"
            continue
        fi

        found=$(find "$search_path" -maxdepth 3 \( \
            -name "setup_bun.js" -o \
            -name "bun_environment.js" -o \
            -name "cloud.json" -o \
            -name "contents.json" -o \
            -name "environment.json" -o \
            -name "truffleSecrets.json" \
        \) -type f 2>/dev/null) || true

        if [[ -n "$found" ]]; then
            log_finding "CRITICAL" "Known malicious files found" \
                "Locations: $found"
            MALICIOUS_FILES=$((MALICIOUS_FILES + 1))
        fi
    fi
done

# Check for self-hosted runner
if [[ -d ~/.dev-env ]]; then
    log_finding "CRITICAL" "Self-hosted runner directory found" \
        "Directory: ~/.dev-env (Shai1-Hulud installs runner here)"
    MALICIOUS_FILES=$((MALICIOUS_FILES + 1))
fi

if pgrep -f "SHA1HULUD" >/dev/null 2>&1; then
    log_finding "CRITICAL" "Malicious runner process detected" \
        "Process name contains 'SHA1HULUD'"
    MALICIOUS_FILES=$((MALICIOUS_FILES + 1))
fi

if [[ $MALICIOUS_FILES -eq 0 ]]; then
    echo -e "${GREEN}✓ No known malicious files detected${NC}"
    echo ""
fi

echo -e "${BOLD}[12/13] Assessing Destructive Capability...${NC}"
echo "----------------------------------------"

DESTRUCTIVE_RISK=0

# Check if Docker daemon is accessible (privilege escalation vector)
# Note: Docker binary being installed is fine - it's daemon access that's dangerous
if command -v docker &> /dev/null; then
    # Check if user can actually access the Docker daemon
    if docker ps &> /dev/null 2>&1; then
        log_finding "CRITICAL" "Docker daemon accessible without authentication" \
            "Shai1-Hulud could use Docker to escalate privileges and delete files as root"
        DESTRUCTIVE_RISK=$((DESTRUCTIVE_RISK + 1))
    fi
    # If docker ps fails, daemon is not accessible - no risk, no finding
fi

# Assess what could be deleted (fast check - no actual counting)
# Note: Shai1-Hulud attempts: rm -rf $HOME/* (deletes everything)

# Test if deletion would actually succeed (safe test in key directories)
DELETION_POSSIBLE=1
BLOCKED_DIRS=()
CWD_DELETION_POSSIBLE=1

# Test deletion in all critical directories (including package manager dirs)
for test_dir in "$HOME" "$HOME/Documents" "$HOME/Desktop" "$HOME/Downloads" "$HOME/Projects" \
                "$HOME/.ssh" "$HOME/.aws" "$HOME/.config" \
                "$HOME/.npm" "$HOME/.cargo" "$HOME/.rustup" "$HOME/.node" "$HOME/.cache"; do
    if [[ -d "$test_dir" ]]; then
        test_file="$test_dir/.dry-hulud-test-$$"
        if touch "$test_file" 2>/dev/null; then
            if ! rm -f "$test_file" 2>/dev/null; then
                DELETION_POSSIBLE=0
                BLOCKED_DIRS+=("$(basename "$test_dir")")
            fi
        else
            DELETION_POSSIBLE=0
            BLOCKED_DIRS+=("$(basename "$test_dir")")
        fi
    fi
done

# Also test current working directory (separate from home)
if [[ "$PWD" != "$HOME" ]]; then
    cwd_test_file="./.dry-hulud-test-$$"
    if touch "$cwd_test_file" 2>/dev/null; then
        if ! rm -f "$cwd_test_file" 2>/dev/null; then
            CWD_DELETION_POSSIBLE=0
        fi
    else
        CWD_DELETION_POSSIBLE=0
    fi
fi

# Check for security systems that might block deletion
SECURITY_SYSTEMS=()

if [[ "$PLATFORM" == "Darwin" ]]; then
    # Check SIP status on macOS
    if command -v csrutil &> /dev/null; then
        sip_status=$(csrutil status 2>/dev/null || echo "unknown")
        if echo "$sip_status" | grep -q "enabled"; then
            SECURITY_SYSTEMS+=("SIP enabled (some files protected)")
        elif echo "$sip_status" | grep -q "disabled"; then
            SECURITY_SYSTEMS+=("SIP disabled (no system protection)")
        fi
    fi

    # Note: Seatbelt/sandbox is hard to detect from within
    # But if we're in a sandboxed app, file operations would fail

elif [[ "$PLATFORM" == "Linux" ]]; then
    # Check SELinux on Linux
    if command -v getenforce &> /dev/null; then
        selinux_status=$(getenforce 2>/dev/null || echo "unknown")
        if [[ "$selinux_status" == "Enforcing" ]]; then
            SECURITY_SYSTEMS+=("SELinux enforcing (may block deletion)")
        fi
    fi

    # Check AppArmor
    if command -v aa-status &> /dev/null; then
        if aa-status --enabled 2>/dev/null; then
            SECURITY_SYSTEMS+=("AppArmor enabled (may block deletion)")
        fi
    fi
fi

# Report the destructive risk
if [[ $DELETION_POSSIBLE -eq 1 ]]; then
    log_finding "CRITICAL" "Destructive capability: Complete home directory deletion" \
        "Shai1-Hulud would execute 'rm -rf $HOME/*' - deletion test SUCCEEDED"

    if [[ ${#SECURITY_SYSTEMS[@]} -gt 0 ]]; then
        echo "  Security systems detected (may provide partial protection):"
        for sys in "${SECURITY_SYSTEMS[@]}"; do
            echo "    • $sys"
        done
        echo ""
    fi

    # Note about app-level sandboxing
    echo "  Note: Seatbelt/AppArmor app-level sandboxing not fully tested"
    echo "  (node/npm may have different permissions than this script)"
    echo ""
else
    # Helper to check if a directory is already protected
    is_protected() {
        local dir=$1
        local basename_dir=$(basename "$dir")
        # Handle empty array safely
        if [[ ${#BLOCKED_DIRS[@]} -eq 0 ]]; then
            return 1
        fi
        for blocked in "${BLOCKED_DIRS[@]}"; do
            if [[ "$blocked" == "$basename_dir" ]]; then
                return 0
            fi
        done
        return 1
    }

    # Build list of critical directories still at risk (not protected by sandbox)
    critical_dirs=()
    [[ -d ~/Documents ]] && ! is_protected ~/Documents && critical_dirs+=("~/Documents")
    [[ -d ~/Downloads ]] && ! is_protected ~/Downloads && critical_dirs+=("~/Downloads")
    [[ -d ~/Desktop ]] && ! is_protected ~/Desktop && critical_dirs+=("~/Desktop")
    [[ -d ~/Projects ]] && ! is_protected ~/Projects && critical_dirs+=("~/Projects")
    [[ -d ~/.ssh ]] && ! is_protected ~/.ssh && critical_dirs+=("~/.ssh")
    [[ -d ~/.aws ]] && ! is_protected ~/.aws && critical_dirs+=("~/.aws")
    [[ -d ~/.config ]] && ! is_protected ~/.config && critical_dirs+=("~/.config")
    [[ -d ~/.npm ]] && ! is_protected ~/.npm && critical_dirs+=("~/.npm")
    [[ -d ~/.cargo ]] && ! is_protected ~/.cargo && critical_dirs+=("~/.cargo")
    [[ -d ~/.rustup ]] && ! is_protected ~/.rustup && critical_dirs+=("~/.rustup")
    [[ -d ~/.node ]] && ! is_protected ~/.node && critical_dirs+=("~/.node")
    [[ -d ~/.cache ]] && ! is_protected ~/.cache && critical_dirs+=("~/.cache")

    # Determine severity based on what's still vulnerable
    severity="LOW"
    at_risk_msg=""
    if [[ ${#critical_dirs[@]} -gt 0 ]]; then
        # Build inline list (up to 5)
        shown_at_risk=("${critical_dirs[@]:0:5}")
        at_risk_msg=$(IFS=', '; echo "${shown_at_risk[*]}")
        if [[ ${#critical_dirs[@]} -gt 5 ]]; then
            at_risk_msg="$at_risk_msg, ... (${#critical_dirs[@]} total)"
        fi

        # Check if high-value targets are exposed
        for dir in "${critical_dirs[@]}"; do
            # Credentials and configs
            if [[ "$dir" =~ (\.ssh|\.aws) ]]; then
                severity="HIGH"
                break
            # Package managers (code injection risk)
            elif [[ "$dir" =~ (\.cargo|\.npm|\.rustup|\.node) ]]; then
                severity="MEDIUM"
            # Config files
            elif [[ "$dir" =~ (\.config|\.cache) ]] && [[ "$severity" == "LOW" ]]; then
                severity="MEDIUM"
            fi
        done

        log_finding "$severity" "Destructive capability partially blocked" \
            "Shai1-Hulud could still delete: $at_risk_msg"

        echo "  Vulnerable directories:"
        for dir in "${critical_dirs[@]}"; do
            echo "    ⚠ $dir"
        done
        echo ""
    else
        # All critical directories are protected
        echo -e "${GREEN}✓ Sandbox blocked all destructive attempts${NC}"
        echo ""
    fi

    # Show what the sandbox protected (context only)
    if [[ ${#BLOCKED_DIRS[@]} -gt 0 ]]; then
        echo "  Sandbox protected:"
        for dir in "${BLOCKED_DIRS[@]}"; do
            echo "    ✓ $dir"
        done
        echo ""
    fi

    if [[ ${#SECURITY_SYSTEMS[@]} -gt 0 ]]; then
        echo "  Protection systems:"
        for sys in "${SECURITY_SYSTEMS[@]}"; do
            echo "    ✓ $sys"
        done
        echo ""
    fi
fi

if [[ $DESTRUCTIVE_RISK -eq 0 ]]; then
    echo -e "${GREEN}✓ Limited destructive capability${NC}"
    echo ""
fi

echo -e "${BOLD}[13/13] Scanning Persistence Mechanisms...${NC}"
echo "----------------------------------------"

PERSISTENCE=0

# Platform-specific persistence checks
if [[ "$PLATFORM" == "Linux" ]]; then
    # Linux-specific: systemd user services
    services=$(safe_find ~/.config/systemd/user -name "*.service" -type f)
    if [[ $services -eq -1 ]]; then
        print_protected "~/.config/systemd/user"
    elif [[ $services -gt 0 ]]; then
        log_finding "MEDIUM" "systemd user services found" \
            "Found $services user service(s) - verify these are legitimate"
        PERSISTENCE=$((PERSISTENCE + 1))
    fi

    # Linux-specific: XDG autostart
    autostart=$(safe_find ~/.config/autostart -name "*.desktop" -type f)
    if [[ $autostart -eq -1 ]]; then
        print_protected "~/.config/autostart"
    elif [[ $autostart -gt 0 ]]; then
        log_finding "MEDIUM" "XDG autostart entries found" \
            "Found $autostart autostart file(s) - verify these are legitimate"
        PERSISTENCE=$((PERSISTENCE + 1))
    fi

    # Shell rc files (both Linux and macOS, but more common persistence on Linux)
    for rcfile in ~/.bashrc ~/.zshrc ~/.profile; do
        if [[ -f "$rcfile" ]]; then
            # Check for suspicious patterns
            if grep -qE "setup_bun|bun_environment|\.dev-env|SHA1HULUD" "$rcfile" 2>/dev/null; then
                log_finding "CRITICAL" "Suspicious content in $(basename $rcfile)" \
                    "File contains potential Shai1-Hulud persistence mechanism"
                PERSISTENCE=$((PERSISTENCE + 1))
            fi
        fi
    done

elif [[ "$PLATFORM" == "Darwin" ]]; then
    # macOS-specific: LaunchAgents
    agents=$(safe_find ~/Library/LaunchAgents -name "*.plist" -type f)
    if [[ $agents -eq -1 ]]; then
        print_protected "~/Library/LaunchAgents"
    elif [[ $agents -gt 0 ]]; then
        log_finding "MEDIUM" "LaunchAgents found" \
            "Found $agents LaunchAgent(s) - verify these are legitimate"
        PERSISTENCE=$((PERSISTENCE + 1))
    fi

    # macOS: Check shell rc files
    for rcfile in ~/.zshrc ~/.bash_profile ~/.zprofile; do
        if [[ -f "$rcfile" ]]; then
            # Check for suspicious patterns
            if grep -qE "setup_bun|bun_environment|\.dev-env|SHA1HULUD" "$rcfile" 2>/dev/null; then
                log_finding "CRITICAL" "Suspicious content in $(basename $rcfile)" \
                    "File contains potential Shai1-Hulud persistence mechanism"
                PERSISTENCE=$((PERSISTENCE + 1))
            fi
        fi
    done
fi

# Common persistence: cron jobs (both platforms)
if command -v crontab &> /dev/null; then
    if crontab -l 2>/dev/null | grep -qE "setup_bun|bun_environment|\.dev-env|SHA1HULUD"; then
        log_finding "CRITICAL" "Suspicious cron job detected" \
            "Crontab contains potential Shai1-Hulud persistence"
        PERSISTENCE=$((PERSISTENCE + 1))
    fi
fi

if [[ $PERSISTENCE -eq 0 ]]; then
    echo -e "${GREEN}✓ No suspicious persistence mechanisms detected${NC}"
    echo ""
fi

echo -e "${BOLD}[GITHUB] Scanning GitHub Workflows...${NC}"
echo "----------------------------------------"

SUSPICIOUS_WORKFLOWS=0

# Check for suspicious workflows
if [[ -d .github/workflows ]]; then
    if [[ -f .github/workflows/discussion.yaml ]]; then
        log_finding "CRITICAL" "Malicious workflow: discussion.yaml" \
            "File: .github/workflows/discussion.yaml (Shai1-Hulud backdoor)"
        SUSPICIOUS_WORKFLOWS=$((SUSPICIOUS_WORKFLOWS + 1))
    fi

    # Check for workflows with hulud in name
    if find .github/workflows -name "*hulud*" -type f 2>/dev/null | grep -q .; then
        found=$(find .github/workflows -name "*hulud*" -type f 2>/dev/null)
        log_finding "CRITICAL" "Suspicious workflow file" \
            "Location: $found"
        SUSPICIOUS_WORKFLOWS=$((SUSPICIOUS_WORKFLOWS + 1))
    fi
fi

if [[ $SUSPICIOUS_WORKFLOWS -eq 0 ]]; then
    echo -e "${GREEN}✓ No suspicious workflow files detected${NC}"
    echo ""
fi

echo -e "${BOLD}[GITHUB] Checking GitHub Account...${NC}"
echo "----------------------------------------"

GITHUB_ISSUES=0

# Check for GitHub CLI and scan repos
if command -v gh &> /dev/null; then
    if gh auth status &> /dev/null; then
        # Check for suspicious repositories
        if gh repo list --json name,description 2>/dev/null | jq -r '.[] | select(.description | contains("Sha1-Hulud") or contains("Shai-Hulud"))' | grep -q .; then
            repos=$(gh repo list --json name,description | jq -r '.[] | select(.description | contains("Sha1-Hulud") or contains("Shai-Hulud")) | .name')
            log_finding "CRITICAL" "Suspicious GitHub repositories found" \
                "Repositories with Hulud in description: $repos"
            GITHUB_ISSUES=$((GITHUB_ISSUES + 1))
        fi

        # Check for self-hosted runners (requires repo context)
        if [[ -d .git ]]; then
            repo=$(gh repo view --json nameWithOwner -q .nameWithOwner 2>/dev/null || echo "")
            if [[ -n "$repo" ]]; then
                runners=$(gh api "repos/$repo/actions/runners" 2>/dev/null | jq -r '.runners[]? | select(.name | contains("SHA1HULUD") or contains("hulud")) | .name' || echo "")
                if [[ -n "$runners" ]]; then
                    log_finding "CRITICAL" "Malicious self-hosted runner" \
                        "Runner name: $runners"
                    GITHUB_ISSUES=$((GITHUB_ISSUES + 1))
                fi
            fi
        fi
    else
        echo -e "${YELLOW}⚠ GitHub CLI not authenticated - skipping repo checks${NC}"
        echo ""
    fi
else
    echo -e "${YELLOW}⚠ GitHub CLI (gh) not installed - skipping repo checks${NC}"
    echo ""
fi

if [[ $GITHUB_ISSUES -eq 0 ]] && command -v gh &> /dev/null && gh auth status &> /dev/null; then
    echo -e "${GREEN}✓ No suspicious GitHub repositories or runners detected${NC}"
    echo ""
fi

# Summary
echo ""
echo -e "${BOLD}==================================================${NC}"
echo -e "${BOLD}                    SUMMARY${NC}"
echo -e "${BOLD}==================================================${NC}"
echo ""


total_score=0
max_score=0

# Calculate exposure score
if [[ $CRITICAL -gt 0 ]]; then
    total_score=$((total_score + CRITICAL * 10))
    max_score=$((max_score + CRITICAL * 10))
fi
if [[ $HIGH -gt 0 ]]; then
    total_score=$((total_score + HIGH * 5))
    max_score=$((max_score + HIGH * 5))
fi
if [[ $MEDIUM -gt 0 ]]; then
    total_score=$((total_score + MEDIUM * 2))
    max_score=$((max_score + MEDIUM * 2))
fi
if [[ $LOW -gt 0 ]]; then
    total_score=$((total_score + LOW * 1))
    max_score=$((max_score + LOW * 1))
fi

echo -e "Total Findings: ${BOLD}${FINDINGS}${NC}"
echo -e "  ${RED}Critical: ${CRITICAL}${NC}"
echo -e "  ${YELLOW}High:     ${HIGH}${NC}"
echo -e "  ${BLUE}Medium:   ${MEDIUM}${NC}"
echo -e "  ${GREEN}Low:      ${LOW}${NC}"
echo ""

    echo "Total Findings: ${FINDINGS}"

if [[ $CRITICAL -gt 0 ]]; then
    echo -e "${RED}${BOLD}⚠ CRITICAL EXPOSURE DETECTED${NC}"
    echo "Your system has CRITICAL vulnerabilities that Shai1-Hulud would exploit:"
    echo "• Credentials that would be immediately stolen and exfiltrated"
    echo "• Potential for complete account compromise"
    echo "• High risk of propagation to other systems/packages"
    echo -e "${BOLD}Immediate Actions Required:${NC}"
    echo "1. Move credentials to encrypted credential manager (1Password, aws-vault)"
    echo "2. Remove credentials from environment variables and config files"
    echo "3. Rotate ALL exposed credentials immediately"
    echo "4. Review GitHub account for suspicious repos/runners"
    echo "5. Enable 2FA on all accounts"
    echo ""
elif [[ $HIGH -gt 0 ]]; then
    echo -e "${YELLOW}${BOLD}⚠ HIGH EXPOSURE DETECTED${NC}"
    echo "Your system has significant vulnerabilities:"
    echo "• Credentials that could be stolen with minimal effort"
    echo "• Risk of account compromise"
    echo -e "${BOLD}Recommended Actions:${NC}"
    echo "1. Improve credential storage practices"
    echo "2. Review and tighten file permissions"
    echo "3. Consider using credential managers"
    echo "4. Audit GitHub account regularly"
    echo ""
else
    echo -e "${GREEN}${BOLD}✓ Good Security Posture${NC}"
    echo "No critical credential exposure detected."
    echo "Continue following security best practices."
    echo ""
fi

echo ""

echo -e "${BOLD}What Shai1-Hulud Would Have Stolen:${NC}"

stolen=()
if [[ $ENV_CREDS -gt 0 ]]; then
    stolen+=("Environment variables with credentials")
fi
if [[ $GITHUB_CREDS -gt 0 ]]; then
    stolen+=("GitHub tokens and authentication")
fi
if [[ $NPM_CREDS -gt 0 ]]; then
    stolen+=("npm authentication tokens")
fi
if [[ $AWS_CREDS -gt 0 ]]; then
    stolen+=("AWS credentials and config")
fi
if [[ $GCP_CREDS -gt 0 ]]; then
    stolen+=("GCP credentials and service accounts")
fi
if [[ $AZURE_CREDS -gt 0 ]]; then
    stolen+=("Azure credentials and access tokens")
fi
if [[ $SSH_KEYS -gt 0 ]]; then
    stolen+=("SSH private keys")
fi
if [[ $HISTORY_CREDS -gt 0 ]]; then
    stolen+=("Credentials from shell history")
fi
if [[ $CONTAINER_CREDS -gt 0 ]]; then
    stolen+=("Docker/Kubernetes credentials")
fi
if [[ $OTHER_PKG_CREDS -gt 0 ]]; then
    stolen+=("Package manager credentials (PyPI, Cargo, RubyGems)")
fi

if [[ ${#stolen[@]} -gt 0 ]]; then
    for item in "${stolen[@]}"; do
        echo "  • $item"
    done
else
    echo -e "  ${GREEN}✓ No credentials would have been stolen${NC}"
fi

echo ""
echo -e "${BOLD}Destructive Capability Assessment:${NC}"
echo ""
echo "Home Directory ($HOME):"
if [[ $DELETION_POSSIBLE -eq 1 ]]; then
    echo -e "  ${RED}⚠ DELETION WOULD SUCCEED - All files would be destroyed${NC}"
    echo "  • Command: rm -rf \$HOME/*"
    echo -e "  ${RED}• Result: TOTAL DATA LOSS${NC}"
    if [[ ${#SECURITY_SYSTEMS[@]} -gt 0 ]]; then
        echo "  • Protection: ${SECURITY_SYSTEMS[@]} (partial only)"
    fi
else
    echo -e "  ${GREEN}✓ DELETION WOULD BE BLOCKED${NC}"
    echo "  • Command: rm -rf \$HOME/* would be attempted"
    echo -e "  ${GREEN}• Result: Directories are protected${NC}"
    if [[ ${#BLOCKED_DIRS[@]} -gt 0 ]]; then
        echo "  • Protected: ${BLOCKED_DIRS[@]}"
    fi
    if [[ ${#SECURITY_SYSTEMS[@]} -gt 0 ]]; then
        echo "  • Protection: ${SECURITY_SYSTEMS[@]}"
    fi
fi

echo ""
if [[ "$PWD" != "$HOME" ]]; then
    echo "Current Directory ($PWD):"
    if [[ $CWD_DELETION_POSSIBLE -eq 1 ]]; then
        echo -e "  ${YELLOW}⚠ DELETION WOULD SUCCEED${NC}"
        echo "  • Current project/repository would be completely deleted"
        echo -e "  ${BLUE}ℹ Expected for coding sandboxes: work within project scope is unrestricted${NC}"
    else
        echo -e "  ${GREEN}✓ DELETION WOULD BE BLOCKED${NC}"
        echo "  • Current directory is protected"
    fi
    echo ""
fi

if command -v docker &> /dev/null && docker ps &> /dev/null 2>&1; then
    echo "Docker Privilege Escalation:"
    echo -e "  ${RED}⚠ CRITICAL: Docker available with user permissions${NC}"
    echo "  • Could mount host filesystem and delete as root"
    echo "  • Would bypass SIP, Seatbelt, SELinux, AppArmor"
    echo -e "  ${RED}• Could wipe system files, not just user data${NC}"
fi

echo -e "${BOLD}==================================================${NC}"
echo ""

# Exit with error code if critical findings
if [[ $CRITICAL -gt 0 ]]; then
    exit 2
elif [[ $HIGH -gt 0 ]]; then
    exit 1
else
    exit 0
fi
