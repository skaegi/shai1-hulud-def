# Protection Strategies

Comprehensive defense strategies against Shai1-Hulud and similar supply chain attacks.

---

## Desktop Operating Systems

### Credential Management

**Never store credentials in plaintext or environment variables.**

#### Best Practices

```bash
# ❌ BAD: Credentials in environment variables
export AWS_ACCESS_KEY_ID="AKIAIOSFODNN7EXAMPLE"
export GITHUB_TOKEN="ghp_xxxxxxxxxxxx"

# ✅ GOOD: Use credential managers
# - 1Password CLI
# - LastPass CLI
# - HashiCorp Vault
# - AWS SSO
# - Azure CLI with managed identities
```

#### Credential Manager Examples

```bash
# Using 1Password CLI
op run -- npm publish

# Using AWS SSO
aws sso login
aws s3 ls  # Uses temporary credentials

# Using Azure CLI
az login
az account get-access-token  # Short-lived token
```

### Authentication Security

1. **Enable Hardware-Based 2FA**
   - Use YubiKey, Titan Security Key, or similar
   - Enable on GitHub, npm, AWS, GCP, Azure
   - Avoid SMS-based 2FA when possible

2. **Use Short-Lived, Scoped Tokens**
   - Generate tokens with minimal required permissions
   - Set expiration dates (hours/days, not months/years)
   - Rotate frequently

3. **Implement Least-Privilege Access**
   - Only grant necessary permissions
   - Use separate tokens for different purposes
   - Regularly audit and remove unused tokens

### Package Management

```bash
# Pin dependencies to known-clean versions
npm ci --ignore-scripts

# Use lock files and commit them
git add package-lock.json

# Audit dependencies regularly
npm audit

# Use npm audit fix cautiously
npm audit fix --dry-run  # Review changes first
```

### System Monitoring

#### Endpoint Detection and Response (EDR)

Deploy EDR tools on developer machines:
- CrowdStrike Falcon
- Microsoft Defender for Endpoint
- SentinelOne
- Carbon Black

#### GitHub Activity Monitoring

Monitor for unauthorized activity:
- Unexpected repository creations
- Unusual API activity patterns
- Self-hosted runner installations
- Public repository conversions

#### Network Monitoring

```bash
# Monitor outbound connections
# Use Little Snitch (macOS) or Windows Firewall

# Alert on:
# - High volumes of GitHub API requests
# - Connections to npm registry from unexpected processes
# - Webhook sites or paste services
```

---

## CI/CD Pipeline Security

### Lifecycle Script Controls

**Primary defense against npm-based attacks:**

```bash
# Method 1: Command-line flag
npm install --ignore-scripts

# Method 2: .npmrc configuration (recommended for CI/CD)
echo "ignore-scripts=true" >> .npmrc
```

#### Implementation in CI/CD

```yaml
# GitHub Actions example
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - uses: actions/setup-node@v3
      - run: echo "ignore-scripts=true" >> .npmrc
      - run: npm ci

# GitLab CI example
build:
  script:
    - echo "ignore-scripts=true" >> .npmrc
    - npm ci

# Jenkins example
stage('Build') {
  steps {
    sh 'echo "ignore-scripts=true" >> .npmrc'
    sh 'npm ci'
  }
}
```

### Network Isolation

#### Restrict Outbound Access

```yaml
# Docker example with network restrictions
docker run --rm \
  --network none \  # No network access
  -v $(pwd):/app \
  node:latest npm ci --ignore-scripts

# Or allow only specific domains
# Use corporate proxy or firewall rules to allowlist:
# - registry.npmjs.org
# - registry.yarnpkg.com
# - github.com (for git dependencies)
```

#### Blocked Domains

Block these categories at the network level:
- Webhook sites (webhook.site, requestbin, etc.)
- Paste services (pastebin, hastebin, etc.)
- File-sharing platforms
- Unknown cloud storage services

### Token Management

**Critical for preventing credential theft:**

#### Short-Lived Tokens

```bash
# GitHub: Use GitHub App tokens (1 hour expiration)
# npm: Use automation tokens with short expiration

# Example: Generate short-lived token
gh auth refresh --expires-in 1h

# Rotate tokens frequently
# Set up automated rotation (daily/weekly)
```

#### Scoped Tokens

```bash
# GitHub: Limit token to specific repositories and permissions
gh auth login --scopes "repo:status,public_repo"

# npm: Use granular access tokens
npm token create --read-only --cidr=10.0.0.0/8
```

#### Token Expiration

- **Daily rotation** for high-security environments
- **Weekly rotation** for standard CI/CD
- **Never** use tokens longer than 90 days
- **Remove classic npm tokens** before December 9, 2025

### Build Environment Security

#### Ephemeral Containers

```bash
# Run builds in disposable containers
docker run --rm \
  -v $(pwd):/app \
  -w /app \
  --network=bridge \
  node:latest \
  sh -c "echo 'ignore-scripts=true' >> .npmrc && npm ci"

# No credentials persist between builds
# Fresh environment for each build
```

#### Credential Isolation

```yaml
# GitHub Actions: Use environment secrets, not repository secrets
# This limits blast radius if a repository is compromised

jobs:
  deploy:
    environment: production  # Requires approval
    steps:
      - run: npm publish
        env:
          NPM_TOKEN: ${{ secrets.NPM_TOKEN }}
```

#### Separate Service Accounts

- **Don't** use personal accounts in CI/CD
- **Do** create dedicated service accounts with minimal permissions
- **Do** use different accounts for different pipelines

### Supply Chain Security Tools

#### Continuous Scanning

```yaml
# GitHub Actions with Socket Security
- name: Socket Security
  uses: SocketDev/socket-action@v1
  with:
    token: ${{ secrets.SOCKET_TOKEN }}

# Snyk scanning
- name: Snyk Test
  uses: snyk/actions/node@master
  env:
    SNYK_TOKEN: ${{ secrets.SNYK_TOKEN }}
```

#### SBOM Generation

```bash
# Generate Software Bill of Materials
npm sbom --format cyclonedx > sbom.json

# Or using Syft
syft packages dir:. -o cyclonedx-json > sbom.json

# Track all dependencies and their versions
```

#### Dependency Review

```yaml
# GitHub Actions dependency review
- name: Dependency Review
  uses: actions/dependency-review-action@v3
  with:
    fail-on-severity: high
```

### Repository Monitoring

#### Automated Monitoring Workflow

```yaml
name: Security Monitor
on:
  schedule:
    - cron: '0 */4 * * *'  # Every 4 hours
  workflow_dispatch:

jobs:
  check-for-compromise:
    runs-on: ubuntu-latest
    steps:
      - name: Check for malicious repos
        env:
          GH_TOKEN: ${{ secrets.GITHUB_TOKEN }}
        run: |
          repos=$(gh repo list --json name,description | \
            jq -r '.[] | select(.description | contains("Sha1-Hulud")) | .name')

          if [ ! -z "$repos" ]; then
            echo "⚠️ WARNING: Potential Shai1-Hulud compromise detected!"
            echo "$repos"
            exit 1
          fi

      - name: Check for self-hosted runners
        run: |
          if gh api /repos/${{ github.repository }}/actions/runners | \
            jq -e '.runners[] | select(.name == "SHA1HULUD")'; then
            echo "⚠️ WARNING: Malicious runner detected!"
            exit 1
          fi

      - name: Check for suspicious workflows
        run: |
          if [ -f .github/workflows/discussion.yaml ]; then
            echo "⚠️ WARNING: Suspicious workflow detected!"
            exit 1
          fi
```

---

## Organizational Policies

### 1. Enforce MFA Everywhere

```bash
# GitHub organization policy
# Settings → Security → Require two-factor authentication

# npm organization policy
npm org set YOUR_ORG require-2fa=true
```

### 2. Package Adoption Cool-Down Period

**Don't immediately use new packages:**

- Wait 24-48 hours after package release
- Check package history and maintainer reputation
- Review source code for suspicious patterns
- Monitor for early reports of compromise

### 3. Code Review for Package Updates

```yaml
# Require PR reviews for dependency updates
branch_protection_rules:
  require_pull_request_reviews:
    required_approving_review_count: 1
    dismiss_stale_reviews: true
```

### 4. Separate Development and Production Credentials

- **Development**: Sandbox accounts with limited access
- **Staging**: Separate credentials from production
- **Production**: Highest security, most restricted access

### 5. Regular Security Training

- Supply chain attack awareness
- Credential hygiene
- Phishing prevention
- Incident response procedures

### 6. Incident Response Plan

**Prepare before an attack:**

- Document response procedures
- Assign roles and responsibilities
- Maintain contact lists
- Practice tabletop exercises
- Test backup and recovery procedures

---

## Quick Protection Checklist

### Immediate Actions (Do Now)

- [ ] Enable 2FA on GitHub, npm, AWS, GCP, Azure
- [ ] Remove credentials from environment variables
- [ ] Set `ignore-scripts=true` in CI/CD `.npmrc`
- [ ] Audit and rotate all access tokens
- [ ] Remove classic npm tokens (before Dec 9, 2025)
- [ ] Deploy EDR on developer machines
- [ ] Set up GitHub activity monitoring

### Short-Term (This Week)

- [ ] Implement credential manager (1Password, Vault, etc.)
- [ ] Deploy supply chain security tools (Socket, Snyk)
- [ ] Create security monitoring workflows
- [ ] Audit all self-hosted runners
- [ ] Review and clean up old access tokens
- [ ] Implement network egress filtering

### Long-Term (This Month)

- [ ] Implement short-lived token rotation
- [ ] Deploy SBOM generation
- [ ] Create incident response runbook
- [ ] Conduct security training for developers
- [ ] Implement package adoption cool-down policy
- [ ] Set up automated dependency review
- [ ] Audit all CI/CD pipelines for security

---

## Defense in Depth

**No single control prevents all attacks. Layer your defenses:**

1. **Credential Security** - Credential managers + 2FA + short-lived tokens
2. **Code Security** - Dependency scanning + code review + SBOM
3. **Runtime Security** - EDR + network monitoring + egress filtering
4. **Pipeline Security** - Lifecycle script controls + ephemeral builds + least privilege
5. **Detection** - Activity monitoring + alerting + threat intelligence
6. **Response** - Incident response plan + regular testing + documentation

---

**See also:**
- [Detection Indicators](detection.md) - Know what to look for
- [Response Guide](response.md) - What to do if compromised
- [Attack Overview](attack-overview.md) - Understand the threat
- [Resources](resources.md) - Security tools and vendors
