# GitHub Actions Defence Strategy

High-level defensive strategies for securing GitHub Actions workflows against Shai1-Hulud and similar supply chain attacks.

---

## GitHub Actions as Attack Surface

**Why GitHub Actions are prime targets:**

- **Credential access**: Workflows have access to repository secrets, GITHUB_TOKEN, and cloud provider credentials
- **Privileged execution**: Workflows run with permissions to commit, push, publish packages, deploy infrastructure
- **Self-hosted runners**: Persistent compute that can be backdoored (Shai1-Hulud installs "SHA1HULUD" runner)
- **Workflow injection**: User-controlled input in workflows enables remote code execution
- **npm lifecycle scripts**: `npm install` in workflows executes malicious code
- **Public repositories**: Workflow files are visible, making reconnaissance easy
- **Fork pull requests**: Can trigger workflows with malicious code

**Shai1-Hulud specifically targets GitHub Actions:**
- Installs self-hosted runner named "SHA1HULUD"
- Creates malicious `discussion.yaml` workflow
- Exfiltrates secrets via workflow execution
- Uses GitHub API for propagation

---

## Defence Strategy: Five Layers

### Layer 1: Workflow Security Hardening

**Goal**: Prevent workflow injection and unauthorized execution.

**The Problem**: Workflows that use untrusted input are vulnerable:
```yaml
# VULNERABLE - User controls discussion body
run: |
  ${{ github.event.discussion.body }}

# VULNERABLE - Issue title in command
run: echo "${{ github.event.issue.title }}"
```

**Capabilities Needed**:
- **Input validation**: Sanitize all user-controlled input
- **Workflow injection detection**: Identify dangerous patterns
- **Permission scoping**: Minimal required permissions only
- **Code review for workflows**: Treat workflows as production code
- **Branch protection**: Protect workflow files from unauthorized changes

**Defensive Principles**:

**1. Never Trust User Input**
- Pull request titles, bodies, comments
- Issue titles, bodies, labels
- Discussion content
- Commit messages
- Branch names

**2. Use Intermediate Steps**
- Don't inline user input directly in `run:`
- Use environment variables as intermediary
- Validate before use

**3. Scope Permissions Minimally**
```yaml
permissions:
  contents: read        # Not write unless necessary
  packages: none        # Not write unless publishing
  actions: none         # Typically not needed
  security-events: none
```

**4. Pin Actions to Commit SHA**
```yaml
# BAD - Mutable tag
uses: actions/checkout@v3

# GOOD - Immutable commit hash
uses: actions/checkout@8e5e7e5ab8b370d6c329ec480221332ada57f0ab # v3.5.2
```

**Defence Value**: Prevent attackers from injecting code via workflow vulnerabilities.

---

### Layer 2: npm Lifecycle Script Control

**Goal**: Prevent malicious npm packages from executing during CI/CD.

**The Problem**: `npm install` runs lifecycle scripts by default. Shai1-Hulud uses `preinstall` scripts that execute before package installation completes.

**Capabilities Needed**:
- **Lifecycle script blocking**: Disable by default
- **Audit logging**: Track what would have executed
- **Exception handling**: Allow known-safe scripts with approval
- **Dependency verification**: Check package integrity before install

**Critical Defence**:

```yaml
# In workflow or add to repository .npmrc
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - name: Setup
        run: echo "ignore-scripts=true" >> .npmrc

      - name: Install dependencies
        run: npm ci  # Now protected
```

**Alternative Approaches**:
- Commit `.npmrc` with `ignore-scripts=true` to repository
- Use `npm ci --ignore-scripts` in all workflow steps
- Pre-install dependencies in Docker image with scripts disabled
- Validate package checksums before installation

**What This Blocks**:
- Malicious `preinstall` scripts (Shai1-Hulud's primary vector)
- Malicious `postinstall` scripts
- Arbitrary code execution during dependency installation
- Credential harvesting during build

**Defence Value**: Primary mitigation for npm-based supply chain attacks in CI/CD.

---

### Layer 3: Secrets Management

**Goal**: Limit secret exposure and prevent theft via compromised workflows.

**The Problem**: Secrets exposed to workflows can be exfiltrated:
- Logged to console (captured in logs)
- Sent to attacker-controlled servers
- Committed to repositories
- Uploaded as artifacts

**Capabilities Needed**:
- **Secret scoping**: Limit which workflows/jobs access secrets
- **Short-lived credentials**: Rotate frequently, minimal lifetime
- **OIDC tokens**: Use GitHub OIDC instead of long-lived secrets
- **Secret scanning**: Detect accidental exposure
- **Audit logging**: Track secret usage

**Defensive Strategies**:

**1. Use GitHub OIDC Instead of Secrets**
```yaml
# Instead of AWS_ACCESS_KEY_ID/AWS_SECRET_ACCESS_KEY
permissions:
  id-token: write
  contents: read

- name: Configure AWS
  uses: aws-actions/configure-aws-credentials@v2
  with:
    role-to-assume: arn:aws:iam::123456789012:role/GitHubActionsRole
    aws-region: us-east-1
    # No secrets needed - uses OIDC token
```

**2. Environment-Specific Secrets**
```yaml
# Require approval for production
environment: production  # Protected environment
steps:
  - run: npm publish
    env:
      NPM_TOKEN: ${{ secrets.NPM_TOKEN }}
```

**3. Minimal Secret Scope**
- Only give secrets to jobs that need them
- Use separate tokens for different purposes
- Rotate tokens frequently (daily/weekly)
- Use read-only tokens where possible

**4. Never Log Secrets**
- GitHub automatically masks registered secrets
- But encoding (base64) bypasses masking
- Never `echo` or `console.log` secrets
- Be careful with debug logging

**What Shai1-Hulud Does**:
- Exfiltrates `${{ toJSON(secrets) }}` in workflows
- Double base64 encodes to bypass secret masking
- Uploads to attacker-controlled GitHub repositories

**Defence Value**: Minimize credential theft impact even if workflow is compromised.

---

### Layer 4: Self-Hosted Runner Security

**Goal**: Prevent runner backdoors and ensure runner integrity.

**The Problem**: Self-hosted runners are persistent compute. Shai1-Hulud:
- Installs runner named "SHA1HULUD" in `~/.dev-env/`
- Survives reboots
- Provides persistent remote access via workflow triggers
- Can access all secrets available to workflows

**Capabilities Needed**:
- **Runner inventory**: Know what runners exist
- **Runner authentication**: Verify runner identity
- **Ephemeral runners**: Destroy after each job
- **Network isolation**: Limit runner internet access
- **Integrity monitoring**: Detect runner tampering
- **Access logging**: Audit what runs on each runner

**Defensive Strategies**:

**1. Prefer GitHub-Hosted Runners**
- Ephemeral by design (destroyed after job)
- Managed by GitHub
- No persistence risk
- Use unless you have specific requirements

**2. Ephemeral Self-Hosted Runners**
- Spin up for single job, destroy immediately
- Use container-based runners
- Fresh environment every time
- Tools: actions-runner-controller (Kubernetes)

**3. Runner Monitoring**
```bash
# Daily check for unauthorized runners
gh api /repos/OWNER/REPO/actions/runners | jq '.runners[] | {name, os, status}'

# Alert on suspicious runner names
jq '.runners[] | select(.name | contains("SHA1HULUD") or contains("hulud"))'
```

**4. Runner Hardening**
- Minimal software installed
- No credentials persisted on runner
- Network egress filtering
- File integrity monitoring
- Regular image rotation

**5. Runner Access Control**
- Require approval for self-hosted runner jobs
- Use labels to segregate runners by trust level
- Don't use self-hosted runners for public repositories
- Separate runners for different sensitivity levels

**Red Flags**:
- Runner named "SHA1HULUD"
- Unexpected runner registrations
- Runners in `~/.dev-env/` directory
- Runners that persist across reboots without your knowledge

**Defence Value**: Eliminate persistent backdoor capability.

---

### Layer 5: Supply Chain Controls

**Goal**: Ensure dependencies and actions are trustworthy.

**The Problem**: Workflows pull code from:
- npm packages (can be compromised)
- GitHub Actions (can be malicious or compromised)
- Docker images (can contain malware)
- External scripts (arbitrary code execution)

**Capabilities Needed**:
- **Dependency scanning**: Identify vulnerable packages
- **Action verification**: Ensure actions are trustworthy
- **Pinning to immutable references**: Prevent version swaps
- **SBOM generation**: Track all dependencies
- **Automated updates with review**: Keep current but controlled

**Defensive Strategies**:

**1. Pin Actions to Commit SHA**
```yaml
# Pin to specific commit, not mutable tag
uses: actions/checkout@8e5e7e5ab8b370d6c329ec480221332ada57f0ab # v3.5.2
```

**2. Use Dependency Review**
```yaml
- name: Dependency Review
  uses: actions/dependency-review-action@v3
  with:
    fail-on-severity: high
    deny-licenses: GPL-3.0, AGPL-3.0
```

**3. Use Supply Chain Security Tools**
```yaml
- name: Socket Security
  uses: SocketDev/socket-action@v1

- name: Snyk
  uses: snyk/actions/node@master
```

**4. Lock File Integrity**
```yaml
# Verify lock file hasn't been tampered with
- name: Verify lock file
  run: |
    npm ci --ignore-scripts
    git diff --exit-code package-lock.json
```

**5. SBOM Generation**
```yaml
- name: Generate SBOM
  run: npm sbom --format cyclonedx > sbom.json

- name: Upload SBOM
  uses: actions/upload-artifact@v3
  with:
    name: sbom
    path: sbom.json
```

**Defence Value**: Know what code you're running and verify it's trustworthy.

---

## Continuous Monitoring

**Goal**: Detect compromises and security drift over time.

**Monitoring Strategies**:

**Daily Automated Checks**:
```yaml
name: Security Monitor
on:
  schedule:
    - cron: '0 */6 * * *'  # Every 6 hours

jobs:
  security-check:
    runs-on: ubuntu-latest
    steps:
      - name: Check for malicious runners
        run: |
          runners=$(gh api /repos/${{ github.repository }}/actions/runners | \
            jq -r '.runners[] | select(.name | contains("SHA1HULUD") or contains("hulud")) | .name')
          if [ ! -z "$runners" ]; then
            echo "::error::Malicious runner detected: $runners"
            exit 1
          fi

      - name: Check for suspicious workflows
        uses: actions/checkout@v3
        run: |
          if find .github/workflows -name "discussion.yaml" -o -name "*hulud*"; then
            echo "::error::Suspicious workflow file detected"
            exit 1
          fi

      - name: Audit workflow permissions
        run: |
          # Check for workflows with overly broad permissions
          grep -r "permissions:" .github/workflows/ | grep -v "read"
```

**Audit Logging**:
- Enable organization audit log
- Monitor for workflow file changes
- Track secret usage
- Alert on new runner registrations
- Review workflow run logs for anomalies

**Security Scanning**:
- CodeQL for workflow injection vulnerabilities
- Secret scanning for exposed credentials
- Dependency scanning for vulnerable packages
- Custom rules for organization-specific risks

**Defence Value**: Early detection of compromise before widespread damage.

---

## Defence Priorities

### Immediate (Do Today)
1. **Add `ignore-scripts=true` to all workflow npm installs**
2. **Audit self-hosted runners** - Remove any named "SHA1HULUD"
3. **Review `.github/workflows/` for `discussion.yaml`**
4. **Check workflow permissions** - Scope minimally
5. **Enable secret scanning**

### Short-Term (This Week)
1. **Pin all actions to commit SHA**
2. **Implement OIDC for cloud credentials** (replace long-lived secrets)
3. **Add dependency review action**
4. **Set up security monitoring workflow**
5. **Review and scope all secrets**

### Long-Term (This Month)
1. **Move to ephemeral self-hosted runners** (if using self-hosted)
2. **Implement SBOM generation**
3. **Deploy supply chain security tools** (Socket, Snyk)
4. **Create workflow security policy**
5. **Train team on workflow injection risks**

---

## Workflow Security Checklist

**Every workflow should:**

- [ ] Use `ignore-scripts=true` for npm installs
- [ ] Pin actions to commit SHA, not tags
- [ ] Scope permissions minimally
- [ ] Never use user input directly in `run:` commands
- [ ] Use environment variables for intermediary values
- [ ] Not log or expose secrets
- [ ] Use OIDC tokens instead of long-lived secrets where possible
- [ ] Run on GitHub-hosted runners (or ephemeral self-hosted)
- [ ] Have dependency review enabled
- [ ] Be reviewed by security team if accessing production

**Red Flags to Reject**:

- [ ] `${{ github.event.*.body }}` directly in run commands
- [ ] `actions/*@latest` or `@v1` tags (mutable)
- [ ] `permissions: write-all`
- [ ] `npm install` without `--ignore-scripts`
- [ ] `echo "${{ secrets.* }}"` or similar
- [ ] Self-hosted runner for public repository
- [ ] Workflow named `discussion.yaml` with suspicious content

---

## Measuring Effectiveness

**Can your CI/CD answer these questions?**

- ✅ Would you know if a new self-hosted runner was registered?
- ✅ Can npm lifecycle scripts execute in your workflows?
- ✅ Are all actions pinned to immutable commit hashes?
- ✅ Do workflows have minimal scoped permissions?
- ✅ Are secrets accessed only by jobs that need them?
- ✅ Would you detect if `discussion.yaml` was added?
- ✅ Can you audit what ran on self-hosted runners?
- ✅ Do you scan dependencies for vulnerabilities?
- ✅ Are workflow changes reviewed before merging?

**If you answered "no" to any of these, you have a gap.**

---

## Key Principles

1. **Workflows Are Code**: Review, test, and secure like production code
2. **Least Privilege**: Minimal permissions, minimal secret access
3. **Immutable References**: Pin to commit SHA, not mutable tags
4. **Never Trust Input**: Validate all user-controlled input
5. **Block by Default**: Disable npm scripts, explicit allow only
6. **Ephemeral Compute**: Prefer GitHub-hosted or ephemeral runners
7. **Continuous Monitoring**: Detect drift and compromise early

---

## Advanced Defences

### Branch Protection for Workflows

```yaml
# Protect .github/workflows/ from unauthorized changes
# Settings → Branches → Branch protection rules

Required:
- Require pull request reviews (2+ reviewers)
- Require status checks to pass
- Require review from CODEOWNERS
- Restrict who can push
```

### Workflow Approval for Sensitive Jobs

```yaml
# Require manual approval for production deployments
environment: production
# Settings → Environments → production → Required reviewers
```

### Organization-Wide Policies

```yaml
# Enforce settings across all repositories
# Settings → Actions → General

- Disable self-hosted runners for public repos
- Require approval for first-time contributors
- Limit workflow run duration
- Control forked repository behavior
```

### Network Egress Filtering

For self-hosted runners:
- Allowlist: `registry.npmjs.org`, `github.com`, `api.github.com`
- Block: webhook sites, paste services, unknown destinations
- Log all connections for audit

---

## Next Steps

1. **Audit**: Review all workflows for vulnerabilities
2. **Harden**: Add `ignore-scripts=true` everywhere
3. **Monitor**: Deploy security monitoring workflow
4. **Scope**: Minimize permissions and secret access
5. **Pin**: Convert all actions to commit SHA
6. **Test**: Verify defences with security scan
7. **Iterate**: Refine based on findings

---

**See also:**
- [Protection Strategies](protection.md) - General CI/CD security
- [Detection Indicators](detection.md) - How to detect compromises
- [Response Guide](response.md) - Incident response procedures
- [Technical Details](technical-details.md) - Attack mechanics
