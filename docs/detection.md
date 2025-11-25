# Detection Indicators

This guide helps you identify if your systems have been compromised by the Shai1-Hulud malware.

---

## GitHub Repository Indicators

### Suspicious Repository Characteristics

- New repositories with description **"Sha1-Hulud: The Second Coming"** or **"Shai1-Hulud Migration"**
- Repository names with **random 18-character UUIDs**
- Repositories with **`-migration` suffix**
- Branches named **`shai-hulud`**

### Search Commands

```bash
# Using GitHub CLI
gh repo list --json name,description | jq -r '.[] | select(.description | contains("Sha1-Hulud"))'

# Using GitHub web search
# Search for: description:"Sha1-Hulud: The Second Coming"
```

---

## Workflow Indicators

### Malicious Workflow Files

Look for these suspicious workflow files in `.github/workflows/`:

- **`discussion.yaml`** - Persistent backdoor workflow
- **`shai-hulud-workflow.yml`** - Credential exfiltration workflow
- Workflows named **"Code Formatter"** that exfiltrate secrets

### Workflow Audit Commands

```bash
# Find all workflow files
find .github/workflows/ -name "*.yml" -o -name "*.yaml"

# Search for suspicious workflow content
grep -r "discussion.body" .github/workflows/
grep -r "SHA1HULUD" .github/workflows/
```

---

## File System Indicators

### Malicious Files (Version 2.0)

- **`setup_bun.js`** - Dropper disguised as Bun installer
- **`bun_environment.js`** - Main payload (10MB file)
- **`cloud.json`** - Exfiltrated cloud credentials
- **`contents.json`** - Exfiltrated GitHub/npm tokens
- **`environment.json`** - Exfiltrated environment variables
- **`truffleSecrets.json`** - TruffleHog scan results

### File Search Commands

```bash
# Search for malicious files in home directory
find ~/ -name "setup_bun.js" -o -name "bun_environment.js" 2>/dev/null

# Search for exfiltrated data files
find ~/ -name "cloud.json" -o -name "truffleSecrets.json" 2>/dev/null

# Search for all suspicious files
find ~/ \( -name "setup_bun.js" -o -name "bun_environment.js" -o -name "cloud.json" -o -name "contents.json" -o -name "environment.json" -o -name "truffleSecrets.json" \) 2>/dev/null
```

---

## Self-Hosted Runner Indicators

### Runner Characteristics

- GitHub Actions runner named **"SHA1HULUD"**
- Runner files in **`~/.dev-env/`** directory
- Background processes related to GitHub Actions runner

### Detection Commands

```bash
# Check for runner directory
ls -la ~/.dev-env/

# Check for running processes
ps aux | grep -i "runner\|sha1hulud"

# Check for runner service
ps aux | grep "actions-runner"
```

---

## Package Indicators

### Suspicious Package Characteristics

- Unexpected **`preinstall`** or **`postinstall`** scripts in package.json
- Package versions published that you didn't authorize
- **Sequential version bumps** (e.g., 18.0.2 → 18.0.3 → 18.0.4)
- Large file sizes (10MB+ files like `bun_environment.js`)

### Package Audit Commands

```bash
# Find all package.json files with lifecycle scripts
find . -name "package.json" -exec grep -l "preinstall\|postinstall" {} \;

# Audit specific package.json
cat package.json | jq '.scripts'

# Check npm audit
npm audit
```

---

## Network Indicators

### Suspicious Network Activity

- Outbound connections to GitHub API for unusual repo creation
- Connections to npm registry API for unauthorized package publishing
- Historical webhook connections (now deactivated):
  - `webhook.site/bb8ca5f6-4175-45d2-b042-fc9ebb8170b7`

### Network Monitoring

```bash
# Monitor active connections (requires running during attack)
lsof -i | grep -i github
netstat -an | grep ESTABLISHED

# Check DNS queries (if logging enabled)
# Look for high volumes of api.github.com requests
```

---

## IoC (Indicators of Compromise)

### File Hashes (SHA-256)

Known malicious file hashes:

```
46faab8ab153fae6e80e7cca38eab363075bb524edd79e42269217a083628f09
b74caeaa75e077c99f7d44f46daaf9796a3be43ecf24f2a1fd381844669da777
dc67467a39b70d1cd4c1f7f7a459b35058163592f4a9e8fb4dffcbba98ef210c
4b2399646573bb737c4969563303d8ee2e9ddbd1b271f1ca9e35ea78062538db
```

### Verify File Hashes

```bash
# Check hash of suspicious file
shasum -a 256 setup_bun.js

# Compare against known malicious hashes
shasum -a 256 setup_bun.js | grep -f malicious_hashes.txt
```

### Repository Search Patterns

```regex
# GitHub search patterns
description:"Sha1-Hulud: The Second Coming"
description:"Shai1-Hulud Migration"
name:*-migration
```

### File Search Patterns

```bash
# Comprehensive file search
find / -name "setup_bun.js" 2>/dev/null
find / -name "bun_environment.js" 2>/dev/null
find / -name "*hulud*.yml" 2>/dev/null
find ~/.github/workflows/ -name "discussion.yaml" 2>/dev/null
```

---

## Security Tools for Detection

### Commercial Solutions

- **Wiz Cloud Security** - CNAPP with Shai1-Hulud detection
- **Docker Scout** - Continuous SBOM monitoring
- **Tenable Cloud Security** - Real-time IoC tracking
- **Snyk** - Dependency vulnerability scanning
- **Socket** - npm malicious package detection
- **Checkmarx** - SCA with malicious package protection
- **Black Duck** - 187 BDSAs for affected components
- **Aikido Security** - Developer security platform
- **SafeDep** - Supply chain security
- **StepSecurity** - CI/CD security

### Open Source Tools

- **TruffleHog** - Secret scanning (ironically used by the malware itself)
- **npm audit** - Built-in vulnerability scanner
- **git-secrets** - Prevent committing secrets

---

## Quick Detection Checklist

Run these commands to perform a quick check:

```bash
# 1. Check for suspicious GitHub repos
gh repo list --json name,description | jq -r '.[] | select(.description | contains("Sha1-Hulud"))'

# 2. Check for malicious files
find ~/ \( -name "setup_bun.js" -o -name "bun_environment.js" -o -name "cloud.json" \) 2>/dev/null

# 3. Check for self-hosted runner
ps aux | grep -i "runner\|sha1hulud"
ls -la ~/.dev-env/ 2>/dev/null

# 4. Check for malicious workflows
find . -path "*/.github/workflows/*" \( -name "*hulud*" -o -name "discussion.yaml" \)

# 5. Audit package.json files
find . -name "package.json" -exec grep -l "preinstall\|postinstall" {} \;
```

If any of these checks return results, **immediately proceed to the [Response Guide](response.md)**.

---

**See also:**
- [Response Guide](response.md) - Immediate actions if compromised
- [Attack Overview](attack-overview.md) - Understanding how the attack works
- [Protection Strategies](protection.md) - Preventing future compromises
