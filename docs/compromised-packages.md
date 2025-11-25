# Compromised Packages

This document tracks npm packages and organizations affected by the Shai1-Hulud attacks.

**Status**: This is an active, ongoing attack. This list is updated as new compromises are discovered.

---

## High-Profile Victims (November 2025 Wave)

### Zapier

**Impact**: Essential for Zapier integration developers

**Compromised Packages**:
- `@zapier/platform-core`
- `@zapier/platform-cli`
- `zapier-platform-*` toolkit packages

**Significance**: Zapier's official packages are widely used by developers building integrations on the Zapier platform. Compromise affects the entire Zapier developer ecosystem.

---

### ENS Domains

**Impact**: Used by wallets, DApps, exchanges, ENS Manager

**Compromised Packages**:
- `@ensdomains/*` (multiple packages)
- `ensjs`
- `ens-contracts`
- `react-ens-address`

**Significance**: ENS (Ethereum Name Service) packages are critical infrastructure for Web3 applications. Compromise affects major cryptocurrency wallets and decentralized applications.

---

### PostHog

**Impact**: Found in 25% of surveyed environments

**Compromised Packages**:
- `posthog-node` (25% of environments)
- `@posthog/siphash`

**Significance**: PostHog is a popular product analytics platform. The widespread usage means many production environments are potentially affected.

---

### Postman

**Impact**: Found in 27% of surveyed environments

**Compromised Packages**:
- `@postman/tunnel-agent` (27% of environments)

**Significance**: Highest penetration rate of any compromised package. This package is used internally by Postman for API testing and development.

---

### AsyncAPI

**Impact**: Core infrastructure for async API development

**Compromised Packages**:
- `@asyncapi/specs` (20% of environments)
- `@asyncapi/openapi-schema-parser` (17% of environments)
- `go-template`

**Significance**: AsyncAPI is fundamental for event-driven architecture and async API documentation. Widespread use in microservices architectures.

---

## September 2025 Wave (First Wave)

### High-Download Packages

#### @ctrl/tinycolor
- **Weekly Downloads**: 2.2 million
- **Type**: Color manipulation library
- **Impact**: Massive reach due to high download count

#### ngx-bootstrap
- **Weekly Downloads**: 300,000
- **Type**: Angular Bootstrap components
- **Impact**: Core Angular ecosystem package

#### ng2-file-upload
- **Weekly Downloads**: 100,000
- **Type**: Angular file upload component
- **Impact**: Common file upload solution for Angular apps

#### rxnt-authentication
- **Weekly Downloads**: Low
- **Significance**: **Patient Zero** - First package compromised
- **Published**: September 14, 2025 at 17:58:50 UTC
- **Detection**: September 15, 2025 by ReversingLabs

---

## Attack Statistics

### Scale of Compromise

**First Wave (September 2025)**:
- 500+ packages compromised
- 278+ secrets publicly leaked
- 90 secrets from local machines
- 188 secrets from malicious workflows

**Second Wave (November 2025)**:
- **800+ packages** compromised
- **25,000+ GitHub repositories** affected
- **~500 unique GitHub accounts** compromised
- **132 million** monthly downloads across compromised packages
- **5,000+ files** with stolen credentials uploaded to GitHub

### Environmental Impact

Penetration rates in cloud/code environments:
- **27%**: `@postman/tunnel-agent`
- **25%**: `posthog-node`
- **20%**: `@asyncapi/specs`
- **17%**: `@asyncapi/openapi-schema-parser`

### Temporal Metrics

- **1,000 repositories** compromised every 30 minutes (at peak)
- **72 hours** from start to 25,000 repos compromised
- **3 days** active attack window (November 21-23, 2025)

---

## How to Check if You're Affected

### Check Your Dependencies

```bash
# Check package-lock.json for compromised packages
cat package-lock.json | jq -r '.packages | keys[]' | grep -E "(zapier|ensdomains|posthog|postman|asyncapi|ctrl/tinycolor|ngx-bootstrap|ng2-file-upload|rxnt-authentication)"

# Check node_modules
ls node_modules/@zapier/
ls node_modules/@ensdomains/
ls node_modules/@posthog/
ls node_modules/@postman/
ls node_modules/@asyncapi/

# Use npm list to check installed versions
npm list @zapier/platform-core
npm list @ensdomains/ensjs
npm list posthog-node
npm list @postman/tunnel-agent
npm list @asyncapi/specs
```

### Check Specific Version Ranges

**Note**: Security researchers are still identifying exactly which versions are malicious. Monitor security advisories for specific version information.

**General guidance**:
- Versions published between November 21-24, 2025 are suspect
- Look for unexpected version bumps
- Check for `preinstall` or `postinstall` scripts in package.json

### Check Your Projects

```bash
# Find all projects using potentially compromised packages
find ~ -name package.json -exec grep -l "zapier\|ensdomains\|posthog\|postman\|asyncapi\|tinycolor\|ngx-bootstrap\|ng2-file-upload" {} \;

# For each project, audit the package.json
cd YOUR_PROJECT
npm audit
```

---

## Reporting New Compromises

If you discover additional compromised packages:

1. **Do Not** publicize the package name immediately
2. **Report to**:
   - npm security: security@npmjs.com
   - GitHub Security: https://github.com/security
   - CISA: https://www.cisa.gov/report
3. **Document**:
   - Package name and version
   - Evidence of compromise (malicious scripts, files)
   - Date of discovery
   - Impact assessment

---

## Package Verification

### How to Verify a Package

```bash
# 1. Check package.json for lifecycle scripts
npm view PACKAGE_NAME --json | jq '.scripts'

# 2. Download and inspect the package
npm pack PACKAGE_NAME
tar -xzf PACKAGE_NAME-*.tgz
cd package

# 3. Look for suspicious files
ls -la
find . -name "setup_bun.js" -o -name "bun_environment.js"

# 4. Check for large files (10MB+)
find . -type f -size +10M

# 5. Review package.json scripts
cat package.json | jq '.scripts'
```

### Red Flags

- ⚠️ `preinstall` or `postinstall` scripts you don't recognize
- ⚠️ Files named `setup_bun.js` or `bun_environment.js`
- ⚠️ Large (10MB+) JavaScript files
- ⚠️ Obfuscated or minified code in lifecycle scripts
- ⚠️ Network connections during installation
- ⚠️ Unexpected version bumps

---

## Clean Versions

### How to Find Clean Versions

```bash
# Check npm registry for version history
npm view PACKAGE_NAME versions --json

# Check version publish dates
npm view PACKAGE_NAME time --json

# Install version published before November 21, 2025
npm install PACKAGE_NAME@VERSION
```

### Freezing Dependencies

```json
// package.json - Use exact versions
{
  "dependencies": {
    "@zapier/platform-core": "15.3.0",  // Exact version, not ^15.3.0
    "posthog-node": "3.1.3"
  }
}
```

```bash
# Generate lock file with exact versions
npm install --package-lock-only

# Commit lock file
git add package-lock.json
git commit -m "Lock dependencies to clean versions"
```

---

## Supply Chain Security Resources

### Package Scanning Services

- **Socket**: https://socket.dev
- **Snyk**: https://snyk.io
- **npm audit**: Built into npm CLI
- **Checkmarx SCA**: https://checkmarx.com
- **Sonatype Nexus**: https://www.sonatype.com

### Monitoring Services

- **Mend.io** (formerly WhiteSource): Vulnerability tracking
- **Black Duck**: 187 BDSAs for affected components
- **Aikido Security**: Developer security platform
- **SafeDep**: Supply chain security

---

## Related Compromises

### Historical Context

Shai1-Hulud is part of a broader pattern of npm supply chain attacks:

- **S1ngularity/Nx Attack** (August 2025): Credential theft, private repo exposure
- **Qix Compromise** (2025): 18 packages with 2 billion weekly downloads
- **event-stream** (2018): Bitcoin wallet theft via compromised package
- **ua-parser-js** (2021): Cryptocurrency miner injection
- **coa/rc** (2021): Password-stealing malware

---

**See also:**
- [Detection Indicators](detection.md) - How to check if you're compromised
- [Response Guide](response.md) - What to do if affected
- [Protection Strategies](protection.md) - Prevent future compromises
- [Resources](resources.md) - Security advisories and reports
