# Shai1-Hulud npm Supply Chain Attack Reference

> A comprehensive defensive security reference for understanding, detecting, and responding to the Shai1-Hulud supply chain attacks.

---

## ⚠️ Current Status: ACTIVE THREAT

**As of November 2025, this is an ongoing attack.**

- **800+ npm packages** compromised
- **25,000+ GitHub repositories** affected
- **132 million** monthly downloads across compromised packages
- **Critical Deadline**: December 9, 2025 - npm will revoke all classic tokens

**If you installed npm packages between November 21-25, 2025, you may be compromised.**

---

## Quick Start

### 🔍 Check If You're Affected

```bash
# 1. Check for suspicious GitHub repos
gh repo list --json name,description | jq -r '.[] | select(.description | contains("Sha1-Hulud"))'

# 2. Check for malicious files
find ~/ \( -name "setup_bun.js" -o -name "bun_environment.js" -o -name "cloud.json" \) 2>/dev/null

# 3. Check for self-hosted runner
ps aux | grep -i "runner\|sha1hulud"

# 4. Audit workflows
find . -path "*/.github/workflows/*" \( -name "*hulud*" -o -name "discussion.yaml" \)
```

If any checks return results, **immediately see [Incident Response Guide](docs/response.md)**.

### 🛡️ Immediate Protection

```bash
# 1. Add to CI/CD .npmrc
echo "ignore-scripts=true" >> .npmrc

# 2. Rotate ALL credentials
# - GitHub tokens
# - npm tokens
# - AWS/GCP/Azure credentials

# 3. Enable 2FA everywhere
```

---

## What is Shai1-Hulud?

Shai1-Hulud is a sophisticated, self-replicating worm targeting the npm ecosystem. Named after the giant sandworms from Frank Herbert's "Dune," it represents one of the most severe JavaScript supply chain attacks observed to date.

### Key Characteristics

- **Self-Replicating**: Automatically spreads to other packages maintained by compromised accounts
- **Credential Harvesting**: Steals AWS, GCP, Azure, GitHub, and npm credentials
- **Persistent Backdoor**: Installs GitHub Actions self-hosted runners for long-term access
- **Token Recycling**: Novel technique that reuses stolen credentials from other victims
- **Destructive Capability**: Attempts to delete home directory if exfiltration fails

### Attack Waves

**First Wave (September 2025)**:
- 500+ packages compromised
- First detected September 15, 2025
- Patient Zero: `rxnt-authentication@0.0.3`

**Second Wave (November 2025)** - **ACTIVE NOW**:
- 800+ packages compromised
- 25,000+ GitHub repositories affected
- Major victims: Zapier, ENS Domains, PostHog, Postman, AsyncAPI

---

## Documentation Index

### 📖 Core Documentation

#### [Attack Overview](docs/attack-overview.md)
Comprehensive overview of how the attack works, timeline, key capabilities, and attack statistics.

**Topics**: Timeline, attack vector, credential harvesting, token recycling, persistent backdoor, self-replication, destructive capabilities

#### [Detection Indicators](docs/detection.md)
How to detect if your systems have been compromised by Shai1-Hulud.

**Topics**: GitHub repository indicators, workflow indicators, file system indicators, self-hosted runners, package indicators, IoCs, security tools

#### [Incident Response Guide](docs/response.md)
Step-by-step guide for responding to a Shai1-Hulud compromise.

**Topics**: Emergency actions, containment, assessment, eradication, recovery, post-incident, forensic analysis

#### [Protection Strategies](docs/protection.md)
Comprehensive defense strategies for desktop and CI/CD environments.

**Topics**: Credential management, authentication security, package management, CI/CD pipeline security, network isolation, organizational policies

### 🖥️ Platform-Specific Defence

#### [macOS Defence Strategy](docs/macos-defence.md)
High-level defensive strategies for macOS developer environments.

**Topics**: Security auditing, network egress control, execution monitoring, file system monitoring, credential isolation, four-layer defence model

#### [Linux Defence Strategy](docs/linux-defence.md)
High-level defensive strategies for Linux developer environments.

**Topics**: auditd configuration, SELinux/AppArmor, systemd hardening, namespace isolation, Docker security, comprehensive monitoring

#### [Windows Defence Strategy](docs/windows-defence.md)
High-level defensive strategies for Windows developer environments.

**Topics**: PowerShell hardening, Windows Defender, UAC, Windows Firewall, scheduled task monitoring, registry protection

**Note**: Shai1-Hulud skips Windows systems but these defences apply to other supply chain attacks.

### ⚙️ CI/CD & Workflow Defence

#### [GitHub Actions Defence Strategy](docs/github-actions-defence.md)
High-level defensive strategies for securing GitHub Actions workflows.

**Topics**: Workflow security hardening, npm lifecycle script control, secrets management, self-hosted runner security, supply chain controls, continuous monitoring

**Critical**: Shai1-Hulud specifically targets GitHub Actions with self-hosted runner backdoors and malicious workflows.

#### [Technical Details](docs/technical-details.md)
Deep technical dive into the malware's implementation and attack flow.

**Topics**: 7-stage attack flow, pseudo-code analysis, credential harvesting techniques, exfiltration methods, worm propagation logic

#### [Compromised Packages](docs/compromised-packages.md)
List of affected packages, organizations, and how to check if you're using them.

**Topics**: High-profile victims (Zapier, ENS, PostHog, Postman, AsyncAPI), package verification, clean versions

#### [Resources & References](docs/resources.md)
Security reports, vendor responses, tools, and additional resources.

**Topics**: Security research reports, industry coverage, vendor responses, security tools, threat intelligence, community resources

---

## Quick Reference

### 🚨 Emergency Response Checklist

If you suspect compromise:

- [ ] Isolate affected systems
- [ ] Check for malicious GitHub repositories
- [ ] Rotate ALL credentials (GitHub, npm, AWS, GCP, Azure)
- [ ] Remove self-hosted runner named "SHA1HULUD"
- [ ] Delete `.github/workflows/discussion.yaml`
- [ ] Scan for malicious files (`setup_bun.js`, `bun_environment.js`)
- [ ] Review cloud provider audit logs
- [ ] Audit all package.json preinstall/postinstall scripts

**Full checklist**: [Response Guide](docs/response.md)

---

### 🛡️ Protection Checklist

Essential security measures:

- [ ] Set `ignore-scripts=true` in CI/CD `.npmrc`
- [ ] Enable 2FA on GitHub, npm, AWS, GCP, Azure
- [ ] Remove credentials from environment variables
- [ ] Audit and rotate all access tokens
- [ ] Remove classic npm tokens before December 9, 2025
- [ ] Deploy EDR on developer machines
- [ ] Implement network egress filtering
- [ ] Deploy supply chain security tools (Socket, Snyk)

**Full checklist**: [Protection Strategies](docs/protection.md)

---

### 🔍 Detection Commands

Quick detection commands:

```bash
# Check GitHub repos
gh repo list --json name,description | \
  jq -r '.[] | select(.description | contains("Sha1-Hulud"))'

# Check for malicious files
find ~/ \( -name "setup_bun.js" -o -name "bun_environment.js" \
  -o -name "cloud.json" -o -name "truffleSecrets.json" \) 2>/dev/null

# Check for self-hosted runner
ps aux | grep -i "runner\|sha1hulud"
ls -la ~/.dev-env/ 2>/dev/null

# Check workflows
find . -path "*/.github/workflows/*" \
  \( -name "*hulud*" -o -name "discussion.yaml" \)

# Check package.json files
find . -name "package.json" -exec grep -l "preinstall\|postinstall" {} \;
```

**Full detection guide**: [Detection Indicators](docs/detection.md)

---

## High-Profile Victims

Major packages and organizations affected in the November 2025 wave:

### Zapier
- `@zapier/platform-core`
- `@zapier/platform-cli`
- `zapier-platform-*` packages

### ENS Domains
- `@ensdomains/*` packages
- `ensjs`, `ens-contracts`
- `react-ens-address`

### PostHog
- `posthog-node` (25% of environments)
- `@posthog/siphash`

### Postman
- `@postman/tunnel-agent` (27% of environments)

### AsyncAPI
- `@asyncapi/specs` (20% of environments)
- `@asyncapi/openapi-schema-parser` (17%)

**Full list**: [Compromised Packages](docs/compromised-packages.md)

---

## Key Resources

### Official Security Reports

- **Wiz Security**: [Shai1-Hulud 2.0 Analysis](https://www.wiz.io/blog/shai-hulud-2-0-ongoing-supply-chain-attack)
- **Palo Alto Unit 42**: [Initial Analysis](https://unit42.paloaltonetworks.com/npm-supply-chain-attack/)
- **ReversingLabs**: [First Detection](https://www.reversinglabs.com/blog/shai-hulud-worm-npm)
- **StepSecurity**: [The Second Coming](https://www.stepsecurity.io/blog/sha1-hulud-the-second-coming-zapier-ens-domains-and-other-prominent-npm-packages-compromised)

### Security Tools

- **Socket**: Malicious package detection - https://socket.dev
- **Snyk**: Dependency scanning - https://snyk.io
- **Docker Scout**: SBOM monitoring - https://docs.docker.com/scout/
- **Wiz**: Cloud security with IoC detection - https://www.wiz.io

### Government Response

- **CISA**: Urges dependency checks and system monitoring
- **GitHub/npm**: Removing compromised packages, enforcing 2FA
- **December 9, 2025**: npm classic token deprecation deadline

**Full resources**: [Resources & References](docs/resources.md)

---

## Repository Purpose

This repository is maintained for **educational and defensive security purposes only**. The content is designed to help:

- **Security professionals** understand the attack mechanics
- **DevOps teams** implement proper defenses
- **Developers** detect and respond to compromises
- **Organizations** protect their software supply chains

### What You'll Find Here

✅ **Comprehensive attack analysis** - Understand how Shai1-Hulud works
✅ **Detection methodologies** - Identify if you're compromised
✅ **Response procedures** - Step-by-step incident response
✅ **Protection strategies** - Prevent future attacks
✅ **Technical details** - Deep dive into malware mechanics
✅ **Security resources** - Tools, reports, and references

### What You Won't Find Here

❌ **Working malware code** - Only pseudo-code for educational purposes
❌ **Exploitation techniques** - Focus is purely defensive
❌ **Attack tutorials** - Content is for understanding and defense

---

## Contributing

This is a living document tracking an ongoing attack. Contributions are welcome:

### How to Contribute

1. **New Compromises**: Report via npm security (security@npmjs.com)
2. **Updated IoCs**: Submit pull request with sources
3. **Detection Methods**: Share new detection techniques
4. **Protection Strategies**: Document successful defenses
5. **Corrections**: Fix errors or outdated information

### Contribution Guidelines

- **Source all information**: Include links to authoritative sources
- **Focus on defense**: Maintain educational/defensive purpose
- **No working exploits**: Pseudo-code and high-level descriptions only
- **Keep it current**: Update with latest threat intelligence

---

## Disclaimer

**This repository is for informational and defensive purposes only.**

The technical details provided should be used exclusively for:
- Understanding the threat landscape
- Implementing security defenses
- Detecting compromises
- Incident response planning
- Security research and education

**Do not use this information for malicious purposes.**

---

## Stay Informed

### Monitor These Sources

- **GitHub Security Advisories**: https://github.com/advisories
- **npm Security**: https://docs.npmjs.com/policies/security
- **CISA Alerts**: https://www.cisa.gov/news-events/cybersecurity-advisories
- **Security vendor blogs**: Listed in [Resources](docs/resources.md)

### Update Frequency

This repository is updated as new information becomes available. Check back regularly for:
- New compromised packages
- Updated IoCs
- Additional protection strategies
- Latest security research

---

## Document Status

**Last Updated**: November 25, 2025
**Status**: Active Threat - Ongoing Attack
**Version**: 2.0 (covering both September and November 2025 waves)

---

## Quick Links

- **Report Compromise**: [Incident Response Guide](docs/response.md)
- **Check Your Systems**: [Detection Indicators](docs/detection.md)
- **Protect Your Environment**: [Protection Strategies](docs/protection.md)
- **Platform Defence**: [macOS](docs/macos-defence.md) | [Linux](docs/linux-defence.md) | [Windows](docs/windows-defence.md)
- **GitHub Actions Defence**: [Workflow Security](docs/github-actions-defence.md)
- **Understand the Attack**: [Attack Overview](docs/attack-overview.md)
- **Technical Deep Dive**: [Technical Details](docs/technical-details.md)
- **Affected Packages**: [Compromised Packages](docs/compromised-packages.md)
- **External Resources**: [Resources & References](docs/resources.md)

---

**🚨 If you believe you're compromised, start with the [Incident Response Guide](docs/response.md) immediately.**

**🛡️ To protect your systems, begin with the [Protection Strategies](docs/protection.md).**

**📚 For a complete understanding, read the [Attack Overview](docs/attack-overview.md).**
