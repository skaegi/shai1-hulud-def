# Shai1-Hulud Attack Overview

## What is Shai1-Hulud?

Shai1-Hulud is a sophisticated, self-replicating worm targeting the npm ecosystem. Named after the giant sandworms from Frank Herbert's "Dune," this malware represents one of the most severe JavaScript supply chain attacks observed to date.

## Attack Timeline

### First Wave: September 14-16, 2025
- **500+ packages** compromised
- First detected by ReversingLabs on September 15, 2025
- **Patient Zero**: `rxnt-authentication@0.0.3` (published September 14, 2025 at 17:58:50 UTC)

### Second Wave: "The Second Coming" - November 21-24, 2025 ⚠️ **ACTIVE NOW**
- **800+ packages** compromised
- **25,000+ GitHub repositories** affected
- **1,000 new repositories** compromised every 30 minutes at peak
- **Major victims**: Zapier, ENS Domains, PostHog, Postman, AsyncAPI

### Critical Deadline

**December 9, 2025**: npm will revoke all classic tokens. The second wave appears timed to exploit these tokens before they expire.

---

## How the Attack Works

### Attack Vector

1. **Initial Compromise**: Developer credentials stolen via phishing or previous compromises
2. **Code Injection**: Malicious code injected into npm packages via compromised maintainer accounts
3. **Execution**: Malware runs during `preinstall` lifecycle (v2.0) or `postinstall` (v1.0)
4. **Propagation**: Self-replicates by publishing infected versions of other packages the maintainer controls

### Key Capabilities

#### 1. Credential Harvesting

The malware systematically harvests credentials from multiple sources:

- **GitHub**: Personal Access Tokens (PAT) and OAuth tokens
- **npm**: Authentication tokens from `.npmrc` files and environment variables
- **AWS**: Credentials from 17 regions, environment variables, config files
- **GCP**: Application Default Credentials and Secret Manager access
- **Azure**: Key Vault via DefaultAzureCredential
- **Environment variables**: All environment variables captured
- **Deep scanning**: Uses TruffleHog tool for comprehensive secret scanning

#### 2. Novel "Token Recycling" Technique

One of the most concerning innovations in this attack:

- Searches GitHub for repositories with **"Sha1-Hulud: The Second Coming"** in the description
- Downloads victim data from other compromised accounts
- **Reuses stolen tokens** from other victims to maintain persistence
- Allows the malware to continue operating even after initial tokens are revoked

#### 3. Data Exfiltration

Sophisticated multi-stage exfiltration:

- Creates **public GitHub repositories** with random 18-character names
- Repository description: **"Sha1-Hulud: The Second Coming"**
- Uploads **double base64-encoded** JSON files:
  - `environment.json` - environment variables
  - `cloud.json` - AWS/GCP/Azure credentials
  - `contents.json` - GitHub and npm tokens
  - `truffleSecrets.json` - TruffleHog scan results

#### 4. Persistent Backdoor (Version 2.0)

Creates a long-term access mechanism:

- Installs **GitHub Actions self-hosted runner** named **"SHA1HULUD"**
- Creates workflow `.github/workflows/discussion.yaml` with injection vulnerability
- Allows **remote command execution** by creating GitHub Discussions
- **Survives system reboots**
- Provides persistent access even after credentials are rotated

#### 5. Self-Replication (Worm Behavior)

Exponential spread without attacker intervention:

- Automatically identifies other packages maintained by compromised accounts
- Injects malicious code and publishes new versions
- Can infect **up to 100 packages per token** (increased from 20 in v1.0)
- Creates exponential spread across the npm ecosystem

#### 6. Destructive Capability (Version 2.0)

If credential theft/exfiltration fails, the malware attempts to:

- Delete entire home directory (`rm -rf ~/*`)
- Delete all writable files owned by the user
- **Escalate privileges via Docker** to gain root access
- Install malicious sudoers file for passwordless root access
- Wipe system files if possible

### Target Platforms

- **Targeted**: Linux, macOS
- **Skipped**: Windows (malware explicitly checks and exits on Windows)

---

## Attack Statistics

### Impact Metrics (November 2025 Wave)

- **800+** npm packages compromised
- **25,000+** GitHub repositories affected
- **~500** unique GitHub user accounts compromised
- **132 million** monthly downloads for compromised packages
- **27%** of cloud/code environments contain affected packages (@postman/tunnel-agent)
- **1,000** new repositories created every 30 minutes at peak

### Timeline Metrics

- **72 hours** from start to 25,000 repos compromised
- **3 days** attack window (November 21-23, 2025)
- **First detection**: November 24, 2025 at 3:16:26 AM GMT

### Credential Exposure

- **278+** secrets publicly leaked (first wave)
- **90** collected from local machines
- **188** compromised through malicious workflows
- **5,000+** files uploaded to GitHub with compromised credentials (second wave)

---

## Key Takeaways

1. **This is an active, ongoing threat** - the November 2025 wave is still unfolding
2. **Self-replicating worms are the new normal** in supply chain attacks
3. **Token recycling** is a novel technique that extends attack lifetime
4. **Persistent backdoors** via GitHub Actions runners are extremely dangerous
5. **Destructive capabilities** represent escalation from pure data theft
6. **Desktop developer environments are blind spots** for traditional security tools
7. **Classic npm tokens must be removed** before December 9, 2025
8. **Assume compromise** if you installed npm packages November 21-25, 2025

---

## Related Attacks

The Shai1-Hulud attacks are part of a broader pattern of npm ecosystem compromises:

- **S1ngularity/Nx Attack** (August 2025): Credential theft, private repo exposure
- **Qix Compromise** (2025): 18 packages with 2 billion weekly downloads
- **XZ Utils Compromise** (2024): Supply chain compromise of critical Linux utility
- **Various cryptojacking campaigns** throughout 2024-2025

---

**See also:**
- [Detection Indicators](detection.md) - How to detect if you're compromised
- [Response Guide](response.md) - What to do if you're affected
- [Protection Strategies](protection.md) - How to protect your systems
- [Technical Details](technical-details.md) - Deep dive into attack mechanics
