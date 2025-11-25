# macOS Desktop Defense Strategy

High-level defensive strategies for macOS developer environments against Shai1-Hulud and similar supply chain attacks.

---

## The Desktop Security Gap

**Why macOS developer machines are prime targets:**

- **Credential concentration**: GitHub tokens, AWS keys, npm tokens, GCP credentials all on one machine
- **Minimal monitoring**: Unlike production servers, developer desktops rarely have logging or alerting
- **Direct internet access**: No corporate firewall, no egress filtering, no network segmentation
- **Trust by default**: npm lifecycle scripts execute with full user permissions
- **Persistent access**: Machines stay on 24/7, perfect for long-running attacks
- **High privilege**: Developers typically have sudo/admin access for their work

**Shai1-Hulud specifically targets macOS and Linux**, explicitly skipping Windows systems.

---

## Defense Strategy: Four Layers

### Layer 1: Security Baseline & Auditing

**Goal**: Understand your current security posture and identify vulnerabilities before an attacker does.

**Capabilities Needed**:
- **Host enumeration**: What's running on your system?
- **Security configuration audit**: Are there weak settings?
- **Credential discovery**: Where are secrets stored?
- **Privilege assessment**: What can processes do?
- **File permission review**: Are sensitive files readable by all?

**Example Tool Categories**:
- Security auditing frameworks (like Lynis, macOS Seatbelt-style tools)
- System inspection utilities
- Configuration analyzers

**What to Look For**:
- Credentials in environment variables
- Overly permissive file permissions on `.aws/`, `.npmrc`, etc.
- Suspicious LaunchAgents or LaunchDaemons
- Unsigned or unknown binaries running at startup
- Unusual network listeners

**Defense Value**: Knowing your baseline makes anomalies obvious.

---

### Layer 2: Network Egress Control

**Goal**: Control what processes can communicate with the internet, blocking data exfiltration paths.

**The Problem**: By default, any process can connect anywhere. Shai1-Hulud exploits this by:
- Creating GitHub repositories (api.github.com)
- Uploading stolen credentials (github.com)
- Scanning for other victims (api.github.com search)
- Potentially using webhook sites or paste services

**Capabilities Needed**:
- **Per-application firewall**: Different rules for different apps
- **Outbound connection blocking**: Deny by default, allow explicitly
- **Domain-based filtering**: Block by hostname, not just IP
- **Alert on first connection**: Know when new processes try to phone home
- **Connection logging**: Audit trail of all outbound connections

**Example Tool Categories**:
- Application-layer firewalls (Little Snitch, LuLu)
- DNS-based filtering (Pi-hole, AdGuard Home)
- Corporate proxy with allowlists

**Defensive Posture**:

**Permissive (Current State for Most)**:
- Everything allowed by default
- Attacker can exfiltrate freely

**Restrictive (Recommended)**:
- Deny by default
- Explicitly allow: `npm` → `registry.npmjs.org`, `git` → `github.com`
- Block: webhook sites, paste services, unknown destinations
- Alert: Any new process attempting network access

**Defense Value**: Even if malware executes, it cannot exfiltrate data or propagate.

---

### Layer 3: Execution Monitoring

**Goal**: Detect when suspicious code is running, especially from package managers.

**The Problem**: npm lifecycle scripts run with full user privileges. Shai1-Hulud exploits `preinstall` scripts that execute before you even see the package contents.

**Capabilities Needed**:
- **Process monitoring**: What's running right now?
- **Parent-child process tracking**: Did npm spawn something unusual?
- **Command-line inspection**: What arguments were used?
- **Execution pattern detection**: Does this look like credential harvesting?
- **Behavioral analysis**: Is this process accessing credential files?

**Example Tool Categories**:
- Process monitoring tools (osquery, Activity Monitor API)
- Execution policies
- EDR (Endpoint Detection and Response) systems

**What to Monitor**:
- `node` processes spawned by `npm install`
- Processes accessing `~/.aws/credentials`, `~/.npmrc`, `~/.gitconfig`
- Processes reading large numbers of files (scanning behavior)
- Processes making unexpected GitHub API calls
- Background processes that persist after package install completes

**Defensive Actions**:
- Alert when npm spawns unexpected child processes
- Block execution of scripts from `node_modules` by default
- Require user approval for lifecycle scripts
- Log all npm install executions for audit

**Defense Value**: Catch attacks at execution time, before damage is done.

---

### Layer 4: File System Monitoring

**Goal**: Detect when attacker creates persistence mechanisms or exfiltration staging areas.

**The Problem**: Shai1-Hulud creates:
- Malicious workflow files (`.github/workflows/discussion.yaml`)
- Self-hosted runner installations (`~/.dev-env/`)
- Exfiltration data files (`cloud.json`, `contents.json`)
- Credential scanning tool installations

**Capabilities Needed**:
- **Real-time file creation alerts**: Know immediately when files appear
- **Directory watching**: Monitor sensitive paths for changes
- **Pattern matching**: Detect known-malicious filenames
- **Workflow file inspection**: Alert on new GitHub Actions workflows
- **Integrity monitoring**: Has `.npmrc` or `.gitconfig` been modified?

**Example Tool Categories**:
- File system monitoring (fswatch, macOS FSEvents API)
- File integrity monitoring (AIDE, Tripwire-style tools)
- Audit subsystems (macOS OpenBSM/audit)

**Critical Paths to Monitor**:
- `~/.github/workflows/` - New workflow files
- `~/.dev-env/` - Self-hosted runner location
- `~/` - Root directory for `setup_bun.js`, `bun_environment.js`
- `~/.aws/`, `~/.config/gcloud/` - Credential file modifications
- `~/.npmrc`, `~/.gitconfig` - Configuration tampering

**Defensive Actions**:
- Alert on any new file in `.github/workflows/`
- Block creation of files matching known-bad patterns
- Require approval before modifying credential files
- Maintain checksums of configuration files

**Defense Value**: Detect persistence mechanisms and staging areas before they're used.

---

## Credential Isolation Strategy

**Goal**: Even if malware executes, it cannot access credentials.

**Current Problem**: Credentials everywhere:
- Environment variables (`GITHUB_TOKEN`, `AWS_ACCESS_KEY_ID`)
- Config files (`~/.aws/credentials`, `~/.npmrc`)
- Shell history (accidental `export` commands)
- Process memory (easy to dump)

**Zero Trust Credential Model**:

### 1. Never Store Long-Lived Credentials
- No tokens in environment variables
- No API keys in config files
- Use credential managers that require authentication

### 2. Short-Lived, Scoped Access
- Generate tokens for single operations (1 hour expiration)
- Minimal scope (read-only when possible)
- Different tokens for different purposes

### 3. Just-In-Time Credential Injection
- Credential manager injects secrets only when needed
- Secrets never touch disk or environment
- Process receives credential, uses it, forgets it

**Example Tool Categories**:
- Credential managers (1Password CLI, AWS Vault)
- SSO systems (AWS SSO, GitHub SSO)
- Secret injection tools

**Defense Value**: Malware can't steal what isn't there.

---

## Continuous Validation

**Goal**: Don't just set up defenses once—continuously verify they're working.

**Capabilities Needed**:
- Periodic security scans (daily/weekly)
- Automated checks for compromise indicators
- Configuration drift detection
- Credential leak scanning

**Checks to Automate**:

**Daily**:
- Check for malicious GitHub repositories in your account
- Scan for self-hosted runners
- Look for suspicious files (`setup_bun.js`, etc.)
- Verify firewall is active and configured correctly

**Weekly**:
- Run full security audit (baseline tool)
- Review firewall logs for blocked connections
- Check for new LaunchAgents/LaunchDaemons
- Audit GitHub workflow files

**Monthly**:
- Rotate all tokens and credentials
- Review osquery logs for unusual patterns
- Update security tools
- Test incident response procedures

**Defense Value**: Catch drift, detect slow-moving attacks, maintain security posture.

---

## Defense Priorities

### Immediate (Do Today)
1. **Remove credentials from environment variables**
2. **Enable npm lifecycle script warnings or blocking**
3. **Install application firewall with egress control**
4. **Run initial security baseline audit**

### Short-Term (This Week)
1. **Set up credential manager for GitHub/AWS/npm tokens**
2. **Configure egress firewall rules (deny by default)**
3. **Set up file monitoring on critical directories**
4. **Create automated daily security check script**

### Long-Term (This Month)
1. **Deploy process monitoring with alerting**
2. **Implement short-lived token rotation**
3. **Set up centralized logging**
4. **Establish incident response procedures**

---

## Measuring Effectiveness

**Can your defenses answer these questions?**

- ✅ Would you know if a GitHub repository was created in your account?
- ✅ Would you detect if npm installed a self-hosted runner?
- ✅ Can malware on your Mac reach webhook.site or pastebin.com?
- ✅ Would you notice if `.github/workflows/discussion.yaml` appeared?
- ✅ Can processes freely read `~/.aws/credentials` without your knowledge?
- ✅ Do you have an audit trail of what npm packages were installed?
- ✅ Would you detect if your GitHub token was used from a new location?

**If you answered "no" to any of these, you have a gap to address.**

---

## Key Principles

1. **Defense in Depth**: No single control is sufficient. Layer multiple defenses.

2. **Deny by Default**: Start restrictive, explicitly allow what's needed.

3. **Assume Breach**: Plan for malware execution. Can it exfiltrate? Can it persist?

4. **Visibility is Security**: You can't defend what you can't see.

5. **Continuous Validation**: Security posture degrades over time. Re-check constantly.

6. **Credential Isolation**: Most valuable data is credentials. Protect them separately.

7. **Developer Ergonomics**: Security that's too painful gets disabled. Balance security with usability.

---

## Next Steps

1. **Audit**: Use security baseline tool to understand current state
2. **Control**: Implement egress filtering to block exfiltration
3. **Monitor**: Add visibility with process and file monitoring
4. **Isolate**: Move credentials to manager, out of environment
5. **Validate**: Run automated checks to verify defenses work
6. **Iterate**: Refine based on what you learn

---

**See also:**
- [Protection Strategies](protection.md) - General security strategies
- [Detection Indicators](detection.md) - How to detect compromises
- [Response Guide](response.md) - Incident response procedures
- [Attack Overview](attack-overview.md) - Understanding the threat
