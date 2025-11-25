# Windows Desktop Defense Strategy

High-level defensive strategies for Windows developer environments against supply chain attacks.

---

## Shai1-Hulud and Windows

**Important**: Shai1-Hulud explicitly skips Windows systems. The malware checks the platform and exits immediately on Windows.

**However**, this document remains critical because:
- Other supply chain attacks *do* target Windows
- The defensive principles apply to all npm-based threats
- Windows developers are not immune to credential theft
- Future variants may remove the Windows check

**Windows developers should implement these defenses proactively.**

---

## The Windows Desktop Security Gap

**Why Windows developer machines are vulnerable:**

- **Credential concentration**: GitHub tokens, AWS keys, npm tokens all on one machine
- **Minimal monitoring**: Developer workstations lack enterprise logging
- **Direct internet access**: No corporate firewall or egress filtering by default
- **Trust by default**: npm lifecycle scripts execute with user permissions
- **PowerShell everywhere**: Powerful scripting capabilities exploitable by attackers
- **Admin access common**: Many developers run with elevated privileges

---

## Defense Strategy: Four Layers

### Layer 1: Security Baseline & Auditing

**Goal**: Understand your current security posture and identify vulnerabilities.

**Capabilities Needed**:
- **Host enumeration**: What's running on your system?
- **Security configuration audit**: Are there weak settings?
- **Credential discovery**: Where are secrets stored?
- **Privilege assessment**: What permissions do processes have?
- **Registry inspection**: Are there persistence mechanisms?

**Example Tool Categories**:
- Security auditing frameworks (Windows security scanners)
- Configuration compliance tools
- Security baseline analyzers

**What to Look For**:
- Credentials in environment variables (System Properties → Environment Variables)
- Overly permissive file permissions on credential directories
- Suspicious scheduled tasks
- Unsigned binaries in startup locations (Task Manager → Startup)
- Unusual Windows services
- PowerShell execution policies (too permissive)

**Defense Value**: Baseline awareness enables anomaly detection.

---

### Layer 2: Network Egress Control

**Goal**: Control what processes can communicate with the internet, blocking exfiltration.

**The Problem**: By default, applications have unrestricted outbound access. Supply chain attacks exploit this to:
- Create GitHub repositories
- Upload stolen credentials
- Download additional payloads
- Communicate with command & control servers

**Capabilities Needed**:
- **Per-application firewall**: Different rules for different applications
- **Outbound connection blocking**: Deny by default, allow explicitly
- **Domain-based filtering**: Block by hostname
- **First connection alerts**: Know when new apps go online
- **Connection logging**: Audit trail of all outbound connections

**Example Tool Categories**:
- Windows Defender Firewall (built-in, enhanced configuration)
- Third-party firewalls (GlassWire, TinyWall, Comodo)
- DNS-based filtering (Pi-hole, AdGuard Home, NextDNS)
- Enterprise proxy servers with allowlists

**Defensive Posture**:

**Permissive (Current State)**:
- All outbound connections allowed
- Attacker can exfiltrate freely

**Restrictive (Recommended)**:
- Deny outbound by default
- Explicitly allow: `npm.exe` → `registry.npmjs.org`, `git.exe` → `github.com`
- Block: webhook sites, paste services, unknown destinations
- Alert: Any new process attempting network access

**Windows-Specific Considerations**:
- Windows Firewall supports outbound rules (often disabled by default)
- Use Windows Firewall with Advanced Security (wf.msc)
- Consider application reputation systems
- PowerShell scripts can bypass simple process-name rules

**Defense Value**: Prevent data exfiltration even if malware executes.

---

### Layer 3: Execution Monitoring

**Goal**: Detect suspicious code execution, especially from package managers.

**The Problem**: npm lifecycle scripts run with full user privileges. Even though Shai1-Hulud skips Windows, other malware uses the same technique.

**Capabilities Needed**:
- **Process monitoring**: What's currently running?
- **Parent-child process tracking**: What spawned what?
- **Command-line inspection**: Full command with arguments
- **PowerShell logging**: Script block logging and transcription
- **Execution pattern detection**: Behavioral anomalies
- **File access monitoring**: What files is the process touching?

**Example Tool Categories**:
- Process monitoring (Process Monitor, Process Explorer)
- EDR (Endpoint Detection and Response) systems
- SIEM integration for centralized logging
- PowerShell logging and monitoring

**What to Monitor**:
- `node.exe` processes spawned by `npm install`
- Processes accessing credential files (`.aws\credentials`, `.npmrc`)
- PowerShell executions from npm context
- Processes making GitHub API calls
- Child processes that outlive npm install
- Unusual network connections from node.exe

**Windows-Specific Indicators**:
- PowerShell `-EncodedCommand` (base64 obfuscation)
- PowerShell download commands (`Invoke-WebRequest`, `WebClient`)
- Processes accessing Windows Credential Manager
- Registry modifications (persistence mechanisms)
- Scheduled task creation

**Defensive Actions**:
- Enable PowerShell script block logging
- Alert on npm spawning PowerShell
- Require approval for lifecycle scripts
- Log all npm install operations
- Monitor Windows Event Logs for suspicious activity

**Defense Value**: Catch attacks during execution, before damage occurs.

---

### Layer 4: File System Monitoring

**Goal**: Detect when attacker creates persistence or staging areas.

**The Problem**: Supply chain attacks create:
- Malicious workflow files (`.github\workflows\`)
- Self-hosted runner installations
- Exfiltration data files
- Registry keys for persistence
- Scheduled tasks

**Capabilities Needed**:
- **Real-time file creation alerts**: Immediate notification
- **Directory watching**: Monitor sensitive paths
- **Pattern matching**: Detect known-malicious filenames
- **Workflow file inspection**: Alert on new GitHub Actions workflows
- **Registry monitoring**: Detect persistence mechanisms
- **Scheduled task monitoring**: New task creation alerts

**Example Tool Categories**:
- File system monitoring (FSMON, Process Monitor)
- File integrity monitoring (AIDE, Tripwire equivalents)
- Windows audit policies
- SIEM with file monitoring

**Critical Paths to Monitor**:
- `.github\workflows\` - New workflow files
- User profile directory - Suspicious files
- `%USERPROFILE%\.aws\` - Credential modifications
- `%USERPROFILE%\.npmrc` - Configuration tampering
- `%APPDATA%` and `%LOCALAPPDATA%` - Malware installation
- Scheduled Tasks folder - Persistence

**Windows-Specific Locations**:
- Registry Run keys: `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`
- Startup folder: `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup`
- Windows services
- WMI event subscriptions (advanced persistence)

**Defensive Actions**:
- Alert on new files in `.github\workflows\`
- Block creation of known-bad filenames
- Monitor registry for new Run keys
- Audit scheduled task creation
- Maintain checksums of credential files

**Defense Value**: Detect persistence before it's used for long-term access.

---

## Credential Isolation Strategy

**Goal**: Malware cannot access credentials even if it executes.

**Windows-Specific Credential Locations**:
- Environment variables (User and System)
- Windows Credential Manager (`Control Panel → Credential Manager`)
- Files: `.aws\credentials`, `.npmrc`, `.gitconfig`
- Registry: Some apps store credentials in registry
- PowerShell history: `%USERPROFILE%\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt`

**Zero Trust Credential Model**:

### 1. Never Store Long-Lived Credentials
- No tokens in environment variables
- No API keys in files
- Use Windows Credential Manager properly (encrypted, requires login)

### 2. Short-Lived, Scoped Access
- Generate tokens for single operations (1 hour)
- Minimal scope permissions
- Different tokens for different purposes

### 3. Just-In-Time Credential Injection
- Credential manager injects only when needed
- Secrets never persist to disk
- Process uses credential and forgets it

**Example Tool Categories**:
- Credential managers (1Password CLI, AWS Vault for Windows)
- Windows Credential Manager (built-in, proper usage)
- SSO systems (AWS SSO, GitHub SSO)
- Secret injection tools

**Windows-Specific Recommendations**:
- Use Windows Hello for biometric authentication to credential manager
- Enable BitLocker for disk encryption
- Use Windows Sandbox for testing untrusted packages
- Consider WSL2 with separate credential storage

**Defense Value**: Malware can't steal what isn't accessible.

---

## Continuous Validation

**Goal**: Continuously verify defenses are working.

**Checks to Automate**:

**Daily** (PowerShell script or scheduled task):
- Check for malicious GitHub repositories
- Scan for self-hosted runners
- Look for suspicious files
- Verify Windows Firewall is active
- Check for new scheduled tasks
- Review registry Run keys

**Weekly**:
- Run security baseline audit
- Review firewall logs
- Check Windows Event Logs for anomalies
- Audit GitHub workflow files
- Review PowerShell logs

**Monthly**:
- Rotate all credentials
- Update security tools
- Review process monitoring logs
- Test incident response procedures

**Windows-Specific Checks**:
- Windows Defender status and signature updates
- Windows Update status
- BitLocker status
- User Account Control (UAC) settings
- PowerShell execution policy

**Defense Value**: Maintain security posture over time.

---

## Defense Priorities

### Immediate (Do Today)
1. **Remove credentials from environment variables**
2. **Enable npm lifecycle script warnings/blocking**
3. **Configure Windows Firewall outbound rules**
4. **Enable PowerShell logging**
5. **Run Windows Defender full scan**

### Short-Term (This Week)
1. **Set up credential manager**
2. **Configure firewall deny-by-default**
3. **Set up file monitoring on critical directories**
4. **Enable Windows audit policies**
5. **Create daily security check script**

### Long-Term (This Month)
1. **Deploy EDR solution**
2. **Implement token rotation**
3. **Set up centralized logging**
4. **Enable BitLocker**
5. **Document incident response procedures**

---

## Windows-Specific Defenses

### PowerShell Hardening
- Enable Constrained Language Mode when possible
- Use PowerShell script block logging
- Enable transcription logging
- Set execution policy to `RemoteSigned` or stricter
- Audit PowerShell module installations

### Windows Defender
- Keep signatures up to date
- Enable cloud-delivered protection
- Enable tamper protection
- Enable controlled folder access (ransomware protection)
- Review protection history regularly

### User Account Control (UAC)
- Keep UAC enabled at highest setting
- Don't run PowerShell or cmd as administrator by default
- Use separate admin account for administrative tasks

### Windows Sandbox
- Test unknown packages in Windows Sandbox first
- Sandbox is a temporary environment, destroyed on close
- No persistence, safe for testing

---

## Measuring Effectiveness

**Can your defenses answer these questions?**

- ✅ Would you know if a GitHub repository was created?
- ✅ Would you detect self-hosted runner installation?
- ✅ Can malware reach webhook.site or pastebin.com?
- ✅ Would you notice new `.github\workflows\` files?
- ✅ Can processes freely read `.aws\credentials`?
- ✅ Do you have audit trail of npm installations?
- ✅ Would you detect new scheduled tasks?
- ✅ Are PowerShell executions logged?

**If you answered "no" to any of these, you have a gap.**

---

## Key Principles

1. **Defense in Depth**: Layer multiple controls
2. **Deny by Default**: Start restrictive, allow explicitly
3. **Assume Breach**: Plan for malware execution
4. **Visibility is Security**: You can't defend what you can't see
5. **Continuous Validation**: Re-check constantly
6. **Credential Isolation**: Protect credentials separately
7. **Least Privilege**: Don't run as admin by default

---

## Next Steps

1. **Audit**: Run security baseline scan
2. **Control**: Configure Windows Firewall for egress filtering
3. **Monitor**: Enable PowerShell logging and file monitoring
4. **Isolate**: Move credentials to secure manager
5. **Validate**: Create automated daily checks
6. **Iterate**: Refine based on findings

---

**See also:**
- [macOS Defence](macos-defence.md) - macOS-specific strategies
- [Linux Defence](linux-defence.md) - Linux-specific strategies
- [Protection Strategies](protection.md) - General security strategies
- [Detection Indicators](detection.md) - How to detect compromises
- [Response Guide](response.md) - Incident response procedures
