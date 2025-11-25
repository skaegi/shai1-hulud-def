# Linux Desktop Defense Strategy

High-level defensive strategies for Linux developer environments against Shai1-Hulud and similar supply chain attacks.

---

## Linux and Shai1-Hulud

**Critical**: Shai1-Hulud specifically targets Linux systems. Along with macOS, Linux is a primary target for this attack.

**Why Linux is targeted:**
- Dominant in cloud/server development environments
- CI/CD pipelines often run on Linux
- Developer containers and WSL2 environments
- Rich credential access (AWS, GCP, GitHub, npm)
- Powerful shell environment for credential harvesting

**Linux developers must implement comprehensive defenses.**

---

## The Linux Desktop Security Gap

**Why Linux developer machines are vulnerable:**

- **Credential concentration**: GitHub tokens, AWS keys, npm tokens, GCP credentials
- **Root access common**: Developers often use sudo freely
- **Minimal monitoring**: Desktop Linux rarely has enterprise logging
- **Direct internet access**: No firewall or egress filtering by default
- **Trust by default**: npm lifecycle scripts execute without scrutiny
- **Shell power**: Bash, Python, Ruby—ideal for credential harvesting
- **False security assumption**: "Linux is secure" doesn't mean "this Linux is secure"

---

## Defense Strategy: Four Layers

### Layer 1: Security Baseline & Auditing

**Goal**: Understand your security posture before an attacker does.

**Capabilities Needed**:
- **Host enumeration**: What's running on your system?
- **Security configuration audit**: Weak settings identification
- **Credential discovery**: Where secrets are stored
- **Privilege assessment**: sudo permissions, capabilities
- **File permission review**: World-readable credential files
- **Service enumeration**: What's listening on network ports

**Example Tool Categories**:
- Security auditing frameworks (Lynis, OpenSCAP, AIDE)
- Configuration compliance scanners
- Vulnerability scanners (Nessus, OpenVAS)

**What to Look For**:
- Credentials in environment variables (`env | grep -i token`)
- World-readable files in `~/.aws/`, `~/.config/gcloud/`
- Suspicious systemd services or timers
- Cron jobs you didn't create
- Setuid binaries in unexpected locations
- SSH keys without passphrases
- Open network services (`netstat -tulpn`)

**Linux-Specific Checks**:
- Check `/etc/sudoers` and `/etc/sudoers.d/` for unauthorized entries
- Review systemd user services (`systemctl --user list-units`)
- Inspect PAM configuration for backdoors
- Check for unauthorized SSH authorized_keys entries

**Defense Value**: Baseline awareness is prerequisite for anomaly detection.

---

### Layer 2: Network Egress Control

**Goal**: Control what processes can communicate externally, blocking exfiltration.

**The Problem**: By default, any process has unrestricted outbound access. Shai1-Hulud exploits this to:
- Create GitHub repositories (api.github.com:443)
- Upload stolen credentials (github.com:443)
- Download TruffleHog scanner
- Search for other victims via GitHub API
- Potentially use webhook/paste sites

**Capabilities Needed**:
- **Per-application firewall**: Different rules per application
- **Outbound connection filtering**: Deny by default
- **Domain-based filtering**: Filter by hostname, not just IP
- **Connection logging**: Audit all outbound connections
- **Alert on anomalies**: New processes going online
- **Process-based rules**: Restrict by full path and hash

**Example Tool Categories**:
- iptables/nftables (kernel packet filtering)
- ufw/firewalld (simplified firewall frontends)
- Application-aware firewalls (OpenSnitch)
- SELinux/AppArmor (mandatory access control)
- DNS-based filtering (Pi-hole, AdGuard Home, /etc/hosts)

**Defensive Posture**:

**Permissive (Current State)**:
- All outbound allowed by default
- Attacker exfiltrates freely

**Restrictive (Recommended)**:
- Deny outbound by default
- Explicitly allow: `npm` → `registry.npmjs.org:443`, `git` → `github.com:443,22`
- Block: webhook.site, pastebin.com, paste services
- Alert: Any new process attempting external connections

**Linux-Specific Considerations**:
- iptables OUTPUT chain (default ACCEPT → DROP is dangerous, plan carefully)
- User-space firewalls (OpenSnitch) offer better per-app control
- cgroups can limit network access for process groups
- Network namespaces for isolation (containers, firejail)

**Defense Value**: Even if malware executes, it cannot exfiltrate or propagate.

---

### Layer 3: Execution Monitoring

**Goal**: Detect suspicious code execution, especially from package managers.

**The Problem**: npm lifecycle scripts execute with full user permissions. Shai1-Hulud uses `preinstall` scripts that run before you even see package contents.

**Capabilities Needed**:
- **Process monitoring**: What's running, with full command lines
- **Parent-child tracking**: Process tree analysis
- **Syscall monitoring**: What system calls are processes making
- **File access monitoring**: Which files are being read
- **Network activity tracking**: What connections are established
- **Behavioral analysis**: Does this look like credential harvesting?

**Example Tool Categories**:
- Process monitoring (osquery, auditd, sysdig)
- System call tracing (strace, perf)
- Behavioral monitoring (Falco, OSSEC)
- EDR (Endpoint Detection and Response) solutions

**What to Monitor**:
- `node` processes spawned by `npm install`
- Processes accessing `~/.aws/credentials`, `~/.npmrc`, `~/.ssh/`
- Processes reading large numbers of files (scanning behavior)
- Processes making GitHub API calls
- Background processes persisting after npm completes
- Unusual bash/python/ruby executions from npm context

**Linux-Specific Indicators**:
- `curl` or `wget` downloads from npm scripts
- Base64 encoding/decoding (obfuscation)
- Modification of `~/.bashrc`, `~/.profile` (persistence)
- systemd service/timer creation
- Cron job additions
- Docker socket access (`/var/run/docker.sock`) for privilege escalation

**Defensive Actions**:
- Use auditd to log file access to credential directories
- Alert on npm spawning curl/wget/python/bash
- Require approval for all lifecycle scripts
- Log npm install operations with full environment
- Monitor for Docker privilege escalation attempts

**Defense Value**: Catch attacks at execution, before credential theft completes.

---

### Layer 4: File System Monitoring

**Goal**: Detect when attacker creates persistence or exfiltration staging.

**The Problem**: Shai1-Hulud creates:
- Malicious workflows (`.github/workflows/discussion.yaml`)
- Self-hosted runner installations (`~/.dev-env/`)
- Exfiltration data files (`cloud.json`, `contents.json`)
- TruffleHog scanner downloads
- sudoers backdoors (`/etc/sudoers.d/malicious`)

**Capabilities Needed**:
- **Real-time file monitoring**: Immediate alerts on file creation
- **Directory watching**: Monitor sensitive paths
- **Pattern matching**: Detect known-malicious filenames
- **Integrity monitoring**: Checksums of critical files
- **Permission change detection**: Detect chmod on sensitive files
- **Inode monitoring**: Detect file replacements

**Example Tool Categories**:
- File monitoring (inotify-tools, fswatch, auditd)
- File integrity (AIDE, Tripwire, Samhain)
- Audit subsystems (auditd with rules)
- Security scanning (rkhunter, chkrootkit)

**Critical Paths to Monitor**:
- `~/.github/workflows/` - New workflow files
- `~/.dev-env/` - Self-hosted runner location
- `~/` - For `setup_bun.js`, `bun_environment.js`
- `~/.aws/`, `~/.config/gcloud/` - Credential modifications
- `~/.npmrc`, `~/.gitconfig` - Configuration tampering
- `~/.ssh/` - SSH key tampering
- `~/.bashrc`, `~/.profile` - Shell persistence
- `/etc/sudoers.d/` - Privilege escalation

**Linux-Specific Locations**:
- systemd user services: `~/.config/systemd/user/`
- Cron: `~/.crontab`, `/var/spool/cron/`
- XDG autostart: `~/.config/autostart/`
- Docker socket access indicators

**Defensive Actions**:
- Use auditd to watch critical directories
- Alert on any file in `.github/workflows/`
- Block creation of files matching `setup_bun.js` pattern
- Monitor `/etc/sudoers.d/` for new files (requires root)
- Maintain checksums of credential files
- Alert on modifications to shell rc files

**Defense Value**: Detect persistence mechanisms before they provide long-term access.

---

## Credential Isolation Strategy

**Goal**: Malware cannot access credentials even if it executes.

**Linux-Specific Credential Locations**:
- Environment variables (`env`, `/proc/*/environ`)
- Files: `~/.aws/credentials`, `~/.npmrc`, `~/.gitconfig`, `~/.netrc`
- GCP: `~/.config/gcloud/application_default_credentials.json`
- Shell history: `~/.bash_history`, `~/.zsh_history`
- Process memory (can be dumped with `/proc/*/mem`)
- systemd environment files

**Zero Trust Credential Model**:

### 1. Never Store Long-Lived Credentials
- No tokens in environment variables
- No API keys in files with lax permissions
- Use encrypted storage requiring authentication

### 2. Short-Lived, Scoped Access
- Generate tokens for single operations (1 hour expiration)
- Minimal scope (read-only where possible)
- Separate tokens for separate purposes

### 3. Just-In-Time Credential Injection
- Credential manager injects only when needed
- Secrets never persist to filesystem
- Process uses credential and immediately discards

**Example Tool Categories**:
- Credential managers (pass, gopass, 1Password CLI)
- Vault systems (HashiCorp Vault)
- SSO (AWS SSO, gcloud auth)
- Secret injection (aws-vault, AWS Session Manager)

**Linux-Specific Recommendations**:
- Use encrypted home directory or LUKS
- Restrict file permissions (`chmod 600 ~/.aws/credentials`)
- Use Linux keyrings (gnome-keyring, KDE Wallet)
- Consider SELinux contexts for credential files
- Use namespaces to isolate credential access
- Audit file access with auditd

**Defense Value**: Credentials that don't exist can't be stolen.

---

## Continuous Validation

**Goal**: Continuously verify defenses are working.

**Checks to Automate** (via cron or systemd timer):

**Daily**:
- Check for malicious GitHub repositories
- Scan for self-hosted runners (process list)
- Look for suspicious files (`find` for setup_bun.js)
- Verify firewall is active (`iptables -L`)
- Check for new systemd services
- Review auditd logs for anomalies

**Weekly**:
- Run full security audit (Lynis)
- Review firewall logs
- Check for new cron jobs
- Audit `.github/workflows/` across all repos
- Review SSH authorized_keys
- Check `/etc/sudoers.d/` for modifications

**Monthly**:
- Rotate all credentials
- Update security tools (`apt update && apt upgrade`)
- Review auditd logs comprehensively
- Test incident response procedures
- Scan for rootkits (rkhunter, chkrootkit)

**Linux-Specific Checks**:
- Check integrity of package manager database
- Review systemd journal for anomalies (`journalctl`)
- Verify SELinux/AppArmor is enforcing (if used)
- Check for unusual kernel modules (`lsmod`)
- Review iptables rules for changes

**Defense Value**: Maintain security posture, catch slow-moving attacks.

---

## Defense Priorities

### Immediate (Do Today)
1. **Remove credentials from environment variables**
2. **Set `ignore-scripts=true` in .npmrc**
3. **Configure firewall with egress rules**
4. **Enable auditd for credential directory monitoring**
5. **Check file permissions on `~/.aws/`, `~/.npmrc`**

### Short-Term (This Week)
1. **Set up credential manager (pass, aws-vault)**
2. **Configure firewall deny-by-default**
3. **Enable comprehensive auditd rules**
4. **Set up inotify monitoring for critical paths**
5. **Create daily security check script**

### Long-Term (This Month)
1. **Deploy osquery or similar monitoring**
2. **Implement short-lived token rotation**
3. **Set up centralized logging (if multi-machine)**
4. **Consider SELinux or AppArmor policies**
5. **Document incident response procedures**

---

## Linux-Specific Defenses

### auditd Configuration
Enable comprehensive auditing:
- File access to credential directories
- Syscalls for network operations
- execve for process execution tracking
- File permission changes
- sudo usage

### SELinux/AppArmor
Mandatory access control to restrict processes:
- Confine npm/node processes
- Prevent access to credential files
- Restrict network access
- Limit file creation locations

### systemd Hardening
Use systemd security features:
- `PrivateNetwork=yes` for services that don't need network
- `ProtectHome=yes` to hide home directories
- `ReadOnlyPaths=` for credential directories
- `NoNewPrivileges=yes` to prevent privilege escalation

### Namespace Isolation
Use namespaces for sensitive operations:
- Network namespaces to isolate connectivity
- Mount namespaces to hide filesystem areas
- User namespaces for privilege separation
- Tools: firejail, bubblewrap, systemd-nspawn

### Docker Socket Protection
If using Docker:
- Don't mount `/var/run/docker.sock` into containers
- Use rootless Docker where possible
- Apply access controls to socket
- Monitor for privilege escalation attempts

---

## Measuring Effectiveness

**Can your defenses answer these questions?**

- ✅ Would you know if a GitHub repository was created?
- ✅ Would you detect self-hosted runner installation?
- ✅ Can malware reach webhook.site or pastebin.com?
- ✅ Would you notice `.github/workflows/discussion.yaml`?
- ✅ Can processes freely read `~/.aws/credentials`?
- ✅ Do you have audit logs of npm installations?
- ✅ Would you detect new systemd services?
- ✅ Are file accesses to credentials logged?
- ✅ Would Docker privilege escalation be detected?

**If you answered "no" to any of these, you have a gap.**

---

## Key Principles

1. **Defense in Depth**: Layer multiple controls
2. **Deny by Default**: Start restrictive, allow explicitly
3. **Assume Breach**: Plan for malware execution
4. **Visibility is Security**: Comprehensive logging
5. **Continuous Validation**: Constant re-checking
6. **Credential Isolation**: Separate, encrypted, minimal access
7. **Least Privilege**: Minimize sudo usage, use capabilities

---

## Next Steps

1. **Audit**: Run Lynis security scan
2. **Control**: Configure iptables/ufw for egress filtering
3. **Monitor**: Enable auditd with comprehensive rules
4. **Isolate**: Move credentials to encrypted manager
5. **Validate**: Create automated daily security checks
6. **Harden**: Apply SELinux/AppArmor policies if capable
7. **Iterate**: Refine based on what you learn

---

**See also:**
- [macOS Defence](macos-defence.md) - macOS-specific strategies
- [Windows Defence](windows-defence.md) - Windows-specific strategies
- [Protection Strategies](protection.md) - General security strategies
- [Detection Indicators](detection.md) - How to detect compromises
- [Response Guide](response.md) - Incident response procedures
