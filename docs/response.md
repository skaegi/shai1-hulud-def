# Incident Response Guide

If you suspect or have confirmed a Shai1-Hulud compromise, follow this guide immediately.

---

## ⚠️ Emergency Actions

### If You Installed npm Packages November 21-25, 2025

You may be compromised. Take these actions **immediately**:

#### 1. Check GitHub for Malicious Repositories

```bash
# Using GitHub CLI
gh repo list --json name,description | jq -r '.[] | select(.description | contains("Sha1-Hulud"))'

# Look for:
# - Repositories with "Sha1-Hulud: The Second Coming" in description
# - Repositories with random 18-character names
# - Repositories ending in "-migration"
```

#### 2. Rotate ALL Credentials Immediately

**Assume all credentials are compromised. Rotate everything:**

- **GitHub**: Personal Access Tokens, OAuth tokens
- **npm**: All authentication tokens
- **AWS**: Access keys, secret keys, IAM credentials
- **GCP**: Service account keys, API keys
- **Azure**: Credentials, managed identities
- **All environment variables**: API keys, secrets, database passwords

```bash
# Example: Rotate GitHub tokens
gh auth refresh

# Example: Rotate AWS keys
aws iam create-access-key --user-name YOUR_USERNAME
# Then delete old keys after updating systems
```

#### 3. Check for Self-Hosted Runners

```bash
# Look for runner directory
ls -la ~/.dev-env/

# Check for running processes
ps aux | grep -i "runner\|sha1hulud"

# If found, kill the process
pkill -f "actions-runner"

# Remove the runner directory
rm -rf ~/.dev-env/
```

#### 4. Audit GitHub Workflows

```bash
# Find all workflow files
find .github/workflows/ -name "*.yml" -o -name "*.yaml"

# Search for malicious workflows
find . -path "*/.github/workflows/*" \( -name "*hulud*" -o -name "discussion.yaml" \)

# Review each workflow for:
# - discussion.yaml (persistent backdoor)
# - shai-hulud-workflow.yml
# - Workflows with ${{ github.event.discussion.body }}
```

#### 5. Scan for Malicious Files

```bash
# Search for dropper and payload files
find ~/ -name "setup_bun.js" -o -name "bun_environment.js" 2>/dev/null

# Search for exfiltrated data
find ~/ -name "cloud.json" -o -name "truffleSecrets.json" 2>/dev/null

# Comprehensive search
find ~/ \( -name "setup_bun.js" -o -name "bun_environment.js" -o -name "cloud.json" -o -name "contents.json" -o -name "environment.json" -o -name "truffleSecrets.json" \) 2>/dev/null
```

---

## Full Incident Response Plan

### Phase 1: Containment

**Objective**: Stop the attack from spreading and causing more damage.

1. **Isolate Affected Systems**
   - Disconnect from network if possible
   - Disable CI/CD pipelines temporarily
   - Suspend automated deployments

2. **Revoke All Access Tokens**
   - GitHub: Settings → Developer settings → Personal access tokens → Revoke all
   - npm: `npm token revoke <token>` for each token
   - Cloud providers: Use respective IAM consoles to disable keys

3. **Remove Self-Hosted Runners**
   ```bash
   # Stop the runner
   pkill -f "actions-runner"

   # Remove runner files
   rm -rf ~/.dev-env/

   # Verify removal
   ps aux | grep runner
   ```

4. **Delete Malicious Workflows**
   ```bash
   # Find and review
   find . -path "*/.github/workflows/*" -name "*hulud*.yml"
   find . -path "*/.github/workflows/discussion.yaml"

   # Delete after verification
   find . -path "*/.github/workflows/discussion.yaml" -delete
   ```

### Phase 2: Assessment

**Objective**: Understand the scope of the compromise.

1. **Identify All Compromised Repositories**
   - Review all repositories for malicious commits
   - Check repository settings for unauthorized collaborators
   - Review deploy keys and webhooks

2. **Check Cloud Provider Logs**
   ```bash
   # AWS CloudTrail
   aws cloudtrail lookup-events --lookup-attributes AttributeKey=EventName,AttributeValue=GetSecretValue

   # GCP Audit Logs
   gcloud logging read "protoPayload.methodName=GetSecretVersion"

   # Azure Activity Log
   az monitor activity-log list --resource-group YOUR_RG
   ```

3. **Audit Repository Access**
   - Review GitHub audit logs
   - Check for unauthorized repository creation
   - Look for unexpected public repository conversions

4. **Document Everything**
   - Screenshot evidence
   - Save logs
   - Record timeline of discovery
   - List all affected systems and credentials

### Phase 3: Eradication

**Objective**: Remove all traces of the malware.

1. **Remove Malicious Files**
   ```bash
   # Remove dropper and payload
   find ~/ -name "setup_bun.js" -delete
   find ~/ -name "bun_environment.js" -delete

   # Remove exfiltrated data files
   find ~/ -name "cloud.json" -o -name "truffleSecrets.json" | xargs rm -f
   ```

2. **Clean Up Malicious Repositories**
   ```bash
   # List repositories to delete
   gh repo list --json name,description | jq -r '.[] | select(.description | contains("Sha1-Hulud")) | .name'

   # Delete each one (CAREFUL!)
   gh repo delete OWNER/REPO --yes
   ```

3. **Remove Malicious Workflows**
   ```bash
   # Remove all hulud-related workflows
   find . -path "*/.github/workflows/*" -name "*hulud*.yml" -delete
   find . -path "*/.github/workflows/discussion.yaml" -delete
   ```

4. **Check for Privilege Escalation**
   ```bash
   # Check for malicious sudoers files
   sudo ls -la /etc/sudoers.d/

   # Look for suspicious entries
   sudo cat /etc/sudoers.d/* | grep NOPASSWD

   # Remove any malicious sudoers files
   sudo rm /etc/sudoers.d/malicious
   ```

5. **Audit All package.json Files**
   ```bash
   # Find all package.json with lifecycle scripts
   find . -name "package.json" -exec grep -l "preinstall\|postinstall" {} \;

   # Review each one for malicious scripts
   # Remove unauthorized preinstall/postinstall scripts
   ```

### Phase 4: Recovery

**Objective**: Restore systems to normal operation.

1. **Reinstall from Clean Backups**
   - If available, restore from backups taken before November 21, 2025
   - Verify backup integrity before restoration

2. **Rebuild Affected Systems**
   - Consider full OS reinstallation for heavily compromised systems
   - Rebuild from known-good images

3. **Update All Dependencies**
   ```bash
   # Remove node_modules
   rm -rf node_modules

   # Clear npm cache
   npm cache clean --force

   # Reinstall with known-clean versions
   npm ci --ignore-scripts
   ```

4. **Re-enable Services Gradually**
   - Start with non-production environments
   - Monitor for signs of reinfection
   - Gradually restore CI/CD pipelines

### Phase 5: Post-Incident

**Objective**: Learn from the incident and prevent recurrence.

1. **Conduct Post-Mortem**
   - Document timeline
   - Identify gaps in security
   - Share learnings with team

2. **Notify Affected Parties**
   - Internal stakeholders
   - Customers (if their data was at risk)
   - Security teams
   - Consider GDPR/compliance requirements

3. **Implement Prevention Measures**
   - See [Protection Strategies](protection.md) for comprehensive guidance
   - Enable MFA everywhere
   - Implement lifecycle script controls
   - Deploy monitoring solutions

4. **Monitor for Reinfection**
   - Set up alerts for suspicious repository creation
   - Monitor for self-hosted runner installations
   - Watch for unusual package publishes

---

## Forensic Analysis

### Analyzing Exfiltrated Data

If you find exfiltrated data files, analyze them carefully:

```bash
# Decode the double base64-encoded data
cat contents.json | base64 -d | base64 -d | jq .

# Review what was stolen
cat cloud.json | base64 -d | base64 -d | jq .
cat environment.json | base64 -d | base64 -d | jq .
```

**Warning**: This shows you what the attacker has access to. Rotate all exposed credentials immediately.

### Checking Cloud Provider Access

```bash
# AWS: Check for unauthorized access
aws cloudtrail lookup-events --start-time 2025-11-21T00:00:00Z

# GCP: Check audit logs
gcloud logging read "timestamp>=\"2025-11-21T00:00:00Z\"" --limit 100

# Azure: Check activity log
az monitor activity-log list --start-time 2025-11-21T00:00:00Z
```

---

## Recovery Checklist

Use this checklist to ensure complete recovery:

### Immediate Actions
- [ ] Isolate affected systems from network
- [ ] Revoke all GitHub Personal Access Tokens
- [ ] Revoke all npm tokens
- [ ] Rotate AWS access keys and secret keys
- [ ] Rotate GCP service account keys
- [ ] Rotate Azure credentials
- [ ] Remove self-hosted runner named "SHA1HULUD"
- [ ] Delete `.github/workflows/discussion.yaml`
- [ ] Delete all repositories with "Sha1-Hulud: The Second Coming"

### Cleanup
- [ ] Remove `setup_bun.js` and `bun_environment.js`
- [ ] Delete exfiltrated data files (cloud.json, contents.json, etc.)
- [ ] Remove malicious workflows from all repositories
- [ ] Audit and clean all package.json preinstall/postinstall scripts
- [ ] Check for malicious sudoers files
- [ ] Verify no unauthorized Docker containers are running

### Verification
- [ ] Scan all systems with updated antivirus/EDR
- [ ] Review cloud provider audit logs for unauthorized access
- [ ] Check for unauthorized repository collaborators
- [ ] Verify no private repositories were made public
- [ ] Confirm all malicious files and workflows are removed

### Prevention
- [ ] Enable hardware-based 2FA on all accounts
- [ ] Implement `ignore-scripts=true` in CI/CD
- [ ] Deploy supply chain security tools (Socket, Snyk, etc.)
- [ ] Set up monitoring for suspicious GitHub activity
- [ ] Remove classic npm tokens (before December 9, 2025)
- [ ] Implement short-lived, scoped tokens
- [ ] Enable EDR on all developer machines
- [ ] Create incident response runbook

### Documentation
- [ ] Document timeline of compromise and discovery
- [ ] List all compromised credentials and systems
- [ ] Record all remediation actions taken
- [ ] Create post-mortem report
- [ ] Share learnings with security team

---

## Getting Help

### Internal Resources
- Contact your security team immediately
- Escalate to incident response team if available
- Notify management of the compromise

### External Resources
- **CISA**: Report to Cybersecurity and Infrastructure Security Agency
- **GitHub Security**: Contact GitHub support for assistance
- **npm Security**: Report to npm security team
- **Security Vendors**: Contact your security tool vendors for assistance

### Community Resources
- Report findings to security research community
- Share IoCs with threat intelligence platforms
- Consider coordinated disclosure if you discover new information

---

**See also:**
- [Detection Indicators](detection.md) - Confirm if you're compromised
- [Protection Strategies](protection.md) - Prevent future attacks
- [Attack Overview](attack-overview.md) - Understand the threat
- [Resources](resources.md) - Additional tools and reports
