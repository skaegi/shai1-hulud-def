# Shai1-Hulud npm Supply Chain Attack

Self-replicating worm targeting npm packages. Active threat as of November 2025.

## Current Status

- **~1,000 packages** compromised
- **25,000+ GitHub repositories** affected
- **Major victims**: Zapier, ENS Domains, PostHog, Postman, AsyncAPI
- **Timeline**: Packages uploaded Nov 21-23, 2025; GitHub mitigation ongoing

## Quick Check

```bash
# Run security audit (3 seconds)
chmod +x dry-hulud.sh && ./dry-hulud.sh
```

**The tool reports:**
- What credentials would be stolen (13 types: GitHub, npm, AWS, GCP, Azure, SSH, Docker/K8s, etc.)
- Whether `rm -rf $HOME/*` would succeed on your system
- Docker privilege escalation risk
- Platform-specific persistence mechanisms

**Exit codes**: 0 (safe), 1 (high risk), 2 (critical - take action immediately)

## Attack Mechanics

**Infection**: npm lifecycle scripts (`preinstall`) execute malicious code during `npm install`

**Credential theft**: AWS, GCP, Azure, GitHub, npm tokens + TruffleHog scan of home directory

**Persistence**: GitHub Actions self-hosted runner named "SHA1HULUD" with `discussion.yaml` workflow backdoor

**Propagation**: Injects malware into up to 100 packages per stolen npm token (worm behavior)

**Novel technique**: "Token recycling" - searches GitHub for other victims' repos, downloads their stolen credentials, reuses them

**Destructive failsafe**: If exfiltration fails, executes `rm -rf $HOME/*` (potentially escalates to root via Docker)

---

## Documentation

**Core**: [Attack Overview](docs/attack-overview.md) • [Detection](docs/detection.md) • [Response](docs/response.md) • [Protection](docs/protection.md) • [Technical Details](docs/technical-details.md)

**Platform Defence**: [macOS](docs/macos-defence.md) • [Linux](docs/linux-defence.md) • [Windows](docs/windows-defence.md) • [GitHub Actions](docs/github-actions-defence.md)

**Reference**: [Compromised Packages](docs/compromised-packages.md) • [Resources](docs/resources.md)

## If Compromised

1. Run `./dry-hulud.sh` to assess exposure
2. Follow [Response Guide](docs/response.md): isolate → rotate credentials → remove runners/workflows → rebuild
3. Check for repos with "Sha1-Hulud" in description
4. Delete `~/.dev-env/` and `.github/workflows/discussion.yaml`

## Protection

```bash
# CI/CD: Disable npm scripts
echo "ignore-scripts=true" >> .npmrc

# Rotate all tokens (GitHub, npm, AWS, GCP, Azure)
# Enable 2FA everywhere
# Use credential managers (1Password, aws-vault)
```

See [Protection Guide](docs/protection.md) for comprehensive strategies.

---

## License

Apache License 2.0 - See [LICENSE](LICENSE) file for details.

