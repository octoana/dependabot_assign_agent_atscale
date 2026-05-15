# Dependabot Alert Scanner & Copilot Auto-Fixer

A Python CLI that scans all repositories in a GitHub organization for open Dependabot security alerts, and optionally creates GitHub Issues assigned to the **Copilot Coding Agent** to fix a specific CVE automatically.

## What it does

1. Loops through all (or a limited number of) repositories in a GitHub organization
2. Fetches open Dependabot alerts for each repo
3. Prints a summary showing the number of alerts per repo, with CVE ID, severity, and affected package
4. When a `--cve` is provided:
   - Creates a detailed GitHub Issue on every repo where that CVE is found
   - The issue includes all vulnerability details and explicit instructions for the Copilot Coding Agent to create a fix PR
   - Assigns the issue to **Copilot** to automatically trigger a pull request with the dependency upgrade

## Requirements

- Python 3.8+
- A GitHub Personal Access Token (PAT) with `repo` and `security_events` scopes

```bash
pip install -r requirements.txt
```

## Setup

```bash
export GITHUB_TOKEN=ghp_yourtoken
```

## Usage

### Scan all repos in an org

```bash
python3 dependabot_alerts.py <org>
```

### Scan only the first N repos

```bash
python3 dependabot_alerts.py <org> --limit 10
```

### Create issues and assign Copilot for a specific CVE

```bash
python3 dependabot_alerts.py <org> --cve CVE-2021-44228
```

### Combine options

```bash
python3 dependabot_alerts.py <org> --cve CVE-2021-44228 --limit 20
```

### Pass the token inline

```bash
python3 dependabot_alerts.py <org> --token ghp_yourtoken --cve CVE-2024-47535
```

## Arguments

| Argument | Required | Description |
|---|---|---|
| `org` | Yes | GitHub organization name |
| `--token` | Yes* | GitHub PAT (`GITHUB_TOKEN` env var used by default) |
| `--limit N` | No | Number of repos to scan (default: all) |
| `--cve CVE-XXXX-XXXXX` | No | CVE ID to act on — creates issues and assigns Copilot |
| `--app-id` | No | GitHub App ID for fully automated Copilot assignment |
| `--app-private-key PATH` | No | Path to GitHub App private key `.pem` file |

## Example output

```
Organization : my-org
CVE filter   : CVE-2021-44228

Repositories found : 42
Checking Dependabot alerts...

------------------------------------------------------------
  api-service: 3 open alert(s)
    [CRITICAL] CVE-2021-44228 — log4j-core
      -> Issue #17 created
      -> Copilot coding agent assigned to issue #17
    [HIGH]     CVE-2022-42003 — jackson-databind
    [MEDIUM]   CVE-2023-20860 — spring-webmvc
  frontend-app: no dependabot on this repo
  legacy-worker: dependabot disabled on this repo
------------------------------------------------------------

Total open Dependabot alerts : 3
Repos skipped                : 2
```

## GitHub App (optional — for fully automated Copilot assignment at scale)

If the PAT-based Copilot assignment does not work in your org, you can use a GitHub App:

1. Create a GitHub App at `https://github.com/organizations/<org>/settings/apps/new`
2. Grant **Issues → Read & write** permissions
3. Install the App on your organization
4. Download the private key (`.pem`)
5. Note the **App ID** from the App settings page

Then run:

```bash
export GITHUB_APP_ID=123456
export GITHUB_APP_PRIVATE_KEY_PATH=/path/to/app.private-key.pem
python3 dependabot_alerts.py <org> --cve CVE-2021-44228
```

## How Copilot fixes the issue

When assigned, the Copilot Coding Agent will:
- Read the issue description (which includes the exact package, vulnerable version range, and safe version)
- Locate the dependency in the project manifest (`pom.xml`, `package.json`, `requirements.txt`, etc.)
- Upgrade it to the safe version
- Verify the build and tests pass
- Open a pull request referencing the issue
