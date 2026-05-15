#!/usr/bin/env python3

import argparse
import os
import sys
import time
import requests

try:
    import jwt  # PyJWT
except ImportError:
    jwt = None


def get_org_repos(session, org, limit=None):
    """Fetch repositories for an organization."""
    repos = []
    page = 1
    per_page = 100

    while True:
        url = f"https://api.github.com/orgs/{org}/repos"
        response = session.get(url, params={"per_page": per_page, "page": page, "type": "all"})
        response.raise_for_status()
        data = response.json()

        if not data:
            break

        repos.extend(data)

        if limit and len(repos) >= limit:
            repos = repos[:limit]
            break

        if len(data) < per_page:
            break

        page += 1

    return repos


DEPENDABOT_DISABLED = "disabled"
DEPENDABOT_FORBIDDEN = "forbidden"


def get_dependabot_alerts(session, owner, repo):
    """Fetch all open Dependabot alerts for a repository.
    Returns DEPENDABOT_DISABLED if Dependabot is not enabled (404/400).
    Returns DEPENDABOT_FORBIDDEN if the token lacks permission (403).
    Uses cursor-based pagination via the Link header.
    """
    alerts = []
    url = f"https://api.github.com/repos/{owner}/{repo}/dependabot/alerts"
    params = {"per_page": 100, "state": "open"}

    while url:
        response = session.get(url, params=params)

        if response.status_code in (400, 404):
            return DEPENDABOT_DISABLED
        if response.status_code == 403:
            return DEPENDABOT_FORBIDDEN

        response.raise_for_status()
        data = response.json()
        alerts.extend(data)

        # Follow cursor-based pagination from the Link header
        next_link = response.links.get("next", {}).get("url")
        url = next_link
        params = {}  # params are already encoded in the next URL

    return alerts


def create_issue(session, owner, repo, cve_id, alert):
    """Create a GitHub issue for a CVE alert and return the issue number."""
    advisory = alert.get("security_advisory", {})
    severity = advisory.get("severity", "unknown").upper()
    vuln = alert.get("security_vulnerability", {})
    package = vuln.get("package", {}).get("name", "unknown")
    ecosystem = vuln.get("package", {}).get("ecosystem", "unknown")
    vulnerable_range = vuln.get("vulnerable_version_range", "unknown")
    patched_version = vuln.get("first_patched_version", {})
    fix_version = patched_version.get("identifier", "no fix available") if patched_version else "no fix available"
    alert_number = alert.get("number", "unknown")
    alert_url = alert.get("html_url", "")
    summary = advisory.get("summary", "No description available.")
    description = advisory.get("description", "")

    title = f"[Security] {cve_id} — {package} ({severity})"
    body = (
        f"## Dependabot Security Alert — Action Required\n\n"
        f"| Field | Value |\n"
        f"|---|---|\n"
        f"| **CVE** | {cve_id} |\n"
        f"| **Dependabot Alert #** | [{alert_number}]({alert_url}) |\n"
        f"| **Package** | `{package}` ({ecosystem}) |\n"
        f"| **Vulnerable versions** | `{vulnerable_range}` |\n"
        f"| **Severity** | {severity} |\n"
        f"| **Safe version** | `{fix_version}` |\n\n"
        f"### Vulnerability Summary\n{summary}\n\n"
        f"{('### Details\n' + description + chr(10) + chr(10)) if description else ''}"
        f"---\n\n"
        f"## Task for Copilot Coding Agent\n\n"
        f"Please create a pull request that fixes this vulnerability by doing the following:\n\n"
        f"1. Locate the dependency `{package}` in the project's dependency manifest(s) "
        f"(e.g. `pom.xml`, `package.json`, `requirements.txt`, `build.gradle`, etc.).\n"
        f"2. Update `{package}` from the vulnerable version range `{vulnerable_range}` "
        f"to version `{fix_version}` or the latest non-vulnerable version available.\n"
        f"3. Verify the project still builds and all existing tests pass after the upgrade.\n"
        f"4. Open a pull request with a clear title and description referencing this issue and "
        f"Dependabot alert [#{alert_number}]({alert_url}).\n\n"
        f"_This issue was automatically created by the Dependabot alert scanner._"
    )

    response = session.post(
        f"https://api.github.com/repos/{owner}/{repo}/issues",
        json={"title": title, "body": body},
    )
    response.raise_for_status()
    return response.json()["number"]


def _generate_app_jwt(app_id, private_key_path):
    """Generate a GitHub App JWT for authentication."""
    if jwt is None:
        raise RuntimeError("PyJWT is not installed. Run: pip install PyJWT cryptography")
    with open(private_key_path, "r") as f:
        private_key = f.read()
    now = int(time.time())
    payload = {"iat": now - 60, "exp": now + 540, "iss": str(app_id)}
    return jwt.encode(payload, private_key, algorithm="RS256")


def _get_installation_token(app_jwt, owner):
    """Exchange a GitHub App JWT for an installation access token scoped to the org."""
    headers = {
        "Authorization": f"Bearer {app_jwt}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    resp = requests.get(f"https://api.github.com/orgs/{owner}/installation", headers=headers)
    resp.raise_for_status()
    installation_id = resp.json()["id"]

    resp = requests.post(
        f"https://api.github.com/app/installations/{installation_id}/access_tokens",
        headers=headers,
    )
    resp.raise_for_status()
    return resp.json()["token"]


def assign_to_copilot(session, owner, repo, issue_number, cve_id, package, fix_version, alert_number, alert_url, app_token=None):
    """Assign the Copilot coding agent to the issue via the assignees endpoint."""
    url = f"https://api.github.com/repos/{owner}/{repo}/issues/{issue_number}/assignees"
    payload = {
        "assignees": ["copilot-swe-agent[bot]"],
        "agent_assignment": {
            "target_repo": f"{owner}/{repo}",
            "base_branch": "main",
            "custom_instructions": "",
            "custom_agent": "",
            "model": "",
        },
    }

    # Try with GitHub App token first if available, fall back to session PAT
    if app_token:
        headers = {
            "Authorization": f"Bearer {app_token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        }
        response = requests.post(url, headers=headers, json=payload)
    else:
        response = session.post(url, json=payload)

    print(f"      [DEBUG] Assignee response: {response.status_code}")
    if response.status_code not in (200, 201):
        print(f"      [DEBUG] Body: {response.text[:300]}")

    if response.status_code in (200, 201):
        assignees = [a["login"] for a in response.json().get("assignees", [])]
        if any("copilot" in a.lower() for a in assignees):
            return True

    issue_url = f"https://github.com/{owner}/{repo}/issues/{issue_number}"
    print(f"      !! Auto-assignment failed. Assign manually (one click) at:")
    print(f"      !! {issue_url}")
    return False


def main():
    parser = argparse.ArgumentParser(
        description="List open Dependabot alerts for repositories in a GitHub organization."
    )
    parser.add_argument("org", help="GitHub organization name")
    parser.add_argument(
        "--limit",
        type=int,
        default=None,
        metavar="N",
        help="Number of repositories to process (default: all)",
    )
    parser.add_argument(
        "--cve",
        default=None,
        metavar="CVE-XXXX-XXXXX",
        help="CVE ID to filter on; matching alerts will get a GitHub issue created and assigned to Copilot",
    )
    parser.add_argument(
        "--token",
        default=os.environ.get("GITHUB_TOKEN"),
        help="GitHub personal access token (defaults to GITHUB_TOKEN env var)",
    )
    parser.add_argument(
        "--app-id",
        default=os.environ.get("GITHUB_APP_ID"),
        help="GitHub App ID for Copilot assignment (defaults to GITHUB_APP_ID env var)",
    )
    parser.add_argument(
        "--app-private-key",
        default=os.environ.get("GITHUB_APP_PRIVATE_KEY_PATH"),
        metavar="PATH",
        help="Path to the GitHub App private key PEM file (defaults to GITHUB_APP_PRIVATE_KEY_PATH env var)",
    )
    args = parser.parse_args()

    if not args.token:
        print(
            "Error: a GitHub token is required.\n"
            "Set the GITHUB_TOKEN environment variable or pass --token <token>.",
            file=sys.stderr,
        )
        sys.exit(1)

    session = requests.Session()
    session.headers.update(
        {
            "Authorization": f"Bearer {args.token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        }
    )

    # Resolve GitHub App installation token for Copilot assignment
    app_token = None
    if args.app_id and args.app_private_key:
        try:
            app_jwt = _generate_app_jwt(args.app_id, args.app_private_key)
            app_token = _get_installation_token(app_jwt, args.org)
            print("GitHub App   : authenticated (Copilot assignment enabled)")
        except Exception as exc:
            print(f"GitHub App   : failed to authenticate ({exc})", file=sys.stderr)
    elif args.cve:
        print("GitHub App   : not configured (Copilot assignment will require manual step)")

    print(f"Organization : {args.org}")
    if args.limit:
        print(f"Repo limit   : {args.limit}")
    if args.cve:
        print(f"CVE filter   : {args.cve}")
    print()

    try:
        repos = get_org_repos(session, args.org, args.limit)
    except requests.HTTPError as exc:
        print(f"Error fetching repositories: {exc}", file=sys.stderr)
        sys.exit(1)

    print(f"Repositories found : {len(repos)}")
    print("Checking Dependabot alerts...\n")
    print("-" * 60)

    total_alerts = 0
    unavailable = 0

    for repo in repos:
        name = repo["name"]
        try:
            alerts = get_dependabot_alerts(session, args.org, name)
        except requests.HTTPError as exc:
            print(f"  {name}: ERROR ({exc})")
            continue

        if alerts == DEPENDABOT_DISABLED:
            print(f"  {name}: no dependabot on this repo")
            unavailable += 1
        elif alerts == DEPENDABOT_FORBIDDEN:
            print(f"  {name}: dependabot disabled on this repo")
            unavailable += 1
        else:
            count = len(alerts)
            total_alerts += count
            print(f"  {name}: {count} open alert(s)")
            for alert in alerts:
                advisory = alert.get("security_advisory", {})
                cve_id = advisory.get("cve_id") or "No CVE assigned"
                severity = advisory.get("severity", "unknown").upper()
                vuln = alert.get("security_vulnerability", {})
                package = vuln.get("package", {}).get("name", "unknown")
                patched = vuln.get("first_patched_version", {})
                fix_version = patched.get("identifier", "no fix available") if patched else "no fix available"
                print(f"    [{severity}] {cve_id} — {package}")

                if args.cve and cve_id.upper() == args.cve.upper():
                    try:
                        issue_number = create_issue(session, args.org, name, cve_id, alert)
                        print(f"      -> Issue #{issue_number} created")
                        assigned = assign_to_copilot(
                            session, args.org, name, issue_number,
                            cve_id, package, fix_version,
                            alert.get("number", ""), alert.get("html_url", ""),
                            app_token=app_token,
                        )
                        if assigned:
                            print(f"      -> Copilot coding agent assigned to issue #{issue_number}")
                    except (requests.HTTPError, RuntimeError) as exc:
                        print(f"      -> Failed to create issue: {exc}", file=sys.stderr)

    print("-" * 60)
    print(f"\nTotal open Dependabot alerts : {total_alerts}")
    if unavailable:
        print(f"Repos skipped                : {unavailable}")


if __name__ == "__main__":
    main()
