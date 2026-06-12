#!/usr/bin/env python3
"""Security review script using DeepSeek API.

Fetches a PR diff from GitHub, sends it to DeepSeek for security analysis,
and posts findings as inline review comments on the PR.
"""

import json
import os
import re
import sys

import requests
from openai import OpenAI


def get_env(name: str) -> str:
    value = os.environ.get(name)
    if not value:
        print(f"Error: {name} environment variable is required")
        sys.exit(1)
    return value


def fetch_pr_diff(repo: str, pr_number: str, token: str) -> tuple[str, list[str]]:
    """Fetch the PR diff and list of changed files from GitHub API."""
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github.v3.diff",
    }
    diff_url = f"https://api.github.com/repos/{repo}/pulls/{pr_number}"
    resp = requests.get(diff_url, headers=headers, timeout=30)
    resp.raise_for_status()
    diff_text = resp.text

    # Also fetch files list
    files_headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github.v3+json",
    }
    files_url = f"https://api.github.com/repos/{repo}/pulls/{pr_number}/files"
    files_resp = requests.get(files_url, headers=files_headers, timeout=30)
    files_resp.raise_for_status()
    files_data = files_resp.json()
    changed_files = [f["filename"] for f in files_data]

    return diff_text, changed_files


def call_deepseek(prompt: str) -> dict:
    """Send the security audit prompt to DeepSeek and parse the response."""
    from prompts import SYSTEM_PROMPT, build_security_audit_prompt

    client = OpenAI(
        api_key=os.environ["DEEPSEEK_API_KEY"],
        base_url="https://api.deepseek.com",
    )

    print("Calling DeepSeek API for security review...")
    response = client.chat.completions.create(
        model="deepseek-chat",
        messages=[
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": prompt},
        ],
        temperature=0.1,
        max_tokens=4096,
    )

    content = response.choices[0].message.content or ""
    print(f"DeepSeek response received ({len(content)} chars)")

    # Try to extract JSON from the response
    return parse_response(content)


def parse_response(content: str) -> dict:
    """Extract and parse JSON from DeepSeek's response."""
    # Try direct parse first
    try:
        return json.loads(content)
    except json.JSONDecodeError:
        pass

    # Try extracting from markdown code block
    json_match = re.search(r"```(?:json)?\s*([\s\S]*?)```", content)
    if json_match:
        try:
            return json.loads(json_match.group(1))
        except json.JSONDecodeError:
            pass

    # Try finding JSON object in the text
    json_match = re.search(r"\{[\s\S]*\"findings\"[\s\S]*\}", content)
    if json_match:
        try:
            return json.loads(json_match.group(0))
        except json.JSONDecodeError:
            pass

    print(f"Failed to parse JSON from response: {content[:500]}")
    return {"findings": [], "parse_error": True}


def post_review(
    repo: str, pr_number: str, token: str, findings: list[dict]
) -> None:
    """Post findings as a PR review with inline comments."""
    if not findings:
        print("No findings to report.")
        # Post a summary comment instead
        url = f"https://api.github.com/repos/{repo}/pulls/{pr_number}/reviews"
        headers = {
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github.v3+json",
        }
        body = {
            "event": "COMMENT",
            "body": "## Security Review (DeepSeek)\n\nNo security issues found in this PR.",
        }
        requests.post(url, headers=headers, json=body, timeout=30)
        return

    comments = []
    for finding in findings:
        try:
            line = int(finding.get("line", 0))
        except (TypeError, ValueError):
            line = 0

        body = (
            f"**Severity:** {finding.get('severity', 'unknown').upper()}\n"
            f"**Category:** {finding.get('category', 'unknown')}\n\n"
            f"{finding.get('description', 'No description.')}\n\n"
            f"**Remediation:** {finding.get('remediation', 'No remediation provided.')}"
        )

        comments.append(
            {
                "path": finding.get("file", ""),
                "line": line,
                "side": "RIGHT",
                "body": body,
            }
        )

    url = f"https://api.github.com/repos/{repo}/pulls/{pr_number}/reviews"
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github.v3+json",
    }
    body = {
        "event": "COMMENT",
        "body": f"## Security Review (DeepSeek)\n\nFound **{len(findings)}** potential security issue(s).",
        "comments": comments,
    }

    resp = requests.post(url, headers=headers, json=body, timeout=30)
    if resp.status_code >= 400:
        print(f"Warning: Failed to post review: {resp.status_code} {resp.text[:500]}")
        # Fallback: post a summary comment without inline annotations
        summary = "## Security Review (DeepSeek)\n\n"
        for f in findings:
            summary += (
                f"- **{f.get('severity', '?').upper()}** [{f.get('file', '?')}:{f.get('line', '?')}] "
                f"{f.get('title', 'No title')}\n"
            )
        fallback_body = {"event": "COMMENT", "body": summary}
        requests.post(url, headers=headers, json=fallback_body, timeout=30)
    else:
        print(f"Review posted successfully with {len(findings)} finding(s).")


def main():
    repo = get_env("REPO")
    pr_number = get_env("PR_NUMBER")
    token = get_env("GITHUB_TOKEN")

    print(f"Fetching diff for {repo}#{pr_number}...")
    diff_text, changed_files = fetch_pr_diff(repo, pr_number, token)

    if not diff_text.strip():
        print("No diff content found. Skipping review.")
        return

    from prompts import build_security_audit_prompt

    prompt = build_security_audit_prompt(diff_text, changed_files)
    result = call_deepseek(prompt)

    findings = result.get("findings", [])
    if result.get("parse_error"):
        print("JSON parsing failed. Raw findings may be incomplete.")
        # Try to post a raw response comment
        url = f"https://api.github.com/repos/{repo}/pulls/{pr_number}/reviews"
        headers = {
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github.v3+json",
        }
        requests.post(
            url,
            headers=headers,
            json={"event": "COMMENT", "body": "## Security Review (DeepSeek)\n\nFailed to parse API response. Please check the action logs."},
            timeout=30,
        )
        return

    print(f"Found {len(findings)} potential security issue(s).")
    for f in findings:
        print(f"  [{f.get('severity', '?').upper()}] {f.get('file', '?')}:{f.get('line', '?')} - {f.get('title', '?')}")

    post_review(repo, pr_number, token, findings)


if __name__ == "__main__":
    main()
