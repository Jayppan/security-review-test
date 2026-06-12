"""Security audit prompt template for DeepSeek API."""

SYSTEM_PROMPT = """\
You are an expert application security engineer. Your task is to perform a thorough
security review of code changes in a pull request. You will receive a git diff.

Analyze the diff for the following categories of security vulnerabilities:

1. **Injection Attacks**: SQL, command, LDAP, NoSQL, XXE, template injection, etc.
2. **Authentication & Authorization**: Broken access control, missing auth checks,
   privilege escalation, session management flaws.
3. **Hardcoded Secrets**: API keys, tokens, passwords, private keys in code.
4. **Cryptographic Weaknesses**: Weak algorithms, improper key management,
   hardcoded IVs, predictable randomness.
5. **Path Traversal & File Inclusion**: Unsanitized file paths, directory traversal.
6. **Cross-Site Scripting (XSS)**: Reflected, stored, DOM-based XSS.
7. **Cross-Site Request Forgery (CSRF)**: Missing or improper CSRF protection.
8. **Race Conditions & TOCTOU**: Time-of-check-time-of-use vulnerabilities.
9. **Deserialization**: Unsafe deserialization of untrusted data.
10. **Input Validation**: Missing or insufficient input validation/sanitization.
11. **Configuration Issues**: Dangerous defaults, debug mode in production,
    missing security headers.
12. **Open Redirects**: Unvalidated redirect URLs.

For each finding, you MUST include the exact file path and line number from the diff.
Only report findings that are introduced or modified by the code change — do not
flag pre-existing code that was not changed.

If you find no security issues, return an empty findings list.

IMPORTANT: Return ONLY valid JSON. Do not include any other text, explanations,
or markdown formatting outside the JSON structure."""


def build_security_audit_prompt(diff_text: str, changed_files: list[str]) -> str:
    """Build the full security audit prompt with diff content."""
    files_list = "\n".join(f"  - {f}" for f in changed_files[:50])

    prompt = f"""\
## Pull Request Security Review

### Changed Files
{files_list if files_list else '  (unable to list files)'}

### Diff Content
```diff
{diff_text[:15000] if len(diff_text) > 15000 else diff_text}
```

{"**Note:** The diff was truncated to 15000 characters." if len(diff_text) > 15000 else ""}

### Instructions

Review the above diff for security vulnerabilities. For each finding, output a JSON
object with this exact structure:

```json
{{
  "findings": [
    {{
      "file": "path/to/file.py",
      "line": 42,
      "severity": "high|medium|low",
      "category": "injection|auth|secret|crypto|path-traversal|xss|csrf|race-condition|deserialization|input-validation|configuration|open-redirect",
      "title": "Short, descriptive title",
      "description": "Detailed explanation of the vulnerability and its impact",
      "remediation": "Specific guidance on how to fix the issue"
    }}
  ]
}}
```

Rules:
- `line` must be an integer (the new line number in the changed file)
- `severity` must be one of: high, medium, low
- Return ONLY the JSON, no other text
- If no issues found, return {{"findings": []}}
"""
    return prompt
