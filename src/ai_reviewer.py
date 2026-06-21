"""
gitleaks-ai: AI-powered false-positive elimination engine.

This module lazy-loads the OpenAI client so normal non-AI scans do not require
OPENAI_API_KEY at import time.
"""

import json
import time
from typing import Any, Optional

try:
    from openai import OpenAI
except ModuleNotFoundError:
    OpenAI = None

from .scanner import Finding


_client: Optional[OpenAI] = None
REDACTED_SECRET = "[REDACTED_SECRET]"


SYSTEM_PROMPT = """You are an expert application security engineer specializing in secrets detection and credential security.
You are reviewing potential secrets found in source code by a static analysis scanner.

For each finding, determine:
1. Whether it is a REAL secret (true positive) or a FALSE POSITIVE (test value, placeholder, example, documentation, etc.)
2. Your confidence level (0.0 to 1.0)
3. A brief reason for your verdict

Be conservative — when in doubt, mark as true positive. Only mark as false positive when you are highly confident.

Respond with JSON only:
{"results":[{"verdict":"true_positive","confidence":0.0,"reason":"..."}]}"""


def get_client() -> OpenAI:
    """Create OpenAI client only when AI functionality is actually used."""
    global _client

    if _client is None:
        _client = OpenAI()

    return _client


def finding_attr(finding: Any, name: str, default: Any = None) -> Any:
    """Support both Finding objects and dict findings."""
    if isinstance(finding, dict):
        return finding.get(name, default)

    return getattr(finding, name, default)


def set_finding_attr(finding: Any, name: str, value: Any) -> None:
    """Set attribute/key on Finding objects or dict findings."""
    if isinstance(finding, dict):
        finding[name] = value
        return

    setattr(finding, name, value)


def is_false_positive(finding: Any) -> bool:
    return bool(finding_attr(finding, "is_false_positive", False))


def finding_context_lines(finding: Any) -> list[str]:
    context = finding_attr(finding, "context_lines", [])

    if context is None:
        return []

    if isinstance(context, list):
        return [str(line) for line in context]

    return [str(context)]


def redact_outgoing_secret(value: str, secret_value: str) -> str:
    """Remove candidate secret material before sending data to external AI APIs."""
    if not secret_value:
        return value

    return value.replace(secret_value, REDACTED_SECRET)


def build_review_item(finding: Any, index: int) -> dict[str, Any]:
    match_value = str(finding_attr(finding, "match", ""))
    safe_context = [
        redact_outgoing_secret(line, match_value)
        for line in finding_context_lines(finding)
    ]

    return {
        "index": index,
        "type": finding_attr(finding, "secret_type", "unknown"),
        "match_preview": REDACTED_SECRET if match_value else "",
        "entropy": finding_attr(finding, "entropy", 0.0),
        "risk_score": finding_attr(finding, "risk_score", 0.0),
        "file": finding_attr(finding, "file", "unknown"),
        "line": finding_attr(finding, "line", "?"),
        "context": "\n".join(safe_context),
    }


def parse_ai_results(raw: str) -> list[dict[str, Any]]:
    """Parse model response while accepting common JSON shapes."""
    parsed = json.loads(raw)

    if isinstance(parsed, list):
        return parsed

    if isinstance(parsed, dict):
        for key in ("results", "findings", "verdicts"):
            value = parsed.get(key)
            if isinstance(value, list):
                return value

    return []


def mark_unreviewed(findings: list[Any]) -> list[Any]:
    """Conservative fallback: keep findings as true-positive relevant."""
    for finding in findings:
        set_finding_attr(finding, "ai_verdict", "unreviewed")
        set_finding_attr(finding, "ai_confidence", None)
        set_finding_attr(finding, "is_false_positive", False)

    return findings


def review_findings_batch(
    findings: list[Finding],
    batch_size: int = 10,
    rate_limit_delay: float = 1.0,
    timeout: int = 300,
) -> list[Finding]:
    """
    Send findings to AI in batches for contextual false-positive review.

    Conservative behavior:
    - AI failures do not suppress findings.
    - Unreviewed findings remain CI-relevant.
    """
    reviewed: list[Finding] = []
    start_time = time.monotonic()

    for i in range(0, len(findings), batch_size):
        if time.monotonic() - start_time > timeout:
            raise TimeoutError(f"AI review exceeded timeout of {timeout}s")

        batch = findings[i:i + batch_size]
        batch_input = [
            build_review_item(finding, index)
            for index, finding in enumerate(batch)
        ]

        prompt = (
            f"Review these {len(batch)} potential secrets.\n\n"
            f"{json.dumps(batch_input, indent=2)}"
        )

        try:
            response = get_client().chat.completions.create(
                model="gpt-4.1-mini",
                messages=[
                    {"role": "system", "content": SYSTEM_PROMPT},
                    {"role": "user", "content": prompt},
                ],
                response_format={"type": "json_object"},
                timeout=timeout,
            )

            raw = response.choices[0].message.content or "{}"
            results = parse_ai_results(raw)

            for j, finding in enumerate(batch):
                result = results[j] if j < len(results) else {}

                verdict = str(result.get("verdict", "unknown"))
                confidence = result.get("confidence", 0.5)
                reason = result.get("reason", "")

                try:
                    confidence = float(confidence)
                except (TypeError, ValueError):
                    confidence = 0.5

                set_finding_attr(finding, "ai_verdict", verdict)
                set_finding_attr(finding, "ai_confidence", confidence)
                set_finding_attr(finding, "ai_reason", reason)
                set_finding_attr(finding, "is_false_positive", verdict == "false_positive")

                reviewed.append(finding)

        except Exception:
            reviewed.extend(mark_unreviewed(batch))

        if rate_limit_delay > 0 and i + batch_size < len(findings):
            time.sleep(rate_limit_delay)

    return reviewed


def generate_static_remediation_report(findings: list[Any]) -> str:
    """Non-AI remediation fallback."""
    confirmed = [finding for finding in findings if not is_false_positive(finding)]

    if not confirmed:
        return "No confirmed secrets found."

    lines = [
        "## Immediate Actions",
        "",
        "- Rotate or revoke every affected credential.",
        "- Treat exposed credentials as compromised.",
        "- Identify where each credential was used and review access logs.",
        "",
        "## Confirmed Findings",
        "",
    ]

    for finding in confirmed[:50]:
        lines.append(
            f"- `{finding_attr(finding, 'secret_type', 'unknown')}` in "
            f"`{finding_attr(finding, 'file', 'unknown')}:{finding_attr(finding, 'line', '?')}` "
            f"(entropy={finding_attr(finding, 'entropy', 0.0)}, "
            f"risk={finding_attr(finding, 'risk_score', 0.0)})"
        )

    if len(confirmed) > 50:
        lines.append(f"- ...and {len(confirmed) - 50} additional findings.")

    lines.extend([
        "",
        "## Remediation Steps",
        "",
        "- Remove secrets from the current tree.",
        "- Rotate credentials before relying on removal.",
        "- Purge sensitive values from Git history where required.",
        "- Move runtime secrets into a secret manager or CI/CD secret store.",
        "- Add pre-commit and CI secret scanning gates.",
        "",
        "## Prevention",
        "",
        "- Add allowlisted test fixtures only when required.",
        "- Block commits containing high-entropy credentials.",
        "- Review generated artifacts, logs, and sample configuration files before commit.",
    ])

    return "\n".join(lines)


def generate_remediation_report(findings: list[Finding]) -> str:
    """Generate a remediation report for confirmed secrets."""
    confirmed = [finding for finding in findings if not is_false_positive(finding)]

    if not confirmed:
        return "No confirmed secrets found."

    summary = "\n".join(
        f"- {finding_attr(finding, 'secret_type', 'unknown')} in "
        f"{finding_attr(finding, 'file', 'unknown')}:{finding_attr(finding, 'line', '?')} "
        f"(entropy={finding_attr(finding, 'entropy', 0.0)}, "
        f"risk={finding_attr(finding, 'risk_score', 0.0)})"
        for finding in confirmed[:20]
    )

    prompt = f"""Generate a concise remediation report for the following confirmed secrets found in source code.

Confirmed Secrets ({len(confirmed)} total):
{summary}

Include:
1. Immediate Actions
2. Root Cause
3. Remediation Steps
4. Prevention

Format in Markdown."""

    try:
        response = get_client().chat.completions.create(
            model="gpt-4.1-mini",
            messages=[
                {"role": "system", "content": "You are an expert DevSecOps engineer."},
                {"role": "user", "content": prompt},
            ],
        )

        return response.choices[0].message.content or generate_static_remediation_report(findings)

    except Exception:
        return generate_static_remediation_report(findings)
