"""
gitleaks-ai: AI-powered false-positive elimination engine.
Sends batched findings to an LLM for contextual review, dramatically
reducing false positives compared to pure regex-based scanners.
"""

import json
from typing import Optional
from openai import OpenAI
from .scanner import Finding

client = OpenAI()


SYSTEM_PROMPT = """You are an expert application security engineer specializing in secrets detection and credential security. 
You are reviewing potential secrets found in source code by a static analysis scanner.

For each finding, determine:
1. Whether it is a REAL secret (true positive) or a FALSE POSITIVE (test value, placeholder, example, documentation, etc.)
2. Your confidence level (0.0 to 1.0)
3. A brief reason for your verdict

Be conservative — when in doubt, mark as true positive. Only mark as false positive when you are highly confident.

Respond with a JSON array matching the input order:
[{"verdict": "true_positive"|"false_positive", "confidence": 0.0-1.0, "reason": "..."}]"""


def review_findings_batch(findings: list[Finding], batch_size: int = 10) -> list[Finding]:
    """
    Send findings to the AI in batches for contextual false-positive review.
    Returns findings with ai_verdict, ai_confidence, and is_false_positive populated.
    """
    reviewed = []

    for i in range(0, len(findings), batch_size):
        batch = findings[i:i + batch_size]
        batch_input = []

        for f in batch:
            batch_input.append({
                "index": len(batch_input),
                "type": f.secret_type,
                "match_preview": f.match[:80],
                "entropy": f.entropy,
                "file": f.file,
                "line": f.line,
                "context": "\n".join(f.context_lines),
            })

        prompt = f"Review these {len(batch)} potential secrets:\n\n{json.dumps(batch_input, indent=2)}"

        try:
            response = client.chat.completions.create(
                model="gpt-4.1-mini",
                messages=[
                    {"role": "system", "content": SYSTEM_PROMPT},
                    {"role": "user", "content": prompt},
                ],
                response_format={"type": "json_object"},
            )
            raw = response.choices[0].message.content
            results = json.loads(raw)

            # Handle both {"results": [...]} and direct array responses
            if isinstance(results, dict):
                results = results.get("results", results.get("findings", list(results.values())[0]))

            for j, finding in enumerate(batch):
                if j < len(results):
                    r = results[j]
                    finding.ai_verdict = r.get("verdict", "unknown")
                    finding.ai_confidence = float(r.get("confidence", 0.5))
                    finding.is_false_positive = finding.ai_verdict == "false_positive"
                reviewed.append(finding)

        except Exception as e:
            # On AI failure, keep all findings as unreviewed (conservative)
            for finding in batch:
                finding.ai_verdict = "unreviewed"
                finding.ai_confidence = None
                reviewed.append(finding)

    return reviewed


def generate_remediation_report(findings: list[Finding]) -> str:
    """Generate a comprehensive remediation report for confirmed secrets."""
    confirmed = [f for f in findings if not f.is_false_positive]
    if not confirmed:
        return "No confirmed secrets found."

    summary = "\n".join([
        f"- {f.secret_type} in {f.file}:{f.line} (entropy={f.entropy}, risk={f.risk_score})"
        for f in confirmed[:20]
    ])

    prompt = f"""You are a security engineer. Generate a concise remediation report for the following confirmed secrets found in source code.

Confirmed Secrets ({len(confirmed)} total):
{summary}

Include:
1. **Immediate Actions** (rotate/revoke affected credentials NOW)
2. **Root Cause** (why were secrets committed?)
3. **Remediation Steps** (remove from history, use secret managers)
4. **Prevention** (pre-commit hooks, CI/CD scanning, vault integration)

Format in Markdown."""

    try:
        response = client.chat.completions.create(
            model="gpt-4.1-mini",
            messages=[
                {"role": "system", "content": "You are an expert DevSecOps engineer."},
                {"role": "user", "content": prompt},
            ]
        )
        return response.choices[0].message.content
    except Exception:
        return "AI remediation report unavailable."
