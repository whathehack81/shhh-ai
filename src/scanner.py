"""
shhh-ai: Core scanning engine.
Combines regex-based pattern matching, Shannon entropy analysis,
and AI-powered context reasoning to detect secrets with near-zero false positives.
"""

import math
import re
import os
from pathlib import Path
from dataclasses import dataclass, field
from typing import Optional

# ---------------------------------------------------------------------------
# Secret patterns — ordered by specificity (most specific first)
# ---------------------------------------------------------------------------
SECRET_PATTERNS = {
    "AWS Access Key ID":        (r"(?<![A-Z0-9])AKIA[0-9A-Z]{16}(?![A-Z0-9])", 0.85),
    "AWS Secret Access Key":    (r"(?i)aws[_\-\s]?secret[_\-\s]?(?:access[_\-\s]?)?key[\s]*[=:]\s*['\"]?([A-Za-z0-9/+=]{40})['\"]?", 0.80),
    "GitHub Token (Classic)":   (r"ghp_[A-Za-z0-9]{36}", 0.95),
    "GitHub PAT (Fine-grained)":(r"github_pat_[A-Za-z0-9_]{82}", 0.95),
    "Google API Key":           (r"AIza[0-9A-Za-z\-_]{35}", 0.90),
    "Stripe Secret Key":        (r"sk_live_[0-9a-zA-Z]{24}", 0.95),
    "Stripe Publishable Key":   (r"pk_live_[0-9a-zA-Z]{24}", 0.90),
    "Slack Bot Token":          (r"xoxb-[0-9A-Za-z\-]{24,48}", 0.90),
    "Slack User Token":         (r"xoxp-[0-9A-Za-z\-]{24,48}", 0.90),
    "SendGrid API Key":         (r"SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}", 0.95),
    "Twilio Account SID":       (r"AC[a-zA-Z0-9]{32}", 0.75),
    "Twilio Auth Token":        (r"(?i)twilio[_\-\s]?auth[_\-\s]?token[\s]*[=:]\s*['\"]?([a-f0-9]{32})['\"]?", 0.80),
    "JWT Token":                (r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}", 0.80),
    "RSA Private Key":          (r"-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----", 0.99),
    "Database URL":             (r"(?i)(mysql|postgres|postgresql|mongodb|redis|mssql|sqlite):\/\/[^:]+:[^@\s]+@[^\s]+", 0.90),
    "Generic High-Entropy":     (r"(?i)(?:password|passwd|secret|token|api[_\-]?key|auth[_\-]?key)\s*[=:]\s*['\"]?([A-Za-z0-9+/=_\-!@#$%^&*]{16,})['\"]?", 0.60),
    "Heroku API Key":           (r"(?i)heroku[_\-\s]?api[_\-\s]?key[\s]*[=:]\s*['\"]?([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})['\"]?", 0.85),
    "Mailgun API Key":          (r"key-[0-9a-zA-Z]{32}", 0.80),
    "NPM Token":                (r"npm_[A-Za-z0-9]{36}", 0.90),
    "Cloudflare API Token":     (r"(?i)cloudflare[_\-\s]?(?:api[_\-\s]?)?token[\s]*[=:]\s*['\"]?([A-Za-z0-9_-]{40})['\"]?", 0.80),
}

IGNORE_EXTENSIONS = {
    ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".webp",
    ".pdf", ".zip", ".tar", ".gz", ".bz2", ".xz", ".7z",
    ".bin", ".exe", ".dll", ".so", ".dylib", ".wasm",
    ".lock", ".sum",
}

IGNORE_DIRS = {
    ".git", "node_modules", "__pycache__", ".venv", "venv",
    "dist", "build", ".next", ".nuxt", "target", "vendor",
}

# Strings that strongly suggest a value is a placeholder/example
PLACEHOLDER_INDICATORS = [
    "your_", "your-", "<your", "example", "placeholder", "changeme",
    "xxxxxxxx", "aaaaaaaa", "test_key", "dummy", "fake", "sample",
    "insert_", "replace_", "todo", "fixme", "xxx", "000000",
]


@dataclass
class Finding:
    file: str
    line: int
    col: int
    secret_type: str
    match: str
    entropy: float
    pattern_confidence: float
    context_lines: list[str] = field(default_factory=list)
    classification: str = "secret_candidate"
    clue_type: Optional[str] = None
    routes: list[str] = field(default_factory=list)
    disposition: str = "unresolved"
    context_clues: list[str] = field(default_factory=list)
    ai_verdict: Optional[str] = None
    ai_confidence: Optional[float] = None
    is_false_positive: bool = False

    @property
    def risk_score(self) -> float:
        """Composite risk score combining entropy and pattern confidence."""
        return round((self.entropy / 8.0) * 0.4 + self.pattern_confidence * 0.6, 3)

    def to_dict(self) -> dict:
        return {
            "file": self.file,
            "line": self.line,
            "col": self.col,
            "type": self.secret_type,
            "match": self.match[:60] + "..." if len(self.match) > 60 else self.match,
            "entropy": self.entropy,
            "pattern_confidence": self.pattern_confidence,
            "risk_score": self.risk_score,
            "classification": self.classification,
            "clue_type": self.clue_type,
            "routes": self.routes,
            "disposition": self.disposition,
            "context_clues": self.context_clues,
            "ai_verdict": self.ai_verdict,
            "ai_confidence": self.ai_confidence,
            "is_false_positive": self.is_false_positive,
        }


def shannon_entropy(data: str) -> float:
    """Calculate Shannon entropy of a string (bits per character)."""
    if not data:
        return 0.0
    freq = {}
    for c in data:
        freq[c] = freq.get(c, 0) + 1
    length = len(data)
    return -sum((count / length) * math.log2(count / length) for count in freq.values())


def is_likely_placeholder(value: str) -> bool:
    """Heuristic check for placeholder/example values."""
    lower = value.lower()
    return any(indicator in lower for indicator in PLACEHOLDER_INDICATORS)


def extract_context(lines: list[str], line_num: int, window: int = 3) -> list[str]:
    """Extract surrounding lines for context."""
    start = max(0, line_num - window - 1)
    end = min(len(lines), line_num + window)
    return [f"{i+1}: {lines[i]}" for i in range(start, end)]



def classify_finding(secret_type: str, file_path: Path, matched_value: str, context_lines: list[str]) -> dict:
    """Classify matches as secrets, clues, or unresolved signals for analyst routing."""
    path = str(file_path).lower()
    current_line = ""
    for line in context_lines:
        if matched_value and matched_value in line:
            current_line = line.lower()
            break

    ctx = current_line or "\n".join(context_lines).lower()
    context_clues: list[str] = []

    if any(part in path for part in ["docs/", "example", "sample"]):
        context_clues.append("documentation_or_example")
    if any(part in path for part in ["src/test/", "/test/", "fixtures", "mock"]):
        context_clues.append("test_or_fixture_path")
    if any(part in path for part in [".github/workflows", ".github/actions"]):
        context_clues.append("github_actions_surface")
    if any(part in path for part in ["key/", ".pem", ".p12", ".jks", "keystore", "truststore"]):
        context_clues.append("crypto_material_path")
    if any(word in ctx for word in ["postgres", "mysql", "mongodb", "redis", "jdbc", "datasource"]):
        context_clues.append("database_surface")
    if any(word in ctx for word in ["pull_request_target", "workflow_dispatch", "secrets.", "github_token"]):
        context_clues.append("ci_trust_boundary_surface")

    if secret_type == "Database URL":
        return {
            "classification": "security_clue",
            "clue_type": "database_surface",
            "routes": ["db_surface", "sqli_review", "auth_boundary"],
            "disposition": "unresolved",
            "context_clues": context_clues,
        }

    if secret_type == "Twilio Account SID":
        return {
            "classification": "detector_signal",
            "clue_type": "possible_detector_issue",
            "routes": ["detector_review"],
            "disposition": "unresolved",
            "context_clues": context_clues,
        }

    if secret_type in {"RSA Private Key", "JWT Token"}:
        return {
            "classification": "secret_candidate",
            "clue_type": "crypto_or_auth_material",
            "routes": ["crypto_review", "reuse_check", "fixture_exposure"],
            "disposition": "unresolved",
            "context_clues": context_clues,
        }

    return {
        "classification": "secret_candidate",
        "clue_type": None,
        "routes": ["secret_validation"],
        "disposition": "unresolved",
        "context_clues": context_clues,
    }


def scan_file(file_path: Path, min_entropy: float = 3.5) -> list[Finding]:
    """Scan a single file for secrets using pattern matching + entropy."""
    findings = []
    try:
        content = file_path.read_text(errors="ignore")
        lines = content.splitlines()
    except (PermissionError, OSError, UnicodeDecodeError):
        return findings

    for line_num, line in enumerate(lines, 1):
        for secret_type, (pattern, confidence) in SECRET_PATTERNS.items():
            for match in re.finditer(pattern, line):
                matched_value = match.group(1) if match.lastindex else match.group(0)

                # Skip obvious placeholders
                if is_likely_placeholder(matched_value):
                    continue

                entropy = shannon_entropy(matched_value)

                # For generic patterns, require higher entropy threshold
                if secret_type == "Generic High-Entropy" and entropy < min_entropy:
                    continue

                context_lines = extract_context(lines, line_num)
                clue = classify_finding(secret_type, file_path, matched_value, context_lines)
                finding = Finding(
                    file=str(file_path),
                    line=line_num,
                    col=match.start(),
                    secret_type=secret_type,
                    match=matched_value,
                    entropy=round(entropy, 3),
                    pattern_confidence=confidence,
                    context_lines=context_lines,
                    classification=clue["classification"],
                    clue_type=clue["clue_type"],
                    routes=clue["routes"],
                    disposition=clue["disposition"],
                    context_clues=clue["context_clues"],
                )
                findings.append(finding)

    return findings


def scan_directory(
    target: str,
    min_entropy: float = 3.5,
    max_file_size_kb: int = 512,
    excludes: list[str] | None = None,
) -> list[Finding]:
    """Recursively scan a directory for secrets."""
    all_findings = []
    target_path = Path(target)
    excludes = excludes or []

    if target_path.is_file():
        target_str = str(target_path)
        if any(fragment in target_str for fragment in excludes):
            return []
        return scan_file(target_path, min_entropy)

    for root, dirs, files in os.walk(target_path):
        dirs[:] = [
            d for d in dirs
            if d not in IGNORE_DIRS
            and not any(fragment in str(Path(root) / d) for fragment in excludes)
        ]
        for fname in files:
            fp = Path(root) / fname
            if any(fragment in str(fp) for fragment in excludes):
                continue
            if fp.suffix.lower() in IGNORE_EXTENSIONS:
                continue
            if fp.stat().st_size > max_file_size_kb * 1024:
                continue
            all_findings.extend(scan_file(fp, min_entropy))

    return all_findings
