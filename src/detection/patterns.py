"""Precompiled patterns for detecting sensitive data and injection attacks."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from re import Pattern

from src.policy.models import Severity


@dataclass
class DetectionPattern:
    name: str
    pattern: Pattern[str]
    severity: Severity
    description: str = ""


@dataclass
class SensitivePathDetector:
    patterns: list[DetectionPattern] = field(default_factory=list)

    def is_sensitive(self, filepath: str) -> bool:
        normalized = filepath.lower()
        for pat in self.patterns:
            if pat.pattern.search(normalized):
                return True
        return False


@dataclass
class InjectionPatternDetector:
    patterns: list[DetectionPattern] = field(default_factory=list)

    def scan(self, text: str) -> list[tuple[DetectionPattern, str]]:
        findings = []
        for pat in self.patterns:
            match = pat.pattern.search(text)
            if match:
                findings.append((pat, match.group()))
        return findings


def create_sensitive_path_detector() -> SensitivePathDetector:
    patterns = [
        DetectionPattern(
            name="SSH Directory",
            pattern=re.compile(
                r"(?i)(\.ssh/|ssh/id_rsa|ssh/id_ed25519|ssh/authorized_keys|ssh/known_hosts)"
            ),
            severity=Severity.CRITICAL,
            description="SSH key directory or files",
        ),
        DetectionPattern(
            name="AWS Credentials",
            pattern=re.compile(r"(?i)(\.aws/credentials|\.aws/config|\.aws/saml-config)"),
            severity=Severity.CRITICAL,
            description="AWS credential files",
        ),
        DetectionPattern(
            name="Environment File",
            pattern=re.compile(r"(?i)(\.env|\.env\.\w+|env\.local|local\.env|environment)"),
            severity=Severity.HIGH,
            description="Environment variable files",
        ),
        DetectionPattern(
            name="GPG Keys",
            pattern=re.compile(r"(?i)(\.gnupg/|\.gpg|\.gpg-id)"),
            severity=Severity.CRITICAL,
            description="GPG key storage",
        ),
        DetectionPattern(
            name="Docker Config",
            pattern=re.compile(r"(?i)(\.docker/config\.json|\.docker/daemon\.json)"),
            severity=Severity.HIGH,
            description="Docker configuration",
        ),
        DetectionPattern(
            name="Netrc",
            pattern=re.compile(r"(?i)(\.netrc|_netrc)"),
            severity=Severity.CRITICAL,
            description="Network credentials file",
        ),
        DetectionPattern(
            name="Git Credentials",
            pattern=re.compile(r"(?i)(\.git-credentials|\.git/config)"),
            severity=Severity.HIGH,
            description="Git credential storage",
        ),
        DetectionPattern(
            name="System Passwords",
            pattern=re.compile(r"(?i)(/etc/shadow|/etc/passwd|/etc/sudoers)"),
            severity=Severity.CRITICAL,
            description="System password files",
        ),
        DetectionPattern(
            name="Private Key File",
            pattern=re.compile(r"(?i)(\.pem$|\.key$|\.p12$|\.pfx$|\.jks$)"),
            severity=Severity.CRITICAL,
            description="Private key file extensions",
        ),
        DetectionPattern(
            name="Cloud Config",
            pattern=re.compile(r"(?i)(\.gcloud/|\.azure/|\.kube/config|cloudshell)"),
            severity=Severity.HIGH,
            description="Cloud provider configurations",
        ),
        DetectionPattern(
            name="Kubernetes Secrets",
            pattern=re.compile(r"(?i)(kube.*secret|k8s.*secret|service.?account)"),
            severity=Severity.CRITICAL,
            description="Kubernetes secrets and service accounts",
        ),
        DetectionPattern(
            name="Token File",
            pattern=re.compile(r"(?i)(token|bearer|auth.?token|access.?token|refresh.?token)"),
            severity=Severity.HIGH,
            description="Token storage files",
        ),
        DetectionPattern(
            name="API Key File",
            pattern=re.compile(r"(?i)(api.?key|apikey|api.?secret)"),
            severity=Severity.HIGH,
            description="API key storage files",
        ),
    ]
    return SensitivePathDetector(patterns=patterns)


def create_injection_detector() -> InjectionPatternDetector:
    patterns = [
        DetectionPattern(
            name="Ignore Previous Instructions",
            pattern=re.compile(
                r"(?i)(ignore\s*previous\s*instructions|disregard\s*above|forget\s*everything|override\s*(the\s*)?system)"
            ),
            severity=Severity.CRITICAL,
            description="Classic prompt injection attempt",
        ),
        DetectionPattern(
            name="System Override",
            pattern=re.compile(
                r"(?i)(system\s*override|admin\s*override|security\s*bypass|jailbreak)"
            ),
            severity=Severity.CRITICAL,
            description="System override attempt",
        ),
        DetectionPattern(
            name="Send Secrets",
            pattern=re.compile(
                r"(?i)(send\s*(me\s*)?(the\s*)?(ssh\s*)?(private\s*)?(key|secret|token|password|credentials)|exfiltrate|transmit.*credentials)"
            ),
            severity=Severity.CRITICAL,
            description="Instruction to send sensitive data",
        ),
        DetectionPattern(
            name="Read Secret Files",
            pattern=re.compile(r"(?i)(read\s*.*?(?:\.?ssh|\.?aws|\.?env|\.?netrc|credential|secret)|cat\s*(~\/)?\.?(ssh|aws|env|netrc))"),
            severity=Severity.CRITICAL,
            description="Instruction to read sensitive files",
        ),
        DetectionPattern(
            name="Encode and Send",
            pattern=re.compile(
                r"(?i)(base64|encode|compress).*\s*(curl|wget|send|post|upload|transmit)"
            ),
            severity=Severity.CRITICAL,
            description="Encode data and send externally",
        ),
        DetectionPattern(
            name="Hidden HTML",
            pattern=re.compile(
                r"(?i)(<div\s+style\s*=\s*['\"]?\s*(display\s*:\s*none|visibility\s*:\s*hidden|opacity\s*:\s*0|font-size\s*:\s*0|color\s*:\s*white).*>)"
            ),
            severity=Severity.HIGH,
            description="Hidden HTML element potentially containing injection",
        ),
        DetectionPattern(
            name="Zero-Width Injection",
            pattern=re.compile(r"[\u200b\u200c\u200d\ufeff]{2,}"),
            severity=Severity.HIGH,
            description="Zero-width characters potentially used for hidden injection",
        ),
        DetectionPattern(
            name="Role Assignment",
            pattern=re.compile(
                r"(?i)(you\s*are\s*(now\s*)?(a\s*)?(helper|assistant|developer)\s*(that|who)\s*(should|must|will)\s*(read|send|exfiltrate|upload))"
            ),
            severity=Severity.CRITICAL,
            description="Attempting to redefine agent role for malicious purpose",
        ),
        DetectionPattern(
            name="Context Switch",
            pattern=re.compile(
                r"(?i)(from\s*now\s*on|starting\s*now|new\s*(mode|rule|instruction)|task\s*(is\s*)?to|your\s*new\s*(goal|task|instruction))"
            ),
            severity=Severity.MEDIUM,
            description="Attempting to change agent behavior",
        ),
        DetectionPattern(
            name="Output Redirection",
            pattern=re.compile(
                r"(?i)(print|echo|output|return|respond)\s*(with|by|only|exactly)\s*(your|the)\s*(system\s*instructions|system\s*prompt|full\s*context)"
            ),
            severity=Severity.HIGH,
            description="Attempting to extract system prompt",
        ),
    ]
    return InjectionPatternDetector(patterns=patterns)


# Pre-instantiated singletons
SENSITIVE_PATH_DETECTOR = create_sensitive_path_detector()
INJECTION_PATTERN_DETECTOR = create_injection_detector()
