"""
╔══════════════════════════════════════════════════════════════╗
║  Mobile Analysis — APK/IPA Static Security Scanner          ║
╚══════════════════════════════════════════════════════════════╝
"""

import logging
import re
from typing import Any, Dict, List

logger = logging.getLogger("hydra.mobile")


class APKAnalyzer:
    """Static analysis for Android APK files."""

    MANIFEST_CHECKS = {
        "debuggable": {
            "pattern": r'android:debuggable\s*=\s*"true"',
            "severity": "high",
            "description": "App is debuggable in production",
        },
        "backup_enabled": {
            "pattern": r'android:allowBackup\s*=\s*"true"',
            "severity": "medium",
            "description": "Backup enabled — data extractable via adb",
        },
        "exported_activity": {
            "pattern": r'android:exported\s*=\s*"true"',
            "severity": "medium",
            "description": "Exported component accessible by other apps",
        },
        "cleartext_traffic": {
            "pattern": r'android:usesCleartextTraffic\s*=\s*"true"',
            "severity": "high",
            "description": "Cleartext HTTP traffic allowed",
        },
        "min_sdk_low": {
            "pattern": r'android:minSdkVersion\s*=\s*"(\d+)"',
            "severity": "medium",
            "description": "Low minimum SDK version — missing security patches",
        },
    }

    SECRET_PATTERNS = [
        (r'(?i)(api[_-]?key|apikey)\s*[:=]\s*["\'][A-Za-z0-9+/=]{16,}', "API Key"),
        (r'(?i)(secret|token|password)\s*[:=]\s*["\'][^"\']{8,}', "Secret/Token"),
        (r'(?i)firebase[a-z]*\.googleapis\.com', "Firebase URL"),
        (r'-----BEGIN (RSA )?PRIVATE KEY-----', "Private Key"),
        (r'(?i)AWS[A-Z0-9]{2,}\s*[:=]\s*["\'][A-Za-z0-9/+]{16,}', "AWS Credential"),
    ]

    def analyze_manifest(self, manifest_content: str) -> List[Dict]:
        findings = []
        for check_name, info in self.MANIFEST_CHECKS.items():
            if re.search(info["pattern"], manifest_content):
                findings.append({
                    "name": check_name, "severity": info["severity"],
                    "description": info["description"], "source": "AndroidManifest.xml",
                })
        return findings

    def scan_for_secrets(self, source_content: str) -> List[Dict]:
        findings = []
        for pattern, name in self.SECRET_PATTERNS:
            matches = re.findall(pattern, source_content)
            if matches:
                findings.append({
                    "name": f"Hardcoded {name}",
                    "severity": "high",
                    "count": len(matches),
                    "description": f"Found {len(matches)} potential {name}(s) in source",
                })
        return findings


class IPAAnalyzer:
    """Static analysis for iOS IPA files."""

    PLIST_CHECKS = {
        "ats_disabled": {
            "pattern": r"NSAllowsArbitraryLoads.*true",
            "severity": "high",
            "description": "App Transport Security disabled — allows HTTP",
        },
        "custom_url_schemes": {
            "pattern": r"CFBundleURLSchemes",
            "severity": "medium",
            "description": "Custom URL schemes — check for deep link hijacking",
        },
    }

    def analyze_plist(self, plist_content: str) -> List[Dict]:
        findings = []
        for check_name, info in self.PLIST_CHECKS.items():
            if re.search(info["pattern"], plist_content, re.IGNORECASE):
                findings.append({
                    "name": check_name, "severity": info["severity"],
                    "description": info["description"], "source": "Info.plist",
                })
        return findings
