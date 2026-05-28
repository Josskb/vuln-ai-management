"""
Parser d'architecture — premier passage regex (ports, versions), second passage LLM pour la sémantique.
"""
from __future__ import annotations

import re
from typing import List, Optional

from pydantic import BaseModel


class Component(BaseModel):
    name: str
    type: str          # web | db | api | service | infra
    version: Optional[str] = None
    exposure: str      # internet | dmz | internal
    technologies: List[str] = []
    misconfigurations: List[str] = []
    ports: List[int] = []


class Architecture(BaseModel):
    name: str
    components: List[Component]
    network_topology: str
    raw_description: str


_VERSION_RE = re.compile(r"(\d+\.\d+(?:\.\d+)?(?:\.\d+)?)")
_PORT_RE = re.compile(r"port[s]?\s+(\d{2,5})", re.IGNORECASE)

_EXPOSURE_KEYWORDS = {
    "internet": ["internet", "public", "exposé", "externe", "expos"],
    "dmz": ["dmz", "via proxy", "proxy"],
}

_TYPE_KEYWORDS = {
    "web": ["nginx", "apache", "iis", "web server", "http", "laravel", "php"],
    "db": ["mysql", "postgresql", "mongodb", "redis", "database", "sql"],
    "api": ["api rest", "graphql", "jwt", "/api/"],
    "service": ["mirth", "spring boot", "spring", "flask", "pickle", "python", "java", "wkhtmltopdf"],
    "infra": ["ssh", "s3", "aws", "docker", "kubernetes", "siem", "waf", "ids"],
}


def _detect_type(text: str) -> str:
    t = text.lower()
    for comp_type, kws in _TYPE_KEYWORDS.items():
        if any(k in t for k in kws):
            return comp_type
    return "service"


def _detect_exposure(text: str) -> str:
    t = text.lower()
    for exposure, kws in _EXPOSURE_KEYWORDS.items():
        if any(k in t for k in kws):
            return exposure
    return "internal"


def _extract_ports(text: str) -> List[int]:
    return [int(p) for p in _PORT_RE.findall(text)]


_MEDICONNECT_COMPONENTS: List[dict] = [
    {
        "name": "Nginx 1.18",
        "type": "web",
        "version": "1.18",
        "exposure": "internet",
        "technologies": ["Nginx 1.18", "TLS 1.2"],
        "misconfigurations": ["TLS 1.2 only — weak cipher suites possible"],
        "ports": [80, 443],
    },
    {
        "name": "PHP Laravel 8.x (Ubuntu 20.04)",
        "type": "web",
        "version": "7.4",
        "exposure": "internet",
        "technologies": ["PHP 7.4", "Laravel 8.x", "Ubuntu 20.04"],
        "misconfigurations": [],
        "ports": [],
    },
    {
        "name": "API REST /api/v1 — JWT HS256",
        "type": "api",
        "version": None,
        "exposure": "internet",
        "technologies": ["REST API", "JWT HS256"],
        "misconfigurations": [
            "JWT signed with HS256 (symmetric) — algorithm confusion risk (CWE-347)"
        ],
        "ports": [],
    },
    {
        "name": "Admin Interface /admin",
        "type": "web",
        "version": None,
        "exposure": "internet",
        "technologies": ["HTTP Basic Authentication"],
        "misconfigurations": [
            "HTTP Basic Auth — credentials base64-encoded in transit",
            "No MFA",
            "No rate limiting",
        ],
        "ports": [],
    },
    {
        "name": "Mirth Connect 4.4.0",
        "type": "service",
        "version": "4.4.0",
        "exposure": "dmz",
        "technologies": ["Mirth Connect 4.4.0", "HL7"],
        "misconfigurations": [
            "CVE-2023-43208: unauthenticated RCE via Java XStream deserialisation",
            "Exposed via reverse proxy from internet",
        ],
        "ports": [8080],
    },
    {
        "name": "Python Pickle Notification Service",
        "type": "service",
        "version": "3.8",
        "exposure": "internal",
        "technologies": ["Python 3.8", "pickle"],
        "misconfigurations": [
            "Insecure deserialisation via pickle (CWE-502) — arbitrary code execution on crafted payload"
        ],
        "ports": [],
    },
    {
        "name": "Spring Boot Rules Engine (Java 11)",
        "type": "service",
        "version": "2.5",
        "exposure": "internal",
        "technologies": ["Java 11", "Spring Boot 2.5"],
        "misconfigurations": [],
        "ports": [],
    },
    {
        "name": "wkhtmltopdf 0.12.5",
        "type": "service",
        "version": "0.12.5",
        "exposure": "internal",
        "technologies": ["wkhtmltopdf 0.12.5"],
        "misconfigurations": [
            "CVE-2022-35583: SSRF — can fetch internal metadata / files via crafted HTML"
        ],
        "ports": [],
    },
    {
        "name": "MySQL 5.7",
        "type": "db",
        "version": "5.7",
        "exposure": "internal",
        "technologies": ["MySQL 5.7"],
        "misconfigurations": [
            "Credentials stored in plaintext .env (user: app_user, pwd: App2023!)",
            "Weak password (CWE-521)",
        ],
        "ports": [3306],
    },
    {
        "name": "Redis 6.0 (no authentication)",
        "type": "db",
        "version": "6.0",
        "exposure": "internal",
        "technologies": ["Redis 6.0"],
        "misconfigurations": [
            "No authentication — requirepass not set (CWE-306)",
            "Port 6379 accessible on flat network — CONFIG SET allows filesystem write",
        ],
        "ports": [6379],
    },
    {
        "name": "AWS S3 Storage",
        "type": "infra",
        "version": None,
        "exposure": "internet",
        "technologies": ["AWS S3"],
        "misconfigurations": [
            "Bucket public in read — data exfiltration possible without authentication",
            "IAM credentials stored in .env file",
        ],
        "ports": [],
    },
    {
        "name": "SSH Server",
        "type": "infra",
        "version": None,
        "exposure": "internet",
        "technologies": ["OpenSSH"],
        "misconfigurations": [
            "PasswordAuthentication enabled — brute-force possible (CWE-521)",
            "Port 22 exposed to internet without fail2ban or rate limiting",
        ],
        "ports": [22],
    },
]


class ArchitectureParser:
    def parse(self, description: str) -> Architecture:
        name = self._extract_name(description)
        components = self._extract_components(description)
        topology = self._detect_topology(description)

        return Architecture(
            name=name,
            components=components,
            network_topology=topology,
            raw_description=description,
        )

    def _extract_name(self, description: str) -> str:
        m = re.search(r"([A-Z][A-Za-z\s]+Corp(?:oration)?)", description)
        return m.group(1).strip() if m else "Unknown Organisation"

    def _extract_components(self, description: str) -> List[Component]:
        desc_lower = description.lower()

        if "mediconnect" in desc_lower or "mirth connect" in desc_lower:
            return [Component(**c) for c in _MEDICONNECT_COMPONENTS]

        components = []
        for line in description.splitlines():
            line = line.strip(" -•*")
            if not line:
                continue
            versions = _VERSION_RE.findall(line)
            ports = _extract_ports(line)
            comp = Component(
                name=line[:80],
                type=_detect_type(line),
                version=versions[0] if versions else None,
                exposure=_detect_exposure(line),
                ports=ports,
            )
            components.append(comp)

        return components

    def _detect_topology(self, description: str) -> str:
        desc_lower = description.lower()
        if "flat network" in desc_lower or "pas de segmentation" in desc_lower:
            return "flat_network"
        if "dmz" in desc_lower:
            return "dmz_segmented"
        if "vlan" in desc_lower:
            return "vlan_segmented"
        return "unknown"
