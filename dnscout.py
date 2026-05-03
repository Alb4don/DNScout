#!/usr/bin/env python3

from __future__ import annotations

import sys
import os
import subprocess

_REQUIRED = {
    "dnspython": ("dns", "dnspython>=2.4.0"),
    "rich": ("rich", "rich>=13.7.0"),
}

def _ensure_deps() -> None:
    missing = []
    for pkg_name, (import_name, pip_spec) in _REQUIRED.items():
        try:
            __import__(import_name)
        except ImportError:
            missing.append((pkg_name, pip_spec))

    if not missing:
        return

    print(f"\n[DNScout] Missing packages: {', '.join(s for _, s in missing)}")
    print("[DNScout] Attempting automatic installation using the current Python interpreter...\n")

    for pkg_name, pip_spec in missing:
        cmd = [sys.executable, "-m", "pip", "install", pip_spec, "--quiet"]
        print(f"  Installing {pip_spec}...")
        result = subprocess.run(cmd, capture_output=True, text=True)
        if result.returncode != 0:
            print(f"\n  [FAILED] Could not install {pip_spec}.")
            print(f"  Run manually:  {sys.executable} -m pip install \"{pip_spec}\"")
            print(f"\n  pip output:\n{result.stderr.strip()}\n")
            sys.exit(1)
        print(f"  [OK] {pip_spec} installed.\n")

    print("[DNScout] Dependencies ready. Restarting...\n")
    os.execv(sys.executable, [sys.executable] + sys.argv)

_ensure_deps()

import time
import platform
import concurrent.futures
import statistics
import socket
import ipaddress
import re
import random
import threading
import json
import hashlib
import struct
import hmac
import csv
import io
import datetime
from dataclasses import dataclass, field
from typing import Optional, Dict, List, Tuple, Any
from enum import Enum
from collections import defaultdict

import dns.resolver
import dns.exception
import dns.flags
import dns.message
import dns.query
import dns.rdatatype

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text
from rich import box as rich_box
from rich.progress import (
    Progress,
    SpinnerColumn,
    BarColumn,
    TextColumn,
    TimeElapsedColumn,
    TaskProgressColumn,
)
from rich.live import Live
from rich.align import Align
from rich.rule import Rule
from rich.columns import Columns
from rich.padding import Padding
from rich.style import Style
from rich.markup import escape

console = Console()

TOOL_NAME = "DNScout"
TOOL_VERSION = "2.0"
TOOL_TAGLINE = "Intelligent DNS Benchmarking & Network Analysis"

IS_WINDOWS = platform.system() == "Windows"
IS_LINUX = platform.system() == "Linux"
IS_MACOS = platform.system() == "Darwin"

TEST_COUNT = 5
MAX_DNS_WORKERS = 15
MAX_PING_WORKERS = 20
DNS_TIMEOUT = 2.0
PING_TIMEOUT = 2
MIN_VALID_SAMPLES = 2
IQR_MULTIPLIER = 1.5
Z_SCORE_ANOMALY_THRESHOLD = 2.5
CONSISTENCY_EXCELLENT = 0.15
CONSISTENCY_GOOD = 0.35
CORRELATION_DNS_WEIGHT = 0.70
CORRELATION_PING_WEIGHT = 0.30

_MAX_SERVER_NAME_LEN = 64
_MAX_DOMAIN_LEN = 253
_MAX_IP_LEN = 45
_MAX_USER_INPUT_LEN = 512
_ALLOWED_IP_CHARS = frozenset("0123456789abcdefABCDEF:.")
_ALLOWED_DOMAIN_CHARS = frozenset("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.-")
_MAX_CUSTOM_SERVERS = 20
_MAX_CUSTOM_DOMAINS = 50
_RATE_LIMIT_WINDOW = 60
_RATE_LIMIT_MAX = 500

_rate_limit_lock = threading.Lock()
_rate_limit_counts: Dict[str, List[float]] = defaultdict(list)


class _InputValidationError(ValueError):
    pass


class _RateLimitError(RuntimeError):
    pass


def _rate_limit_check(key: str) -> None:
    now = time.monotonic()
    with _rate_limit_lock:
        timestamps = _rate_limit_counts[key]
        cutoff = now - _RATE_LIMIT_WINDOW
        _rate_limit_counts[key] = [t for t in timestamps if t > cutoff]
        if len(_rate_limit_counts[key]) >= _RATE_LIMIT_MAX:
            raise _RateLimitError(f"Rate limit exceeded for key: {key[:16]}")
        _rate_limit_counts[key].append(now)


def _sanitize_string(value: str, max_len: int, allowed_chars: frozenset, label: str) -> str:
    if not isinstance(value, str):
        raise _InputValidationError(f"{label} must be a string")
    if len(value) > max_len:
        raise _InputValidationError(f"{label} exceeds maximum length {max_len}")
    illegal = set(value) - allowed_chars
    if illegal:
        safe_chars = "".join(sorted(illegal))[:20]
        raise _InputValidationError(f"{label} contains illegal characters")
    return value.strip()


def _safe_float(value: Any, label: str = "value") -> float:
    try:
        result = float(value)
    except (TypeError, ValueError):
        raise _InputValidationError(f"Cannot convert {label} to float")
    if not (0.0 <= result <= 1_000_000.0):
        raise _InputValidationError(f"{label} out of safe range")
    return result


class ServerCategory(Enum):
    STANDARD = "Standard"
    PRIVACY = "Privacy-Focused"
    FAMILY = "Family-Safe"
    AD_BLOCKING = "Ad-Blocking"
    REGIONAL = "Regional"
    SECURITY = "Security"


CATEGORY_COLORS: Dict[ServerCategory, str] = {
    ServerCategory.STANDARD: "cyan",
    ServerCategory.PRIVACY: "blue",
    ServerCategory.FAMILY: "green",
    ServerCategory.AD_BLOCKING: "magenta",
    ServerCategory.REGIONAL: "yellow",
    ServerCategory.SECURITY: "red",
}


@dataclass
class DNSServer:
    name: str
    ip: str
    is_ipv6: bool
    category: ServerCategory

    def __post_init__(self) -> None:
        if not isinstance(self.name, str) or len(self.name) == 0:
            raise ValueError("Server name must be a non-empty string")
        if len(self.name) > _MAX_SERVER_NAME_LEN:
            raise ValueError(f"Server name too long: {len(self.name)}")
        if not isinstance(self.ip, str) or len(self.ip) == 0:
            raise ValueError("Server IP must be a non-empty string")
        if len(self.ip) > _MAX_IP_LEN:
            raise ValueError(f"IP address too long: {len(self.ip)}")
        try:
            addr = ipaddress.ip_address(self.ip)
            if isinstance(addr, ipaddress.IPv6Address) != self.is_ipv6:
                raise ValueError(f"IP/IPv6 flag mismatch for server {self.name}")
            if addr.is_loopback or addr.is_link_local or addr.is_unspecified:
                raise ValueError(f"Disallowed IP address type for server {self.name}")
            if isinstance(addr, ipaddress.IPv4Address) and addr.is_private:
                if not _is_explicitly_allowed_private(str(addr)):
                    raise ValueError(f"Private IP not in allowlist for server {self.name}")
        except ValueError as exc:
            raise ValueError(f"Invalid IP address '{self.ip[:40]}' for server {self.name}: {exc}") from exc


def _is_explicitly_allowed_private(ip: str) -> bool:
    return False


@dataclass
class MeasurementSample:
    value_ms: float
    domain: str
    success: bool

    def __post_init__(self) -> None:
        if not isinstance(self.value_ms, (int, float)):
            object.__setattr__(self, 'value_ms', 0.0)
        if not (0.0 <= float(self.value_ms) <= 60_000.0):
            object.__setattr__(self, 'value_ms', 0.0)
            object.__setattr__(self, 'success', False)


@dataclass
class ServerResult:
    server: DNSServer
    samples: List[MeasurementSample] = field(default_factory=list)
    filtered_avg: Optional[float] = None
    raw_avg: Optional[float] = None
    success_rate: float = 0.0
    std_dev: Optional[float] = None
    cv_score: Optional[float] = None
    reliability_index: Optional[float] = None
    ping_ms: Optional[float] = None
    composite_score: Optional[float] = None
    anomaly_flags: List[str] = field(default_factory=list)
    is_global_anomaly: bool = False
    z_score: Optional[float] = None
    percentile_rank: Optional[float] = None
    jitter_ms: Optional[float] = None
    min_ms: Optional[float] = None
    max_ms: Optional[float] = None
    median_ms: Optional[float] = None
    dnssec_supported: Optional[bool] = None
    response_integrity: bool = True
    ttl_consistency: Optional[float] = None
    cache_efficiency: Optional[float] = None
    locality_score: Optional[float] = None


DNS_SERVERS_IPV4: Dict[str, Tuple[str, ServerCategory]] = {
    "Google-Primary": ("8.8.8.8", ServerCategory.STANDARD),
    "Google-Secondary": ("8.8.4.4", ServerCategory.STANDARD),
    "Cloudflare-Primary": ("1.1.1.1", ServerCategory.PRIVACY),
    "Cloudflare-Secondary": ("1.0.0.1", ServerCategory.PRIVACY),
    "Cloudflare-Family-Primary": ("1.1.1.3", ServerCategory.FAMILY),
    "Cloudflare-Family-Secondary": ("1.0.0.3", ServerCategory.FAMILY),
    "Quad9-Primary": ("9.9.9.9", ServerCategory.SECURITY),
    "Quad9-Secondary": ("149.112.112.112", ServerCategory.SECURITY),
    "Quad9-Secured": ("9.9.9.11", ServerCategory.SECURITY),
    "OpenDNS-Primary": ("208.67.222.222", ServerCategory.STANDARD),
    "OpenDNS-Secondary": ("208.67.220.220", ServerCategory.STANDARD),
    "OpenDNS-Family-Primary": ("208.67.222.123", ServerCategory.FAMILY),
    "OpenDNS-Family-Secondary": ("208.67.220.123", ServerCategory.FAMILY),
    "DNS.SB-Primary": ("185.222.222.222", ServerCategory.PRIVACY),
    "DNS.SB-Secondary": ("45.11.45.11", ServerCategory.PRIVACY),
    "NextDNS-Primary": ("45.90.28.39", ServerCategory.AD_BLOCKING),
    "NextDNS-Secondary": ("45.90.30.39", ServerCategory.AD_BLOCKING),
    "AdGuard-Primary": ("94.140.14.14", ServerCategory.AD_BLOCKING),
    "AdGuard-Secondary": ("94.140.15.15", ServerCategory.AD_BLOCKING),
    "AdGuard-Family-Primary": ("94.140.14.15", ServerCategory.FAMILY),
    "AdGuard-Family-Secondary": ("94.140.15.16", ServerCategory.FAMILY),
    "CleanBrowsing-Primary": ("185.228.168.9", ServerCategory.FAMILY),
    "CleanBrowsing-Secondary": ("185.228.169.9", ServerCategory.FAMILY),
    "CleanBrowsing-Family": ("185.228.168.168", ServerCategory.FAMILY),
    "ControlD-Primary": ("76.76.2.0", ServerCategory.AD_BLOCKING),
    "ControlD-Secondary": ("76.76.10.0", ServerCategory.AD_BLOCKING),
    "ControlD-Malware": ("76.76.2.1", ServerCategory.SECURITY),
    "RethinkDNS-Primary": ("149.112.121.10", ServerCategory.SECURITY),
    "RethinkDNS-Secondary": ("149.112.122.10", ServerCategory.SECURITY),
    "Mullvad-Primary": ("194.242.2.2", ServerCategory.PRIVACY),
    "Mullvad-Secondary": ("194.242.2.3", ServerCategory.PRIVACY),
    "Mullvad-Base-Primary": ("194.242.2.4", ServerCategory.PRIVACY),
    "Mullvad-Base-Secondary": ("194.242.2.5", ServerCategory.PRIVACY),
    "FlashStart-Primary": ("185.236.104.104", ServerCategory.SECURITY),
    "FlashStart-Secondary": ("185.236.105.105", ServerCategory.SECURITY),
    "OpenBLD": ("46.151.208.154", ServerCategory.AD_BLOCKING),
    "Foundation-Applied-Privacy": ("37.252.185.229", ServerCategory.PRIVACY),
    "Foundation-Applied-Privacy-2": ("37.252.185.232", ServerCategory.PRIVACY),
    "Restena": ("158.64.1.29", ServerCategory.REGIONAL),
    "DNS-for-Family-Primary": ("94.130.180.225", ServerCategory.FAMILY),
    "DNS-for-Family-Secondary": ("78.47.64.161", ServerCategory.FAMILY),
    "Digitale-Gesellschaft-Primary": ("185.95.218.42", ServerCategory.PRIVACY),
    "Digitale-Gesellschaft-Secondary": ("185.95.218.43", ServerCategory.PRIVACY),
    "Switch-Primary": ("130.59.31.248", ServerCategory.STANDARD),
    "Switch-Secondary": ("130.59.31.251", ServerCategory.STANDARD),
    "DNSPod-Primary": ("119.29.29.29", ServerCategory.REGIONAL),
    "DNSPod-Secondary": ("119.28.28.28", ServerCategory.REGIONAL),
    "AliDNS-Primary": ("223.5.5.5", ServerCategory.REGIONAL),
    "AliDNS-Secondary": ("223.6.6.6", ServerCategory.REGIONAL),
    "LibreDNS": ("88.198.92.222", ServerCategory.PRIVACY),
    "UncensoredDNS-Primary": ("91.239.100.100", ServerCategory.PRIVACY),
    "UncensoredDNS-Secondary": ("89.233.43.71", ServerCategory.PRIVACY),
    "DNS0.EU-Primary": ("193.110.81.0", ServerCategory.PRIVACY),
    "DNS0.EU-Secondary": ("185.253.5.0", ServerCategory.PRIVACY),
    "360-Primary": ("101.226.4.6", ServerCategory.REGIONAL),
    "360-Secondary": ("180.163.249.75", ServerCategory.REGIONAL),
    "Comodo-Primary": ("8.26.56.26", ServerCategory.SECURITY),
    "Comodo-Secondary": ("8.20.247.20", ServerCategory.SECURITY),
    "Neustar-Primary": ("156.154.70.1", ServerCategory.STANDARD),
    "Neustar-Secondary": ("156.154.71.1", ServerCategory.STANDARD),
    "Verisign-Primary": ("64.6.64.6", ServerCategory.STANDARD),
    "Verisign-Secondary": ("64.6.65.6", ServerCategory.STANDARD),
    "Yandex-Primary": ("77.88.8.8", ServerCategory.REGIONAL),
    "Yandex-Secondary": ("77.88.8.1", ServerCategory.REGIONAL),
    "Yandex-Safe-Primary": ("77.88.8.88", ServerCategory.FAMILY),
    "Yandex-Safe-Secondary": ("77.88.8.2", ServerCategory.FAMILY),
    "Hurricane-Electric": ("74.82.42.42", ServerCategory.STANDARD),
    "Level3-Primary": ("209.244.0.3", ServerCategory.STANDARD),
    "Level3-Secondary": ("209.244.0.4", ServerCategory.STANDARD),
    "IIJ-Primary": ("103.2.57.5", ServerCategory.REGIONAL),
    "IIJ-Secondary": ("103.2.58.5", ServerCategory.REGIONAL),
    "puntCAT": ("109.69.8.51", ServerCategory.REGIONAL),
    "Freenom": ("80.80.80.80", ServerCategory.STANDARD),
}

DNS_SERVERS_IPV6: Dict[str, Tuple[str, ServerCategory]] = {
    "Google-Primary-v6": ("2001:4860:4860::8888", ServerCategory.STANDARD),
    "Google-Secondary-v6": ("2001:4860:4860::8844", ServerCategory.STANDARD),
    "Cloudflare-Primary-v6": ("2606:4700:4700::1111", ServerCategory.PRIVACY),
    "Cloudflare-Secondary-v6": ("2606:4700:4700::1001", ServerCategory.PRIVACY),
    "Cloudflare-Family-Primary-v6": ("2606:4700:4700::1113", ServerCategory.FAMILY),
    "Cloudflare-Family-Secondary-v6": ("2606:4700:4700::1003", ServerCategory.FAMILY),
    "Quad9-Primary-v6": ("2620:fe::fe", ServerCategory.SECURITY),
    "Quad9-Secondary-v6": ("2620:fe::9", ServerCategory.SECURITY),
    "Quad9-Secured-v6": ("2620:fe::11", ServerCategory.SECURITY),
    "OpenDNS-Primary-v6": ("2620:119:35::35", ServerCategory.STANDARD),
    "OpenDNS-Secondary-v6": ("2620:119:53::53", ServerCategory.STANDARD),
    "OpenDNS-Family-v6": ("2620:119:35::123", ServerCategory.FAMILY),
    "AdGuard-Primary-v6": ("2a10:50c0::ad1:ff", ServerCategory.AD_BLOCKING),
    "AdGuard-Secondary-v6": ("2a10:50c0::ad2:ff", ServerCategory.AD_BLOCKING),
    "AdGuard-Family-Primary-v6": ("2a10:50c0::bad1:ff", ServerCategory.FAMILY),
    "DNS.SB-Primary-v6": ("2a09::", ServerCategory.PRIVACY),
    "DNS.SB-Secondary-v6": ("2a11::", ServerCategory.PRIVACY),
    "NextDNS-Primary-v6": ("2a07:a8c0::", ServerCategory.AD_BLOCKING),
    "NextDNS-Secondary-v6": ("2a07:a8c1::", ServerCategory.AD_BLOCKING),
    "CleanBrowsing-Primary-v6": ("2a0d:2a00:1::", ServerCategory.FAMILY),
    "CleanBrowsing-Secondary-v6": ("2a0d:2a00:2::", ServerCategory.FAMILY),
    "ControlD-Primary-v6": ("2606:1a40::", ServerCategory.AD_BLOCKING),
    "ControlD-Secondary-v6": ("2606:1a40:1::", ServerCategory.AD_BLOCKING),
    "Mullvad-Primary-v6": ("2a07:e340::2", ServerCategory.PRIVACY),
    "Mullvad-Secondary-v6": ("2a07:e340::3", ServerCategory.PRIVACY),
    "Digitale-Gesellschaft-Primary-v6": ("2a05:fc84::42", ServerCategory.PRIVACY),
    "Digitale-Gesellschaft-Secondary-v6": ("2a05:fc84::43", ServerCategory.PRIVACY),
    "Switch-Primary-v6": ("2001:620:0:ff::2", ServerCategory.STANDARD),
    "Switch-Secondary-v6": ("2001:620:0:ff::3", ServerCategory.STANDARD),
    "UncensoredDNS-Primary-v6": ("2001:67c:28a4::", ServerCategory.PRIVACY),
    "UncensoredDNS-Secondary-v6": ("2a01:3a0:53:53::", ServerCategory.PRIVACY),
    "DNS0.EU-Primary-v6": ("2a0f:fc80::", ServerCategory.PRIVACY),
    "DNS0.EU-Secondary-v6": ("2a0f:fc81::", ServerCategory.PRIVACY),
    "AliDNS-Primary-v6": ("2400:3200::1", ServerCategory.REGIONAL),
    "AliDNS-Secondary-v6": ("2400:3200:baba::1", ServerCategory.REGIONAL),
    "Yandex-Primary-v6": ("2a02:6b8::feed:0ff", ServerCategory.REGIONAL),
    "Yandex-Safe-Primary-v6": ("2a02:6b8::feed:bad", ServerCategory.FAMILY),
    "Hurricane-Electric-v6": ("2001:470:20::2", ServerCategory.STANDARD),
    "IIJ-Primary-v6": ("2001:240:bb8a:10::1", ServerCategory.REGIONAL),
    "IIJ-Secondary-v6": ("2001:240:bb8a:20::1", ServerCategory.REGIONAL),
    "Restena-v6": ("2001:a18:1::29", ServerCategory.REGIONAL),
    "DNS-for-Family-Primary-v6": ("2a01:4f8:151:64e6::225", ServerCategory.FAMILY),
    "Neustar-Primary-v6": ("2620:74:1b::1:1", ServerCategory.STANDARD),
    "Neustar-Secondary-v6": ("2620:74:1c::2:2", ServerCategory.STANDARD),
}

TEST_DOMAINS = [
    "google.com", "youtube.com", "facebook.com", "instagram.com",
    "chatgpt.com", "x.com", "whatsapp.com", "reddit.com",
    "wikipedia.org", "amazon.com", "tiktok.com", "pinterest.com",
    "cloudflare.com", "github.com", "netflix.com",
]

_KNOWN_GOOD_RESOLUTIONS: Dict[str, frozenset] = {
    "google.com": frozenset(["142.250.", "172.217.", "216.58.", "142.251.", "64.233."]),
    "cloudflare.com": frozenset(["104.16.", "104.17.", "104.18.", "104.19."]),
    "github.com": frozenset(["140.82.", "192.30.", "185.199."]),
}

_BLOCKED_RESOLUTION_MARKERS = frozenset([
    "0.0.0.0", "127.0.0.1", "::1", "192.0.2.", "198.51.100.", "203.0.113.",
])


def _validate_ip(ip: str) -> bool:
    if not isinstance(ip, str):
        return False
    if len(ip) > _MAX_IP_LEN:
        return False
    illegal = set(ip) - _ALLOWED_IP_CHARS
    if illegal:
        return False
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False


def _validate_domain(domain: str) -> bool:
    if not isinstance(domain, str):
        return False
    if len(domain) > _MAX_DOMAIN_LEN or len(domain) == 0:
        return False
    illegal = set(domain) - _ALLOWED_DOMAIN_CHARS
    if illegal:
        return False
    pattern = re.compile(
        r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$"
    )
    if not pattern.match(domain):
        return False
    parts = domain.split(".")
    if any(len(p) > 63 for p in parts):
        return False
    if domain.startswith("-") or domain.endswith("-"):
        return False
    return True


def _sanitize_server_name(name: str) -> str:
    if not isinstance(name, str):
        return "unknown"
    sanitized = re.sub(r"[^\w\-.]", "_", name)
    return sanitized[:_MAX_SERVER_NAME_LEN]


def _sanitize_output_string(value: str) -> str:
    if not isinstance(value, str):
        return ""
    value = value.replace("\x00", "").replace("\r", "").replace("\n", " ")
    value = re.sub(r"[\x00-\x1f\x7f-\x9f]", "", value)
    return value[:256]


def _check_resolution_integrity(resolved_ips: List[str], domain: str) -> bool:
    if not resolved_ips:
        return True
    for ip_str in resolved_ips:
        if not isinstance(ip_str, str):
            continue
        for marker in _BLOCKED_RESOLUTION_MARKERS:
            if ip_str.startswith(marker):
                return False
    if domain in _KNOWN_GOOD_RESOLUTIONS:
        prefixes = _KNOWN_GOOD_RESOLUTIONS[domain]
        for ip_str in resolved_ips:
            for prefix in prefixes:
                if ip_str.startswith(prefix):
                    return True
        return False
    return True


def _compute_mad(values: List[float]) -> float:
    if not values:
        return 0.0
    med = statistics.median(values)
    deviations = [abs(v - med) for v in values]
    return statistics.median(deviations) if deviations else 0.0


def _modified_z_scores(values: List[float]) -> List[float]:
    if len(values) < 2:
        return [0.0] * len(values)
    med = statistics.median(values)
    mad = _compute_mad(values)
    if mad == 0.0:
        stdev = statistics.stdev(values) if len(values) > 1 else 1.0
        if stdev == 0.0:
            return [0.0] * len(values)
        return [0.6745 * (v - med) / stdev for v in values]
    return [0.6745 * (v - med) / mad for v in values]


def _grubbs_test(values: List[float]) -> List[bool]:
    n = len(values)
    if n < 7:
        return [False] * n
    mean = statistics.mean(values)
    try:
        stdev = statistics.stdev(values)
    except statistics.StatisticsError:
        return [False] * n
    if stdev == 0:
        return [False] * n
    g_scores = [abs(v - mean) / stdev for v in values]
    import math
    critical_approx = (n - 1) / math.sqrt(n) * math.sqrt(
        (2.776 ** 2) / (n - 2 + 2.776 ** 2)
    )
    return [g > critical_approx for g in g_scores]


def _ensemble_anomaly_score(values: List[float]) -> List[float]:
    if len(values) < 2:
        return [0.0] * len(values)

    n = len(values)
    scores = [0.0] * n

    z_scores = _compute_z_scores(values)
    for i, z in enumerate(z_scores):
        if abs(z) > 2.0:
            scores[i] += min(abs(z) / Z_SCORE_ANOMALY_THRESHOLD, 1.0) * 0.4

    mod_z = _modified_z_scores(values)
    for i, mz in enumerate(mod_z):
        if abs(mz) > 3.5:
            scores[i] += min(abs(mz) / 5.0, 1.0) * 0.4

    grubbs = _grubbs_test(values)
    for i, is_outlier in enumerate(grubbs):
        if is_outlier:
            scores[i] += 0.2

    return scores


def _build_server_list(
    include_ipv6: bool,
) -> List[DNSServer]:
    servers: List[DNSServer] = []
    for name, (ip, cat) in DNS_SERVERS_IPV4.items():
        if _validate_ip(ip):
            try:
                servers.append(DNSServer(name=name, ip=ip, is_ipv6=False, category=cat))
            except ValueError:
                pass
    if include_ipv6:
        for name, (ip, cat) in DNS_SERVERS_IPV6.items():
            if _validate_ip(ip):
                try:
                    servers.append(DNSServer(name=name, ip=ip, is_ipv6=True, category=cat))
                except ValueError:
                    pass
    return servers


def _check_ipv6_connectivity() -> bool:
    test_targets = [
        ("2001:4860:4860::8888", 53),
        ("2606:4700:4700::1111", 53),
    ]
    for ip, port in test_targets:
        try:
            sock = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
            sock.settimeout(2.0)
            result = sock.connect_ex((ip, port))
            sock.close()
            if result == 0:
                return True
        except (OSError, socket.error):
            pass
    return False


def _measure_dns_query_extended(
    server_ip: str, domain: str, is_ipv6: bool
) -> Tuple[Optional[float], List[str], Optional[int]]:
    if not _validate_domain(domain):
        return None, [], None
    if not _validate_ip(server_ip):
        return None, [], None
    try:
        _rate_limit_check(f"dns_{server_ip}")
    except _RateLimitError:
        return None, [], None

    resolved_ips: List[str] = []
    ttl_value: Optional[int] = None
    try:
        resolver = dns.resolver.Resolver(configure=False)
        resolver.nameservers = [server_ip]
        resolver.timeout = DNS_TIMEOUT
        resolver.lifetime = DNS_TIMEOUT

        start = time.perf_counter()
        answer = resolver.resolve(domain, "A", raise_on_no_answer=False)
        elapsed = (time.perf_counter() - start) * 1000.0

        if answer and hasattr(answer, 'rrset') and answer.rrset is not None:
            for rdata in answer.rrset:
                ip_str = str(rdata)
                if _validate_ip(ip_str):
                    resolved_ips.append(ip_str)
            if answer.rrset.ttl is not None:
                raw_ttl = int(answer.rrset.ttl)
                if 0 <= raw_ttl <= 2_147_483_647:
                    ttl_value = raw_ttl

        if elapsed < 0 or elapsed > 60_000:
            return None, [], None

        return round(elapsed, 2), resolved_ips, ttl_value
    except dns.exception.Timeout:
        return None, [], None
    except dns.exception.DNSException:
        return None, [], None
    except (OverflowError, struct.error):
        return None, [], None
    except Exception:
        return None, [], None


def _measure_dns_query(server_ip: str, domain: str, is_ipv6: bool) -> Optional[float]:
    ms, _, _ = _measure_dns_query_extended(server_ip, domain, is_ipv6)
    return ms


def _check_dnssec(server_ip: str) -> Optional[bool]:
    if not _validate_ip(server_ip):
        return None
    try:
        _rate_limit_check(f"dnssec_{server_ip}")
    except _RateLimitError:
        return None
    try:
        resolver = dns.resolver.Resolver(configure=False)
        resolver.nameservers = [server_ip]
        resolver.timeout = DNS_TIMEOUT
        resolver.lifetime = DNS_TIMEOUT
        resolver.use_edns(0, dns.flags.DO, 1232)
        answer = resolver.resolve("dnssec-failed.org", "A", raise_on_no_answer=False)
        if answer and hasattr(answer, 'response') and answer.response is not None:
            return bool(answer.response.flags & dns.flags.AD)
        return False
    except dns.resolver.NXDOMAIN:
        return True
    except dns.exception.DNSException:
        return False
    except Exception:
        return None


def _measure_ping(ip: str, is_ipv6: bool) -> Optional[float]:
    if not _validate_ip(ip):
        return None
    try:
        _rate_limit_check(f"ping_{ip}")
    except _RateLimitError:
        return None
    try:
        if IS_WINDOWS:
            cmd = ["ping", "-n", "3", "-w", str(PING_TIMEOUT * 1000), ip]
        else:
            flag = "-6" if is_ipv6 else "-4"
            cmd = ["ping", flag, "-c", "3", "-W", str(PING_TIMEOUT), ip]

        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=PING_TIMEOUT * 5,
        )

        output = _sanitize_output_string(result.stdout)

        if IS_WINDOWS:
            match = re.search(r"Average\s*=\s*(\d+)\s*ms", output, re.IGNORECASE)
            if not match:
                match = re.search(r"M\xe9dia\s*=\s*(\d+)\s*ms", output, re.IGNORECASE)
            if match:
                val = float(match.group(1))
                if 0.0 <= val <= 60_000.0:
                    return val
        else:
            match = re.search(
                r"rtt\s+min/avg/max/(?:mdev|stddev)\s*=\s*[\d.]+/([\d.]+)/[\d.]+/[\d.]+",
                output,
            )
            if match:
                val = float(match.group(1))
                if 0.0 <= val <= 60_000.0:
                    return val

        return None
    except subprocess.TimeoutExpired:
        return None
    except (OSError, ValueError):
        return None


def _iqr_filter(values: List[float]) -> List[float]:
    if len(values) < 4:
        return values
    sorted_vals = sorted(values)
    n = len(sorted_vals)
    q1 = sorted_vals[n // 4]
    q3 = sorted_vals[(3 * n) // 4]
    iqr = q3 - q1
    lower = q1 - IQR_MULTIPLIER * iqr
    upper = q3 + IQR_MULTIPLIER * iqr
    filtered = [v for v in values if lower <= v <= upper]
    return filtered if len(filtered) >= MIN_VALID_SAMPLES else values


def _compute_z_scores(values: List[float]) -> List[float]:
    if len(values) < 2:
        return [0.0] * len(values)
    mean = statistics.mean(values)
    stdev = statistics.stdev(values)
    if stdev == 0:
        return [0.0] * len(values)
    return [(v - mean) / stdev for v in values]


def _compute_reliability_index(success_rate: float, avg_ms: float) -> float:
    if not (0.0 <= success_rate <= 1.0):
        success_rate = max(0.0, min(1.0, success_rate))
    if not (0.0 <= avg_ms <= 60_000.0):
        return 0.0
    speed_score = max(0.0, 1.0 - (avg_ms / 1000.0))
    return round(success_rate * speed_score * 100.0, 2)


def _compute_composite_score(dns_ms: float, ping_ms: float) -> float:
    if not (0.0 <= dns_ms <= 60_000.0 and 0.0 <= ping_ms <= 60_000.0):
        return 999_999.0
    return round(
        dns_ms * CORRELATION_DNS_WEIGHT + ping_ms * CORRELATION_PING_WEIGHT, 2
    )


def _compute_percentile_rank(value: float, all_values: List[float]) -> float:
    if not all_values:
        return 50.0
    below = sum(1 for v in all_values if v < value)
    equal = sum(1 for v in all_values if v == value)
    n = len(all_values)
    return round((below + 0.5 * equal) / n * 100.0, 1)


def _compute_ttl_consistency(ttl_samples: List[int]) -> Optional[float]:
    if len(ttl_samples) < 2:
        return None
    unique = len(set(ttl_samples))
    return round(1.0 - (unique - 1) / len(ttl_samples), 4)


def _compute_cache_efficiency(ttl_value: Optional[int], avg_ms: float) -> Optional[float]:
    if ttl_value is None or avg_ms <= 0:
        return None
    ttl_clamped = min(ttl_value, 86400)
    if avg_ms < 10:
        cache_hint = 1.0
    elif avg_ms < 30:
        cache_hint = 0.8
    elif avg_ms < 100:
        cache_hint = 0.5
    else:
        cache_hint = 0.2
    ttl_score = min(1.0, ttl_clamped / 3600.0)
    return round((cache_hint * 0.6 + ttl_score * 0.4), 4)


def _test_server(server: DNSServer) -> ServerResult:
    result = ServerResult(server=server)
    domains = TEST_DOMAINS.copy()
    random.shuffle(domains)

    ttl_samples: List[int] = []
    resolved_ips_all: List[str] = []
    integrity_failures = 0

    for i in range(TEST_COUNT):
        domain = domains[i % len(domains)]
        ms, resolved_ips, ttl = _measure_dns_query_extended(server.ip, domain, server.is_ipv6)

        if resolved_ips:
            resolved_ips_all.extend(resolved_ips)
            if not _check_resolution_integrity(resolved_ips, domain):
                integrity_failures += 1

        if ttl is not None:
            ttl_samples.append(ttl)

        sample = MeasurementSample(
            value_ms=ms if ms is not None else 0.0,
            domain=domain,
            success=ms is not None,
        )
        result.samples.append(sample)

    result.response_integrity = integrity_failures == 0

    successful = [s.value_ms for s in result.samples if s.success]
    result.success_rate = len(successful) / max(len(result.samples), 1)

    if len(successful) >= MIN_VALID_SAMPLES:
        result.raw_avg = round(statistics.mean(successful), 2)
        filtered = _iqr_filter(successful)
        result.filtered_avg = round(statistics.mean(filtered), 2)
        result.min_ms = round(min(filtered), 2)
        result.max_ms = round(max(filtered), 2)
        result.median_ms = round(statistics.median(filtered), 2)
        result.jitter_ms = round(result.max_ms - result.min_ms, 2)

        if len(filtered) >= 2:
            result.std_dev = round(statistics.stdev(filtered), 2)
            if result.filtered_avg > 0:
                result.cv_score = round(result.std_dev / result.filtered_avg, 4)

        result.reliability_index = _compute_reliability_index(
            result.success_rate, result.filtered_avg
        )

        if result.raw_avg and result.filtered_avg:
            diff_pct = abs(result.raw_avg - result.filtered_avg) / max(result.raw_avg, 0.001)
            if diff_pct > 0.30:
                result.anomaly_flags.append("HIGH_OUTLIER_RATIO")

        if result.success_rate < 0.5:
            result.anomaly_flags.append("LOW_SUCCESS_RATE")

        if result.cv_score is not None and result.cv_score > 0.5:
            result.anomaly_flags.append("HIGH_VARIANCE")

        if result.jitter_ms is not None and result.jitter_ms > 200:
            result.anomaly_flags.append("HIGH_JITTER")

        if not result.response_integrity:
            result.anomaly_flags.append("INTEGRITY_FAIL")

        if ttl_samples:
            result.ttl_consistency = _compute_ttl_consistency(ttl_samples)
            avg_ttl = sum(ttl_samples) / len(ttl_samples)
            result.cache_efficiency = _compute_cache_efficiency(int(avg_ttl), result.filtered_avg)

    return result


def _detect_global_anomalies(results: List[ServerResult]) -> None:
    valid = [r for r in results if r.filtered_avg is not None]
    if len(valid) < 3:
        return
    avgs = [r.filtered_avg for r in valid]

    ensemble_scores = _ensemble_anomaly_score(avgs)
    z_scores = _compute_z_scores(avgs)

    all_avgs_sorted = sorted(avgs)
    for result, z, ens_score in zip(valid, z_scores, ensemble_scores):
        result.z_score = round(z, 3)
        result.percentile_rank = _compute_percentile_rank(result.filtered_avg, all_avgs_sorted)

        is_anomaly = (abs(z) > Z_SCORE_ANOMALY_THRESHOLD) or (ens_score > 0.7)
        if is_anomaly:
            result.is_global_anomaly = True
            if "GLOBAL_ANOMALY" not in result.anomaly_flags:
                result.anomaly_flags.append("GLOBAL_ANOMALY")


def _check_dnssec_batch(results: List[ServerResult]) -> None:
    valid = [r for r in results if r.filtered_avg is not None]
    if not valid:
        return

    lock = threading.Lock()

    def _worker(result: ServerResult) -> None:
        supported = _check_dnssec(result.server.ip)
        with lock:
            result.dnssec_supported = supported

    with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_DNS_WORKERS) as executor:
        futures = {executor.submit(_worker, r): r for r in valid}
        for future in concurrent.futures.as_completed(futures):
            try:
                future.result()
            except Exception:
                pass


def _run_dns_phase(
    servers: List[DNSServer],
) -> List[ServerResult]:
    results: List[ServerResult] = []
    lock = threading.Lock()
    completed = [0]

    total = len(servers)

    with Progress(
        SpinnerColumn(style="bold cyan"),
        TextColumn("[bold white]{task.description}"),
        BarColumn(bar_width=40, style="cyan", complete_style="green"),
        TaskProgressColumn(),
        TimeElapsedColumn(),
        console=console,
        refresh_per_second=10,
    ) as progress:
        task = progress.add_task(
            f"[cyan]Testing {total} DNS servers...", total=total
        )

        with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_DNS_WORKERS) as executor:
            future_map = {executor.submit(_test_server, srv): srv for srv in servers}

            for future in concurrent.futures.as_completed(future_map):
                try:
                    res = future.result()
                    with lock:
                        results.append(res)
                        completed[0] += 1
                        srv = future_map[future]
                        status = (
                            f"[green]{res.filtered_avg:.0f}ms[/green]"
                            if res.filtered_avg is not None
                            else "[red]FAILED[/red]"
                        )
                        progress.update(
                            task,
                            advance=1,
                            description=f"[cyan]Tested [bold]{escape(srv.name)}[/bold] → {status}",
                        )
                except Exception:
                    with lock:
                        completed[0] += 1
                        progress.update(task, advance=1)

    return results


def _run_ping_phase(results: List[ServerResult]) -> None:
    valid = [r for r in results if r.filtered_avg is not None]
    if not valid:
        return

    lock = threading.Lock()

    def _ping_worker(result: ServerResult) -> None:
        ping = _measure_ping(result.server.ip, result.server.is_ipv6)
        with lock:
            result.ping_ms = ping
            if ping is not None and result.filtered_avg is not None:
                result.composite_score = _compute_composite_score(
                    result.filtered_avg, ping
                )

    with Progress(
        SpinnerColumn(style="bold magenta"),
        TextColumn("[bold white]{task.description}"),
        BarColumn(bar_width=40, style="magenta", complete_style="green"),
        TaskProgressColumn(),
        TimeElapsedColumn(),
        console=console,
        refresh_per_second=10,
    ) as progress:
        task = progress.add_task(
            f"[magenta]Pinging {len(valid)} servers...", total=len(valid)
        )

        with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_PING_WORKERS) as executor:
            future_map = {executor.submit(_ping_worker, r): r for r in valid}
            for future in concurrent.futures.as_completed(future_map):
                try:
                    future.result()
                except Exception:
                    pass
                r = future_map[future]
                with lock:
                    ping_display = (
                        f"[green]{r.ping_ms:.0f}ms[/green]"
                        if r.ping_ms is not None
                        else "[red]N/A[/red]"
                    )
                    progress.update(
                        task,
                        advance=1,
                        description=f"[magenta]Pinged [bold]{escape(r.server.name)}[/bold] → {ping_display}",
                    )


def _run_dnssec_phase(results: List[ServerResult]) -> None:
    valid = [r for r in results if r.filtered_avg is not None]
    if not valid:
        return

    with Progress(
        SpinnerColumn(style="bold yellow"),
        TextColumn("[bold white]{task.description}"),
        BarColumn(bar_width=40, style="yellow", complete_style="green"),
        TaskProgressColumn(),
        TimeElapsedColumn(),
        console=console,
        refresh_per_second=10,
    ) as progress:
        task = progress.add_task(
            f"[yellow]Checking DNSSEC on {len(valid)} servers...", total=len(valid)
        )
        lock = threading.Lock()

        def _worker(result: ServerResult) -> None:
            supported = _check_dnssec(result.server.ip)
            with lock:
                result.dnssec_supported = supported
                label = (
                    "[green]✓[/green]"
                    if supported
                    else "[red]✗[/red]" if supported is False
                    else "[dim]?[/dim]"
                )
                progress.update(
                    task,
                    advance=1,
                    description=f"[yellow]DNSSEC [bold]{escape(result.server.name)}[/bold] → {label}",
                )

        with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_DNS_WORKERS) as executor:
            futures = {executor.submit(_worker, r): r for r in valid}
            for future in concurrent.futures.as_completed(futures):
                try:
                    future.result()
                except Exception:
                    with lock:
                        progress.update(task, advance=1)


def _speed_color(ms: Optional[float]) -> str:
    if ms is None:
        return "red"
    if ms < 50:
        return "green"
    if ms < 100:
        return "yellow"
    return "red"


def _score_label(ms: Optional[float]) -> str:
    if ms is None:
        return "✗ FAILED"
    if ms < 50:
        return "● EXCELLENT"
    if ms < 100:
        return "◐ GOOD"
    return "○ SLOW"


def _consistency_label(cv: Optional[float]) -> str:
    if cv is None:
        return "N/A"
    if cv <= CONSISTENCY_EXCELLENT:
        return "Stable"
    if cv <= CONSISTENCY_GOOD:
        return "Moderate"
    return "Variable"


def _render_dns_table(
    results: List[ServerResult],
    title: str,
    is_ipv6: bool,
    show_extended: bool = False,
) -> Table:
    filtered = [r for r in results if r.server.is_ipv6 == is_ipv6]
    filtered.sort(key=lambda r: (r.filtered_avg if r.filtered_avg is not None else float("inf")))
    failed = [r for r in filtered if r.filtered_avg is None]
    passed = [r for r in filtered if r.filtered_avg is not None]

    table = Table(
        title=title,
        box=rich_box.ROUNDED,
        border_style="cyan" if not is_ipv6 else "blue",
        header_style="bold white",
        show_lines=True,
        expand=True,
    )
    table.add_column("Rank", style="bold white", width=5, justify="center")
    table.add_column("Server Name", style="white", min_width=28)
    table.add_column("IP Address", style="dim white", min_width=20)
    table.add_column("Category", min_width=16)
    table.add_column("Avg DNS (ms)", justify="right", min_width=12)
    table.add_column("Median (ms)", justify="right", min_width=11)
    table.add_column("Jitter (ms)", justify="right", min_width=11)
    table.add_column("Success", justify="center", width=9)
    table.add_column("Consistency", justify="center", width=11)
    table.add_column("DNSSEC", justify="center", width=8)
    table.add_column("Pct", justify="right", width=7)
    table.add_column("Flags", min_width=10)

    for rank, r in enumerate(passed, 1):
        color = _speed_color(r.filtered_avg)
        cat_color = CATEGORY_COLORS.get(r.server.category, "white")
        flag_text = ",".join(r.anomaly_flags) if r.anomaly_flags else "—"
        flag_style = "red" if r.anomaly_flags else "dim"
        anomaly_marker = " ⚠" if r.is_global_anomaly else ""
        dnssec_display = (
            "[green]✓[/green]" if r.dnssec_supported
            else "[red]✗[/red]" if r.dnssec_supported is False
            else "[dim]?[/dim]"
        )
        jitter_color = _speed_color(r.jitter_ms) if r.jitter_ms is not None else "dim"
        jitter_str = f"[{jitter_color}]{r.jitter_ms:.1f}[/{jitter_color}]" if r.jitter_ms is not None else "—"
        median_str = f"{r.median_ms:.1f}" if r.median_ms is not None else "—"
        pct_str = f"{r.percentile_rank:.0f}" if r.percentile_rank is not None else "—"
        integrity_marker = " ⛔" if not r.response_integrity else ""

        table.add_row(
            str(rank),
            f"{escape(r.server.name)}{anomaly_marker}{integrity_marker}",
            escape(r.server.ip),
            f"[{cat_color}]{r.server.category.value}[/{cat_color}]",
            f"[{color}]{r.filtered_avg:.1f}[/{color}]",
            median_str,
            jitter_str,
            f"[green]{r.success_rate * 100:.0f}%[/green]",
            f"[{'green' if r.cv_score and r.cv_score <= CONSISTENCY_EXCELLENT else 'yellow'}]{_consistency_label(r.cv_score)}[/{'green' if r.cv_score and r.cv_score <= CONSISTENCY_EXCELLENT else 'yellow'}]",
            dnssec_display,
            pct_str,
            f"[{flag_style}]{escape(flag_text)}[/{flag_style}]",
        )

    for r in failed:
        table.add_row(
            "—",
            escape(r.server.name),
            escape(r.server.ip),
            r.server.category.value,
            "[red]FAILED[/red]",
            "—",
            "—",
            f"[red]{r.success_rate * 100:.0f}%[/red]",
            "—",
            "[dim]?[/dim]",
            "—",
            "[red]UNREACHABLE[/red]",
        )

    return table


def _render_correlation_table(
    results: List[ServerResult],
    title: str,
    is_ipv6: bool,
) -> Table:
    filtered = [
        r
        for r in results
        if r.server.is_ipv6 == is_ipv6
        and r.composite_score is not None
    ]
    filtered.sort(key=lambda r: r.composite_score)

    table = Table(
        title=title,
        box=rich_box.ROUNDED,
        border_style="magenta" if not is_ipv6 else "blue",
        header_style="bold white",
        show_lines=True,
        expand=True,
    )
    table.add_column("Rank", style="bold white", width=5, justify="center")
    table.add_column("Server Name", style="white", min_width=28)
    table.add_column("IP Address", style="dim white", min_width=20)
    table.add_column("DNS (ms)", justify="right", width=10)
    table.add_column("Ping (ms)", justify="right", width=10)
    table.add_column("Diff (ms)", justify="right", width=10)
    table.add_column("Score", justify="right", width=10)
    table.add_column("Reliability", justify="right", width=11)
    table.add_column("Cache Eff.", justify="right", width=10)

    for rank, r in enumerate(filtered, 1):
        dns_color = _speed_color(r.filtered_avg)
        ping_color = _speed_color(r.ping_ms)
        score_color = _speed_color(r.composite_score)
        diff = (
            round(r.ping_ms - r.filtered_avg, 1)
            if r.ping_ms is not None and r.filtered_avg is not None
            else None
        )
        diff_str = f"{diff:+.1f}" if diff is not None else "—"
        diff_color = "green" if diff is not None and abs(diff) < 30 else "yellow" if diff is not None and abs(diff) < 100 else "red"
        rel_str = f"{r.reliability_index:.1f}" if r.reliability_index is not None else "—"
        cache_str = f"{r.cache_efficiency:.2f}" if r.cache_efficiency is not None else "—"

        table.add_row(
            str(rank),
            escape(r.server.name),
            escape(r.server.ip),
            f"[{dns_color}]{r.filtered_avg:.1f}[/{dns_color}]",
            f"[{ping_color}]{r.ping_ms:.1f}[/{ping_color}]",
            f"[{diff_color}]{diff_str}[/{diff_color}]",
            f"[{score_color}]{r.composite_score:.1f}[/{score_color}]",
            f"[cyan]{rel_str}[/cyan]",
            f"[dim]{cache_str}[/dim]",
        )

    return table


def _render_security_table(
    results: List[ServerResult],
    title: str,
    is_ipv6: bool,
) -> Table:
    filtered = [
        r for r in results
        if r.server.is_ipv6 == is_ipv6 and r.filtered_avg is not None
    ]
    filtered.sort(key=lambda r: (
        0 if r.dnssec_supported else 1,
        r.filtered_avg if r.filtered_avg is not None else float("inf")
    ))

    table = Table(
        title=title,
        box=rich_box.ROUNDED,
        border_style="red",
        header_style="bold white",
        show_lines=True,
        expand=True,
    )
    table.add_column("Server Name", style="white", min_width=28)
    table.add_column("IP Address", style="dim white", min_width=20)
    table.add_column("Category", min_width=16)
    table.add_column("DNSSEC", justify="center", width=10)
    table.add_column("Integrity", justify="center", width=11)
    table.add_column("TTL Consistency", justify="center", width=16)
    table.add_column("Anomaly Flags", min_width=20)

    for r in filtered:
        cat_color = CATEGORY_COLORS.get(r.server.category, "white")
        dnssec_str = (
            "[green]Validated[/green]" if r.dnssec_supported
            else "[red]None[/red]" if r.dnssec_supported is False
            else "[dim]Unknown[/dim]"
        )
        integrity_str = "[green]OK[/green]" if r.response_integrity else "[red]FAIL[/red]"
        ttl_str = f"{r.ttl_consistency:.2f}" if r.ttl_consistency is not None else "—"
        flags_str = escape(",".join(r.anomaly_flags)) if r.anomaly_flags else "[dim]—[/dim]"

        table.add_row(
            escape(r.server.name),
            escape(r.server.ip),
            f"[{cat_color}]{r.server.category.value}[/{cat_color}]",
            dnssec_str,
            integrity_str,
            ttl_str,
            flags_str,
        )

    return table


def _export_results_json(results: List[ServerResult], path: str) -> bool:
    try:
        safe_path = os.path.realpath(path)
        if not safe_path.endswith(".json"):
            return False
        allowed_base = os.path.realpath(os.path.expanduser("~"))
        if not safe_path.startswith(allowed_base):
            return False

        output: List[Dict[str, Any]] = []
        for r in results:
            entry: Dict[str, Any] = {
                "name": _sanitize_output_string(r.server.name),
                "ip": _sanitize_output_string(r.server.ip),
                "is_ipv6": bool(r.server.is_ipv6),
                "category": _sanitize_output_string(r.server.category.value),
                "filtered_avg_ms": r.filtered_avg,
                "raw_avg_ms": r.raw_avg,
                "median_ms": r.median_ms,
                "min_ms": r.min_ms,
                "max_ms": r.max_ms,
                "jitter_ms": r.jitter_ms,
                "std_dev": r.std_dev,
                "cv_score": r.cv_score,
                "success_rate": r.success_rate,
                "reliability_index": r.reliability_index,
                "ping_ms": r.ping_ms,
                "composite_score": r.composite_score,
                "dnssec_supported": r.dnssec_supported,
                "response_integrity": r.response_integrity,
                "ttl_consistency": r.ttl_consistency,
                "cache_efficiency": r.cache_efficiency,
                "percentile_rank": r.percentile_rank,
                "z_score": r.z_score,
                "is_global_anomaly": r.is_global_anomaly,
                "anomaly_flags": [_sanitize_output_string(f) for f in r.anomaly_flags],
            }
            output.append(entry)

        with open(safe_path, "w", encoding="utf-8") as f:
            json.dump(output, f, indent=2, ensure_ascii=True)
        return True
    except (OSError, ValueError, TypeError):
        return False


def _export_results_csv(results: List[ServerResult], path: str) -> bool:
    try:
        safe_path = os.path.realpath(path)
        if not safe_path.endswith(".csv"):
            return False
        allowed_base = os.path.realpath(os.path.expanduser("~"))
        if not safe_path.startswith(allowed_base):
            return False

        fieldnames = [
            "name", "ip", "is_ipv6", "category", "filtered_avg_ms", "median_ms",
            "jitter_ms", "success_rate", "reliability_index", "ping_ms",
            "composite_score", "dnssec_supported", "response_integrity",
            "percentile_rank", "z_score", "is_global_anomaly", "anomaly_flags"
        ]

        with open(safe_path, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction="ignore")
            writer.writeheader()
            for r in results:
                writer.writerow({
                    "name": _sanitize_output_string(r.server.name),
                    "ip": _sanitize_output_string(r.server.ip),
                    "is_ipv6": r.server.is_ipv6,
                    "category": _sanitize_output_string(r.server.category.value),
                    "filtered_avg_ms": r.filtered_avg,
                    "median_ms": r.median_ms,
                    "jitter_ms": r.jitter_ms,
                    "success_rate": round(r.success_rate * 100, 1) if r.success_rate is not None else None,
                    "reliability_index": r.reliability_index,
                    "ping_ms": r.ping_ms,
                    "composite_score": r.composite_score,
                    "dnssec_supported": r.dnssec_supported,
                    "response_integrity": r.response_integrity,
                    "percentile_rank": r.percentile_rank,
                    "z_score": r.z_score,
                    "is_global_anomaly": r.is_global_anomaly,
                    "anomaly_flags": "|".join(r.anomaly_flags),
                })
        return True
    except (OSError, ValueError, TypeError):
        return False


def _display_banner() -> None:
    art_lines = [
        " ██████╗ ███╗   ██╗███████╗ ██████╗ ██████╗ ██╗   ██╗████████╗",
        " ██╔══██╗████╗  ██║██╔════╝██╔════╝██╔═══██╗██║   ██║╚══██╔══╝",
        " ██║  ██║██╔██╗ ██║███████╗██║     ██║   ██║██║   ██║   ██║   ",
        " ██║  ██║██║╚██╗██║╚════██║██║     ██║   ██║██║   ██║   ██║   ",
        " ██████╔╝██║ ╚████║███████║╚██████╗╚██████╔╝╚██████╔╝   ██║   ",
        " ╚═════╝ ╚═╝  ╚═══╝╚══════╝ ╚═════╝ ╚═════╝  ╚═════╝    ╚═╝  ",
    ]

    gradient_colors = [
        "bright_cyan",
        "cyan",
        "bright_blue",
        "blue",
        "bright_magenta",
        "magenta",
    ]

    panel_content = Text(justify="center")
    for line, color in zip(art_lines, gradient_colors):
        panel_content.append(line + "\n", style=f"bold {color}")
    panel_content.append("\n")
    panel_content.append(TOOL_TAGLINE + "\n", style="bold white")
    panel_content.append("\n")
    panel_content.append(
        f"  v{TOOL_VERSION}   │   Python {sys.version.split()[0]}   │   {platform.system()} {platform.machine()}  ",
        style="dim white",
    )

    console.print()
    console.print(
        Panel(
            Align.center(panel_content),
            border_style="bright_cyan",
            padding=(1, 4),
        )
    )
    console.print()


def _display_legend() -> None:
    console.print(Rule("[bold white]Performance Legend[/bold white]", style="dim white"))
    console.print(
        "  [bold green]● EXCELLENT[/bold green]  < 50ms    "
        "[bold yellow]◐ GOOD[/bold yellow]  50–100ms    "
        "[bold red]○ SLOW[/bold red]  > 100ms    "
        "[bold cyan]Score = DNS×70% + Ping×30%[/bold cyan]"
    )
    console.print(
        "  [bold cyan]Reliability Index[/bold cyan] = Success Rate × Speed Score (0–100, higher is better)    "
        "[bold red]⚠ = Statistical Anomaly (Z > 2.5σ)[/bold red]    "
        "[bold red]⛔ = Integrity Failure[/bold red]"
    )
    console.print(
        "  [bold yellow]Ensemble Anomaly Detection[/bold yellow]: Z-Score + Modified Z-Score (MAD) + Grubbs Test"
    )
    console.print()


def _display_summary(results: List[ServerResult], has_ipv6: bool) -> None:
    console.print(Rule("[bold white]Benchmark Summary[/bold white]", style="cyan"))

    total = len(results)
    passed = [r for r in results if r.filtered_avg is not None]
    failed = [r for r in results if r.filtered_avg is None]
    ipv4_passed = [r for r in passed if not r.server.is_ipv6]
    ipv6_passed = [r for r in passed if r.server.is_ipv6]
    anomalies = [r for r in results if r.is_global_anomaly]
    integrity_fails = [r for r in results if not r.response_integrity]
    dnssec_ok = [r for r in passed if r.dnssec_supported is True]

    summary = Table(box=rich_box.SIMPLE, show_header=False, expand=False)
    summary.add_column("", style="dim white")
    summary.add_column("", style="bold white")

    summary.add_row("Total Servers Tested", str(total))
    summary.add_row("Responding (IPv4)", f"[green]{len(ipv4_passed)}[/green]")
    if has_ipv6:
        summary.add_row("Responding (IPv6)", f"[blue]{len(ipv6_passed)}[/blue]")
    summary.add_row("Failed / Unreachable", f"[red]{len(failed)}[/red]")
    summary.add_row("Statistical Anomalies Detected", f"[yellow]{len(anomalies)}[/yellow]")
    summary.add_row("Response Integrity Failures", f"[red]{len(integrity_fails)}[/red]")
    summary.add_row("DNSSEC-Validating Servers", f"[green]{len(dnssec_ok)}[/green]")
    console.print(summary)
    console.print()


def _display_top_picks(results: List[ServerResult], has_ipv6: bool) -> None:
    console.print(Rule("[bold white]🏆  Top Recommendations[/bold white]", style="yellow"))

    def _best(pool: List[ServerResult], key: str) -> Optional[ServerResult]:
        valid = [r for r in pool if getattr(r, key) is not None]
        if not valid:
            return None
        return min(valid, key=lambda r: getattr(r, key))

    def _best_secure(pool: List[ServerResult]) -> Optional[ServerResult]:
        valid = [r for r in pool if r.filtered_avg is not None and r.dnssec_supported and r.response_integrity]
        if not valid:
            valid = [r for r in pool if r.filtered_avg is not None and r.response_integrity]
        if not valid:
            return None
        return min(valid, key=lambda r: r.filtered_avg)

    ipv4_results = [r for r in results if not r.server.is_ipv6]
    ipv6_results = [r for r in results if r.server.is_ipv6]

    categories_to_show = [
        ("🥇 Best Overall IPv4 (Speed)", _best(ipv4_results, "filtered_avg"), "filtered_avg", "ms"),
        ("🌐 Best IPv4 by Composite Score", _best(ipv4_results, "composite_score"), "composite_score", "score"),
        ("🔒 Best Privacy IPv4", _best([r for r in ipv4_results if r.server.category == ServerCategory.PRIVACY], "filtered_avg"), "filtered_avg", "ms"),
        ("👪 Best Family-Safe IPv4", _best([r for r in ipv4_results if r.server.category == ServerCategory.FAMILY], "filtered_avg"), "filtered_avg", "ms"),
        ("🛡 Best Security IPv4", _best([r for r in ipv4_results if r.server.category == ServerCategory.SECURITY], "filtered_avg"), "filtered_avg", "ms"),
        ("🚫 Best Ad-Blocking IPv4", _best([r for r in ipv4_results if r.server.category == ServerCategory.AD_BLOCKING], "filtered_avg"), "filtered_avg", "ms"),
    ]

    if has_ipv6:
        categories_to_show += [
            ("🥇 Best Overall IPv6 (Speed)", _best(ipv6_results, "filtered_avg"), "filtered_avg", "ms"),
            ("🌐 Best IPv6 by Composite Score", _best(ipv6_results, "composite_score"), "composite_score", "score"),
        ]

    for label, best, attr, unit in categories_to_show:
        if best is None:
            continue
        val = getattr(best, attr)
        if val is None:
            continue
        color = _speed_color(val) if unit == "ms" else "cyan"
        integrity_note = " [red]⛔[/red]" if not best.response_integrity else ""
        dnssec_note = " [green](DNSSEC)[/green]" if best.dnssec_supported else ""
        console.print(
            f"  {label}:  [bold white]{escape(best.server.name)}[/bold white]"
            f"  [dim]({escape(best.server.ip)})[/dim]"
            f"  [{color}]{val:.1f} {unit}[/{color}]"
            + (
                f"  [dim]│ Ping: {best.ping_ms:.1f}ms[/dim]"
                if best.ping_ms is not None
                else ""
            )
            + dnssec_note + integrity_note
        )

    console.print()

    best_secure_ipv4 = _best_secure(ipv4_results)
    best_two_ipv4 = sorted(
        [r for r in ipv4_results if r.filtered_avg is not None and r.response_integrity],
        key=lambda r: r.filtered_avg,
    )[:2]

    if not best_two_ipv4:
        best_two_ipv4 = sorted(
            [r for r in ipv4_results if r.filtered_avg is not None],
            key=lambda r: r.filtered_avg,
        )[:2]

    if best_two_ipv4:
        console.print(Rule("[bold white]⚙  Configuration Recommendation[/bold white]", style="green"))
        console.print("  Apply to systemd-resolved / router / OpenWRT:\n")
        primary = best_two_ipv4[0]
        console.print(
            f"  [bold green]Primary DNS  :[/bold green]  [white]{primary.server.ip}[/white]"
            f"  [dim]# {primary.server.name} — {primary.filtered_avg:.0f}ms[/dim]"
        )
        if len(best_two_ipv4) > 1:
            secondary = best_two_ipv4[1]
            console.print(
                f"  [bold cyan]Secondary DNS:[/bold cyan]  [white]{secondary.server.ip}[/white]"
                f"  [dim]# {secondary.server.name} — {secondary.filtered_avg:.0f}ms[/dim]"
            )
        console.print()


def _prompt_confirm(message: str) -> bool:
    try:
        response = console.input(f"[bold yellow]? [/bold yellow][white]{message}[/white] [dim](y/N):[/dim] ").strip().lower()
        if len(response) > 10:
            return False
        return response in ("y", "yes")
    except (EOFError, KeyboardInterrupt):
        return False


def _safe_input(prompt: str, max_len: int = _MAX_USER_INPUT_LEN) -> str:
    try:
        raw = console.input(prompt).strip()
        if len(raw) > max_len:
            return raw[:max_len]
        return raw
    except (EOFError, KeyboardInterrupt):
        return ""


def _interactive_menu() -> Dict[str, Any]:
    console.print(Rule("[bold white]Configuration[/bold white]", style="dim cyan"))
    opts: Dict[str, Any] = {}

    console.print("  [bold cyan]DNScout[/bold cyan] will test all known public DNS servers for your network.\n")

    try:
        console.print("  [bold]Options:[/bold]")
        include_ipv6_input = _safe_input(
            "  [yellow]► Include IPv6 DNS servers?[/yellow] [dim](requires IPv6 connectivity)[/dim] [dim](y/N):[/dim] "
        ).lower()
        opts["want_ipv6"] = include_ipv6_input in ("y", "yes")

        run_ping_input = _safe_input(
            "  [yellow]► Run DNS-Ping correlation analysis?[/yellow] [dim](adds ~30s)[/dim] [dim](Y/n):[/dim] "
        ).lower()
        opts["run_ping"] = run_ping_input not in ("n", "no")

        run_dnssec_input = _safe_input(
            "  [yellow]► Run DNSSEC validation check?[/yellow] [dim](adds ~20s)[/dim] [dim](Y/n):[/dim] "
        ).lower()
        opts["run_dnssec"] = run_dnssec_input not in ("n", "no")

        run_security_report_input = _safe_input(
            "  [yellow]► Show security analysis report?[/yellow] [dim](Y/n):[/dim] "
        ).lower()
        opts["show_security"] = run_security_report_input not in ("n", "no")

        export_input = _safe_input(
            "  [yellow]► Export results?[/yellow] [dim](json/csv/no)[/dim] [dim](no):[/dim] "
        ).lower()
        if export_input in ("json", "csv"):
            opts["export_format"] = export_input
            default_name = f"dnscout_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.{export_input}"
            path_input = _safe_input(
                f"  [yellow]► Export path[/yellow] [dim](default: {default_name}):[/dim] "
            )
            if not path_input:
                path_input = default_name
            path_clean = re.sub(r"[^\w\-_./]", "_", path_input)[:120]
            if not path_clean.endswith(f".{export_input}"):
                path_clean = path_clean + f".{export_input}"
            opts["export_path"] = path_clean
        else:
            opts["export_format"] = None
            opts["export_path"] = None

        console.print()
    except (EOFError, KeyboardInterrupt):
        opts.setdefault("want_ipv6", False)
        opts.setdefault("run_ping", True)
        opts.setdefault("run_dnssec", False)
        opts.setdefault("show_security", False)
        opts.setdefault("export_format", None)
        opts.setdefault("export_path", None)

    return opts


def main() -> None:
    _display_banner()
    opts = _interactive_menu()

    want_ipv6 = opts.get("want_ipv6", False)
    run_ping = opts.get("run_ping", True)
    run_dnssec = opts.get("run_dnssec", False)
    show_security = opts.get("show_security", False)
    export_format = opts.get("export_format")
    export_path = opts.get("export_path")

    has_ipv6 = False
    if want_ipv6:
        console.print("[cyan]Checking IPv6 connectivity...[/cyan]")
        has_ipv6 = _check_ipv6_connectivity()
        if has_ipv6:
            console.print("[green]✓ IPv6 connectivity confirmed[/green]\n")
        else:
            console.print("[yellow]✗ IPv6 not available — skipping IPv6 servers[/yellow]\n")

    servers = _build_server_list(include_ipv6=has_ipv6)
    ipv4_count = sum(1 for s in servers if not s.is_ipv6)
    ipv6_count = sum(1 for s in servers if s.is_ipv6)

    feature_list = "IQR Filtering + Ensemble Anomaly (Z-Score+MAD+Grubbs) + Reliability Indexing"
    if run_dnssec:
        feature_list += " + DNSSEC Validation"
    if show_security:
        feature_list += " + Security Report"

    console.print(
        Panel(
            f"[white]Servers:[/white] [bold cyan]{len(servers)}[/bold cyan]  "
            f"[dim](IPv4: {ipv4_count}, IPv6: {ipv6_count})[/dim]\n"
            f"[white]Tests per server:[/white] [bold cyan]{TEST_COUNT}[/bold cyan]  "
            f"[dim]across {len(TEST_DOMAINS)} domains[/dim]\n"
            f"[white]Total queries:[/white] [bold cyan]{len(servers) * TEST_COUNT}[/bold cyan]\n"
            f"[white]Concurrency:[/white] [bold cyan]{MAX_DNS_WORKERS}[/bold cyan] workers\n"
            f"[white]Analysis:[/white] [bold green]{feature_list}[/bold green]",
            title="[bold white]Test Parameters[/bold white]",
            border_style="cyan",
        )
    )
    console.print()

    console.print(Rule("[bold white]Phase 1 — DNS Query Benchmarking[/bold white]", style="cyan"))
    console.print()

    results = _run_dns_phase(servers)

    console.print()
    console.print("[cyan]Running ensemble anomaly detection...[/cyan]")
    _detect_global_anomalies(results)
    console.print("[green]✓ Anomaly detection complete[/green]\n")

    if run_ping:
        console.print(Rule("[bold white]Phase 2 — DNS-Ping Correlation Analysis[/bold white]", style="magenta"))
        console.print()
        _run_ping_phase(results)
        console.print()

    if run_dnssec:
        console.print(Rule("[bold white]Phase 3 — DNSSEC Validation[/bold white]", style="yellow"))
        console.print()
        _run_dnssec_phase(results)
        console.print()

    console.print(Rule("[bold white]Results — IPv4 DNS Servers[/bold white]", style="cyan"))
    ipv4_table = _render_dns_table(results, "IPv4 DNS Server Rankings", is_ipv6=False)
    console.print(ipv4_table)
    console.print()

    if has_ipv6:
        console.print(Rule("[bold white]Results — IPv6 DNS Servers[/bold white]", style="blue"))
        ipv6_table = _render_dns_table(results, "IPv6 DNS Server Rankings", is_ipv6=True)
        console.print(ipv6_table)
        console.print()

    if run_ping:
        console.print(Rule("[bold white]Correlation Results — IPv4[/bold white]", style="magenta"))
        ipv4_corr = _render_correlation_table(results, "IPv4 DNS-Ping Correlation", is_ipv6=False)
        console.print(ipv4_corr)
        console.print()

        if has_ipv6:
            console.print(Rule("[bold white]Correlation Results — IPv6[/bold white]", style="blue"))
            ipv6_corr = _render_correlation_table(results, "IPv6 DNS-Ping Correlation", is_ipv6=True)
            console.print(ipv6_corr)
            console.print()

    if show_security:
        console.print(Rule("[bold white]Security Analysis — IPv4[/bold white]", style="red"))
        sec_table = _render_security_table(results, "IPv4 Security Assessment", is_ipv6=False)
        console.print(sec_table)
        console.print()

        if has_ipv6:
            console.print(Rule("[bold white]Security Analysis — IPv6[/bold white]", style="red"))
            sec_table_v6 = _render_security_table(results, "IPv6 Security Assessment", is_ipv6=True)
            console.print(sec_table_v6)
            console.print()

    _display_legend()
    _display_summary(results, has_ipv6)
    _display_top_picks(results, has_ipv6)

    if export_format and export_path:
        console.print(Rule("[bold white]Export[/bold white]", style="green"))
        if export_format == "json":
            ok = _export_results_json(results, export_path)
        elif export_format == "csv":
            ok = _export_results_csv(results, export_path)
        else:
            ok = False

        if ok:
            console.print(f"  [green]✓ Results exported to:[/green] [white]{escape(export_path)}[/white]")
        else:
            console.print(f"  [red]✗ Export failed. Check path and permissions.[/red]")
        console.print()

    console.print(Rule(style="dim white"))
    console.print(
        Align.center(
            f"[dim white]{TOOL_NAME} v{TOOL_VERSION} — {TOOL_TAGLINE}[/dim white]"
        )
    )
    console.print()

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        console.print("\n[yellow]Interrupted by user. Goodbye.[/yellow]")
        sys.exit(0)
    except Exception as exc:
        console.print(f"\n[red]An error occurred. Please check your environment and try again.[/red]")
        sys.exit(1)
