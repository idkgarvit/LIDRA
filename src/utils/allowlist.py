"""False positive allowlist - skip known-good sources to reduce noise."""

import ipaddress
import logging
from typing import Optional
from dataclasses import dataclass, field

log = logging.getLogger(__name__)


CLOUDFLARE_RANGES_V4 = [
    "173.245.48.0/20",
    "103.21.244.0/22",
    "103.22.200.0/22",
    "103.31.4.0/22",
    "141.101.64.0/18",
    "108.162.192.0/18",
    "190.93.240.0/20",
    "188.114.96.0/20",
    "197.234.240.0/22",
    "198.41.128.0/17",
    "162.158.0.0/15",
    "104.16.0.0/13",
    "104.24.0.0/14",
    "172.64.0.0/13",
    "131.0.72.0/22",
]

CLOUDFLARE_RANGES_V6 = [
    "2400:cb00::/32",
    "2606:4700::/32",
    "2803:f800::/32",
    "2405:b500::/32",
    "2405:8100::/32",
    "2a06:98c0::/29",
    "2c0f:f248::/32",
]

GOOGLE_RANGES_V4 = [
    "8.8.8.0/24",
    "8.8.4.0/24",
    "142.250.0.0/15",
    "172.217.0.0/16",
    "216.58.192.0/19",
    "74.125.0.0/16",
    "173.194.0.0/16",
]

AWS_RANGES_V4 = [
    "13.32.0.0/15",
    "13.224.0.0/14",
    "18.32.0.0/12",
    "52.84.0.0/15",
    "54.230.0.0/16",
    "99.84.0.0/16",
    "205.251.192.0/19",
]

PRIVATE_RANGES_V4 = [
    "10.0.0.0/8",
    "172.16.0.0/12",
    "192.168.0.0/16",
    "127.0.0.0/8",
    "169.254.0.0/16",
    "100.64.0.0/10",
    "224.0.0.0/4",
    "240.0.0.0/4",
]

PRIVATE_RANGES_V6 = [
    "::1/128",
    "fc00::/7",
    "fe80::/10",
    "ff00::/8",
]


@dataclass
class LabeledNet:
    network: object
    label: str


@dataclass
class Allowlist:
    labeled_v4: list = field(default_factory=list)
    labeled_v6: list = field(default_factory=list)
    enabled: bool = True
    suppress_private: bool = True
    suppress_cloudflare: bool = True
    suppress_google: bool = False
    suppress_aws: bool = False

    def is_allowed(self, ip: str) -> tuple[bool, str]:
        if not self.enabled or not ip or ip == "unknown":
            return False, ""

        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return False, ""

        labeled = self.labeled_v4 if isinstance(addr, ipaddress.IPv4Address) else self.labeled_v6

        for entry in labeled:
            if addr in entry.network:
                if entry.label in ("cloudflare", "google", "aws"):
                    if entry.label == "cloudflare" and not self.suppress_cloudflare:
                        return False, ""
                    if entry.label == "google" and not self.suppress_google:
                        return False, ""
                    if entry.label == "aws" and not self.suppress_aws:
                        return False, ""
                if entry.label == "private" and not self.suppress_private:
                    return False, ""
                return True, entry.label

        return False, ""


def _parse_labeled(ranges: list, label: str) -> list:
    out = []
    for r in ranges:
        try:
            net = ipaddress.ip_network(r, strict=False)
            out.append(LabeledNet(network=net, label=label))
        except ValueError:
            log.warning(f"[Allowlist] Invalid CIDR range: {r}")
    return out


def build_allowlist(config: Optional[dict] = None) -> Allowlist:
    cfg = config or {}
    al_cfg = cfg.get("allowlist", {}) if isinstance(cfg, dict) else {}

    enabled = al_cfg.get("enabled", True)
    if not enabled:
        return Allowlist(enabled=False)

    labeled: list = []

    if al_cfg.get("include_cloudflare", True):
        labeled.extend(_parse_labeled(CLOUDFLARE_RANGES_V4, "cloudflare"))
        labeled.extend(_parse_labeled(CLOUDFLARE_RANGES_V6, "cloudflare"))
    if al_cfg.get("include_google", False):
        labeled.extend(_parse_labeled(GOOGLE_RANGES_V4, "google"))
    if al_cfg.get("include_aws", False):
        labeled.extend(_parse_labeled(AWS_RANGES_V4, "aws"))

    labeled.extend(_parse_labeled(PRIVATE_RANGES_V4, "private"))
    labeled.extend(_parse_labeled(PRIVATE_RANGES_V6, "private"))

    for cidr in al_cfg.get("trusted_cidrs", []):
        labeled.extend(_parse_labeled([cidr], "trusted"))
    for cidr in al_cfg.get("trusted_cidrs_v6", []):
        labeled.extend(_parse_labeled([cidr], "trusted"))

    labeled_v4 = [e for e in labeled if isinstance(e.network, ipaddress.IPv4Network)]
    labeled_v6 = [e for e in labeled if isinstance(e.network, ipaddress.IPv6Network)]

    return Allowlist(
        labeled_v4=labeled_v4,
        labeled_v6=labeled_v6,
        enabled=enabled,
        suppress_private=al_cfg.get("suppress_private", True),
        suppress_cloudflare=al_cfg.get("suppress_cloudflare", True),
        suppress_google=al_cfg.get("suppress_google", False),
        suppress_aws=al_cfg.get("suppress_aws", False),
    )


_global_allowlist: Optional[Allowlist] = None


def get_allowlist(config: Optional[dict] = None) -> Allowlist:
    global _global_allowlist
    if _global_allowlist is None:
        _global_allowlist = build_allowlist(config)
    return _global_allowlist


def reset_allowlist() -> None:
    global _global_allowlist
    _global_allowlist = None


# ponytail: port_scan/timing_evasion from RFC1918 is the LAN-recon signal,
# not noise — suppressing it blinded all insider testing. Private nets only
# skip true noise (broadcasts); CDN ranges keep the full noisy set.
NOISY_PACKET_ATTACKS = {
    "broadcast_storm", "timing_evasion", "port_scan",
    "session_correlated_sql_attack", "session_correlated_cmd_attack",
}

PRIVATE_NOISY_ATTACKS = {"broadcast_storm"}


def should_suppress(ip: str, attack_type: str, config: Optional[dict] = None) -> tuple[bool, str]:
    al = get_allowlist(config)
    allowed, reason = al.is_allowed(ip)
    if not allowed:
        return False, ""
    if reason in ("cloudflare", "google", "aws") and attack_type in NOISY_PACKET_ATTACKS:
        return True, reason
    if reason == "private" and attack_type in PRIVATE_NOISY_ATTACKS:
        return True, reason
    return False, ""
