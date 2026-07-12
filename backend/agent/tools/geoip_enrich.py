"""geoip_enrich — geolocation and reputation for an IP address."""

from __future__ import annotations

import ipaddress
from typing import Any

from .base import Tool, ToolParam, ToolResult, load_dataset


class GeoIPEnrichTool(Tool):
    name = "geoip_enrich"
    description = (
        "Enrich an IPv4 address with geolocation, ASN and reputation "
        "(Tor exit, hosting, abuse score). Use it to add context to any "
        "source or destination IP seen in an alert."
    )
    params = [ToolParam("ip", "string", "IPv4 address to enrich, e.g. 185.220.101.44", required=True)]

    def _lookup(self, ip: str) -> dict[str, Any] | None:
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return None
        networks = load_dataset("geoip")["networks"]
        # Exact-network match wins; fall back to the most specific containing net.
        best: dict[str, Any] | None = None
        best_prefix = -1
        for net in networks:
            try:
                cidr = ipaddress.ip_network(net["cidr"], strict=False)
            except ValueError:
                continue
            if addr in cidr and cidr.prefixlen > best_prefix:
                best, best_prefix = net, cidr.prefixlen
        return best

    def run(self, ip: str = "", **_: Any) -> ToolResult:
        ip = (ip or "").strip()
        if not ip:
            return ToolResult(ok=False, summary="No IP provided.")
        net = self._lookup(ip)
        if net is None:
            return ToolResult(
                ok=True,
                summary=f"{ip}: no enrichment record (treat as unknown/unclassified).",
                data={"ip": ip, "known": False},
                sources=["geoip:none"],
            )
        rep = net["reputation"]
        flags = []
        if rep.get("tor_exit"):
            flags.append("Tor exit node")
        if rep.get("hosting"):
            flags.append("hosting/VPS")
        flag_str = ", ".join(flags) if flags else "no notable flags"
        summary = (
            f"{ip} -> {net['country']} ({net['country_code']}), {net['asn']}; "
            f"{flag_str}; abuse score {rep.get('abuse_score', 0)}/100."
        )
        return ToolResult(
            ok=True,
            summary=summary,
            data={"ip": ip, "known": True, **net},
            sources=[f"geoip:{net['cidr']}"],
        )
