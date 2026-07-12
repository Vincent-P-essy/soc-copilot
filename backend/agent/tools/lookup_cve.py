"""lookup_cve — resolve CVEs by id, service or product keyword."""

from __future__ import annotations

from typing import Any

from .base import Tool, ToolParam, ToolResult, load_dataset


class LookupCVETool(Tool):
    name = "lookup_cve"
    description = (
        "Look up known vulnerabilities from the NVD-shaped CVE cache by CVE id "
        "(e.g. CVE-2024-6387), by affected service (ssh, http, vpn) or by "
        "product keyword. Use it to assess whether an exposed service has an "
        "exploitable, high-severity or actively-exploited (KEV) vulnerability."
    )
    params = [
        ToolParam("cve_id", "string", "Exact CVE identifier, e.g. CVE-2021-44228."),
        ToolParam("service", "string", "Affected service class: ssh, http, vpn, ..."),
        ToolParam("keyword", "string", "Product/alias keyword, e.g. openssh, log4j, moveit."),
    ]

    def run(self, cve_id: str = "", service: str = "", keyword: str = "", **_: Any) -> ToolResult:
        cves = load_dataset("cve_cache")["cves"]
        cve_id_l = (cve_id or "").strip().lower()
        service_l = (service or "").strip().lower()
        keyword_l = (keyword or "").strip().lower()

        def matches(cve: dict[str, Any]) -> bool:
            if cve_id_l:
                return cve["id"].lower() == cve_id_l
            if service_l and cve.get("service", "").lower() != service_l:
                return False
            if keyword_l:
                blob = " ".join(
                    [cve.get("product", ""), cve.get("summary", ""), *cve.get("aliases", [])]
                ).lower()
                if keyword_l not in blob:
                    return False
            return bool(service_l or keyword_l)

        found = [c for c in cves if matches(c)]
        if not found:
            crit = cve_id or service or keyword or "(no criteria)"
            return ToolResult(
                ok=True,
                summary=f"No CVE in cache matched '{crit}'.",
                data={"count": 0, "cves": []},
                sources=["cve:none"],
            )

        # Most severe first — KEV then CVSS.
        found.sort(key=lambda c: (c.get("kev", False), c.get("cvss", 0.0)), reverse=True)
        lines = [
            f"{c['id']} (CVSS {c['cvss']} {c['severity']}"
            + (", KEV" if c.get("kev") else "")
            + f") — {c['product']} {c['affected']}"
            for c in found
        ]
        return ToolResult(
            ok=True,
            summary=f"{len(found)} matching CVE(s): " + "; ".join(lines),
            data={"count": len(found), "cves": found},
            sources=[f"cve:{c['id']}" for c in found],
        )
