"""Unit tests for the six grounded tools."""

from __future__ import annotations

from backend.agent import tools
from backend.agent.tools.base import phrase_in


def test_registry_has_six_tools():
    assert set(tools.REGISTRY) == {
        "search_incidents",
        "lookup_cve",
        "correlate_events",
        "mitre_lookup",
        "geoip_enrich",
        "suggest_playbook",
    }
    # Every tool exposes a valid Anthropic-shaped schema.
    for schema in tools.all_schemas():
        assert schema["name"]
        assert schema["input_schema"]["type"] == "object"


def test_phrase_in_avoids_substring_false_positives():
    assert phrase_in("brute force", "we saw a brute force attack")
    assert not phrase_in("rce", "against the SSH force")  # 'rce' inside 'force'
    assert phrase_in("ssh", "port 22 ssh login")


def test_geoip_matches_tor_exit_node():
    r = tools.dispatch("geoip_enrich", {"ip": "185.220.101.44"})
    assert r.ok
    assert r.data["reputation"]["tor_exit"] is True
    assert r.data["country_code"] == "DE"
    assert r.sources == ["geoip:185.220.101.0/24"]


def test_geoip_unknown_ip_is_graceful():
    r = tools.dispatch("geoip_enrich", {"ip": "10.0.0.1"})
    assert r.ok and r.data["known"] is False


def test_geoip_invalid_ip():
    r = tools.dispatch("geoip_enrich", {"ip": "not-an-ip"})
    assert r.ok and r.data["known"] is False


def test_search_incidents_by_ip():
    r = tools.dispatch("search_incidents", {"ioc": "185.220.101.44"})
    assert r.ok and r.data["count"] == 2
    ids = {i["id"] for i in r.data["incidents"]}
    assert {"INC-2041", "INC-2035"} <= ids


def test_search_incidents_days_filter_excludes_old():
    # A 1-day window should exclude the older brute-force incidents.
    r = tools.dispatch("search_incidents", {"ioc": "185.220.101.44", "days": 1})
    assert r.data["count"] == 0


def test_lookup_cve_by_service_sorts_by_severity():
    r = tools.dispatch("lookup_cve", {"service": "ssh"})
    assert r.ok and r.data["count"] == 2
    # KEV/highest CVSS first.
    assert r.data["cves"][0]["id"] == "CVE-2023-38408"


def test_lookup_cve_by_id():
    r = tools.dispatch("lookup_cve", {"cve_id": "CVE-2021-44228"})
    assert r.data["count"] == 1 and r.data["cves"][0]["kev"] is True


def test_mitre_lookup_maps_brute_force():
    r = tools.dispatch("mitre_lookup", {"query": "brute force"})
    ids = [t["id"] for t in r.data["techniques"]]
    assert "T1110" in ids and "T1190" not in ids


def test_correlate_events_reveals_linked_range():
    r = tools.dispatch("correlate_events", {"ioc": "45.155.205.233"})
    assert r.ok
    assert "45.155.205.0/24" in r.data["related_iocs"]
    assert {"T1046", "T1190"} <= set(r.data["techniques"])


def test_suggest_playbook_by_technique():
    r = tools.dispatch("suggest_playbook", {"technique_id": "T1110.001"})
    assert r.data["playbook"]["id"] == "IR-002"


def test_dispatch_unknown_tool():
    r = tools.dispatch("does_not_exist", {})
    assert not r.ok


def test_dispatch_missing_required_arg():
    r = tools.dispatch("geoip_enrich", {})
    assert not r.ok and "missing required" in r.summary
