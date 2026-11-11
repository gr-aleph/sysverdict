"""IOC extraction and the privacy filter: only hashes, public IPv4 and public domains may leave."""

from tests.fixtures.events import attack_events, benign_events
from triage.checks import run_checks
from triage.iocs import check_shareable, extract_iocs


def attack_iocs():
    events = attack_events()
    return extract_iocs(events, run_checks(events))


def by_value(iocs):
    return {i["value"]: i for i in iocs}


def test_no_iocs_when_nothing_is_flagged():
    events = benign_events()
    assert extract_iocs(events, run_checks(events)) == []


def test_attack_iocs_are_found():
    iocs = by_value(attack_iocs())
    assert iocs["b" * 64]["type"] == "sha256"
    assert iocs["167.172.71.11"]["type"] == "ip"
    assert iocs["fireeyee.com"]["type"] == "domain"
    assert iocs["2" * 32]["type"] == "imphash"
    assert iocs["helpdesk@fireeyee.com"]["type"] == "email"
    assert iocs["https://www.leak-site.example.com/files/leak.rtf"]["type"] == "url"
    assert iocs["c:\\ransom.txt"]["type"] == "file"
    assert iocs["hklm\\system\\currentcontrolset\\services\\fake updater\\imagepath"]["type"] == "registry"


def test_only_hashes_public_ipv4_and_public_domains_are_sent():
    for ioc in attack_iocs():
        if ioc["enrich"]:
            assert ioc["type"] in ("sha256", "ip", "domain"), ioc
            assert "analyst" not in ioc["value"] and "lab-pc01" not in ioc["value"]


def test_private_ipv6_hostnames_and_internal_names_are_not_sent():
    iocs = by_value(attack_iocs())
    assert iocs["192.168.1.10"]["enrich"] is False
    assert "IPv6" in iocs["2606:4700::6810:84e5"]["why_not"]
    assert iocs["lab-pc01"]["enrich"] is False
    assert iocs["_ldap._tcp.dc._msdcs.corp.local"]["enrich"] is False


def test_check_shareable_rules():
    computers = {"lab-pc01"}
    assert check_shareable("ip", "8.8.8.8", computers) == ""
    assert check_shareable("ip", "10.0.0.5", computers) != ""
    assert check_shareable("ip", "127.0.0.1", computers) != ""
    assert check_shareable("domain", "example.com", computers) == ""
    assert check_shareable("domain", "wpad", computers) != ""
    assert check_shareable("domain", "fileserver.corp", computers) != ""
    assert check_shareable("domain", "lab-pc01.home", computers) != ""
    assert check_shareable("domain", "lab-pc01.example.com", computers) != ""
    assert check_shareable("sha256", "a" * 64, computers) == ""
    assert check_shareable("file", "c:\\users\\analyst\\a.exe", computers) != ""
