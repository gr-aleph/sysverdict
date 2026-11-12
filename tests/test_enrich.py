"""Enrichment clients, tested offline with saved backend answers (see fixtures/backends/README.md).

requests.get is replaced by a fake that returns a saved answer, raises a timeout, or refuses
the connection, so no test touches the network.
"""

import pytest
import requests

from tests.conftest import load_backend_answer
from triage import enrich


class FakeResponse:
    def __init__(self, status_code, body):
        self.status_code = status_code
        self._body = body

    def json(self):
        if isinstance(self._body, Exception):
            raise self._body
        return self._body


def fake_get(answers):
    """Return a fake requests.get. answers maps a URL fragment to (status, body) or an exception."""
    calls = []

    def get(url, timeout):
        calls.append(url)
        for fragment, answer in answers.items():
            if fragment in url:
                if isinstance(answer, Exception):
                    raise answer
                return FakeResponse(*answer)
        raise requests.exceptions.ConnectionError("no fake answer")
    get.calls = calls
    return get


def ioc(ioc_type, value, enrich_ok=True, why_not=""):
    return {"type": ioc_type, "value": value, "process": "", "event_id": 1, "enrich": enrich_ok, "why_not": why_not}


# ---------- reading saved answers ----------

def test_hash_found_is_malicious():
    result = enrich.read_hash_answer(*load_backend_answer("hash_found.json"))
    assert result["status"] == "enriched"
    assert result["verdict"] == "malicious" and result["score"] == 90
    assert "VirusTotal" in result["note"]


def test_hash_with_failed_source_says_so():
    result = enrich.read_hash_answer(*load_backend_answer("hash_one_source_error.json"))
    assert "threatfox" in result["note"]


def test_hash_not_found():
    result = enrich.read_hash_answer(*load_backend_answer("hash_not_found.json"))
    assert result["status"] == "enriched"
    assert result["verdict"] != "malicious"


def test_ip_ok_and_private_and_ipv6():
    ok = enrich.read_ip_answer(*load_backend_answer("ip_ok.json"))
    assert ok["status"] == "enriched" and ok["verdict"] == "no_known_bad"
    assert enrich.read_ip_answer(*load_backend_answer("ip_private.json"))["status"] == "not enriched"
    ipv6 = enrich.read_ip_answer(*load_backend_answer("ip_400_ipv6.json"))
    assert ipv6["status"] == "not enriched" and "IPv6" in ipv6["note"]


def test_ip_all_sources_down_is_not_enriched():
    result = enrich.read_ip_answer(503, {"error": "sources_unavailable", "message": "x"})
    assert result["status"] == "not enriched"


def test_domain_ok_and_not_graded():
    ok = enrich.read_domain_answer(*load_backend_answer("domain_ok.json"))
    assert ok["status"] == "enriched" and ok["verdict"] == "likely_safe" and ok["score"] == 25
    _, body = load_backend_answer("domain_ok.json")
    body["assessment"].update(verdict="not_graded", average=None)
    assert enrich.read_domain_answer(200, body)["status"] == "not enriched"


def test_simple_verdict_mapping():
    assert enrich.simple_verdict({"verdict": "malicious"}) == "malicious"
    assert enrich.simple_verdict({"verdict": "definitely_malware"}) == "malicious"
    assert enrich.simple_verdict({"verdict": "likely_malware"}) == "suspicious"
    assert enrich.simple_verdict({"verdict": "no_known_bad"}) == ""


# ---------- failures never crash ----------

def test_backend_not_running(monkeypatch):
    monkeypatch.setattr(enrich.requests, "get", fake_get({}))
    result = enrich.enrich_one(ioc("ip", "8.8.8.8"))
    assert result == {"status": "not enriched", "verdict": "", "score": None,
                      "source": "IP backend", "note": "backend is not running"}


def test_timeout(monkeypatch):
    monkeypatch.setattr(enrich.requests, "get", fake_get({"/api/v1/domain/": requests.exceptions.ReadTimeout()}))
    assert enrich.enrich_one(ioc("domain", "example.com"))["note"] == "no answer in time"


def test_connect_timeout_means_not_running(monkeypatch):
    monkeypatch.setattr(enrich.requests, "get", fake_get({"/api/v1/domain/": requests.exceptions.ConnectTimeout()}))
    assert enrich.enrich_one(ioc("domain", "example.com"))["note"] == "backend is not running"


def test_answer_that_is_not_json(monkeypatch):
    monkeypatch.setattr(enrich.requests, "get", fake_get({"/api/v1/hash/": (502, ValueError("not json"))}))
    assert enrich.enrich_one(ioc("sha256", "a" * 64))["note"] == "the answer was not JSON"


def test_answer_with_an_unexpected_shape(monkeypatch):
    # A JSON list instead of an object.
    monkeypatch.setattr(enrich.requests, "get", fake_get({"/api/v1/hash/": (200, ["not", "a", "dict"])}))
    assert enrich.enrich_one(ioc("sha256", "a" * 64))["note"] == "the backend's answer had an unexpected shape"
    # An object whose "verdict" has no "label".
    monkeypatch.setattr(enrich.requests, "get", fake_get({"/api/v1/hash/": (200, {"verdict": {"score": 5}})}))
    result = enrich.enrich_one(ioc("sha256", "b" * 64))
    assert result["status"] == "not enriched"
    assert result["note"] == "the backend's answer had an unexpected shape"


def test_blocked_ioc_is_never_sent(monkeypatch):
    get = fake_get({})
    monkeypatch.setattr(enrich.requests, "get", get)
    result = enrich.enrich_one(ioc("ip", "2606:4700::1", enrich_ok=False, why_not="IPv6 is not supported"))
    assert result["status"] == "not enriched"
    assert get.calls == []


# ---------- rate limit and cache ----------

def test_at_most_four_new_hashes_per_run_and_results_are_cached(monkeypatch):
    get = fake_get({"/api/v1/hash/": load_backend_answer("hash_found.json")})
    monkeypatch.setattr(enrich.requests, "get", get)
    hashes = [ioc("sha256", str(n) * 64) for n in range(6)]

    first = enrich.enrich_all(hashes)
    assert len(get.calls) == 4
    waiting = [r for r in first.values() if "press Enrich more" in r["note"]]
    assert len(waiting) == 2

    second = enrich.enrich_all(hashes)  # the 4 cached ones cost nothing; the last 2 are sent now
    assert len(get.calls) == 6
    assert all(r["status"] == "enriched" for r in second.values())


def test_at_most_twenty_new_ips_and_domains_per_run(monkeypatch):
    get = fake_get({"/api/ip/": load_backend_answer("ip_ok.json"),
                    "/api/v1/domain/": load_backend_answer("domain_ok.json")})
    monkeypatch.setattr(enrich.requests, "get", get)
    ips = [ioc("ip", f"8.8.{n}.1") for n in range(22)]
    domains = [ioc("domain", f"site{n}.example.com") for n in range(22)]

    results = enrich.enrich_all(ips + domains)
    assert len(get.calls) == 40  # 20 IPs + 20 domains
    waiting = [r for r in results.values() if "press Enrich more" in r["note"]]
    assert len(waiting) == 4     # 2 IPs + 2 domains wait for the next run


def test_errors_are_not_cached(monkeypatch):
    monkeypatch.setattr(enrich.requests, "get", fake_get({}))
    enrich.enrich_one(ioc("ip", "8.8.8.8"))
    monkeypatch.setattr(enrich.requests, "get", fake_get({"/api/ip/": load_backend_answer("ip_ok.json")}))
    assert enrich.enrich_one(ioc("ip", "8.8.8.8"))["status"] == "enriched"


def test_health(monkeypatch):
    monkeypatch.setattr(enrich.requests, "get", fake_get({
        "/api/v1/health": (200, {"status": "ok"}),
        "/api/ip/": (400, {"error": "invalid_ip"}),  # the IP backend's answer to an empty address
    }))
    assert enrich.check_health() == {"Hash backend": True, "IP backend": True, "DNS backend": True}
    monkeypatch.setattr(enrich.requests, "get", fake_get({}))
    assert enrich.check_health() == {"Hash backend": False, "IP backend": False, "DNS backend": False}


@pytest.mark.parametrize("name", ["hash_found.json", "ip_ok.json", "domain_ok.json"])
def test_saved_answers_contain_no_api_key(name):
    text = str(load_backend_answer(name)).lower()
    assert "api_key" not in text and "apikey" not in text
