"""Ask the three local enrichment backends about IOCs, over HTTP on 127.0.0.1.

    hashes  -> hash-enrich-2            GET /api/v1/hash/{sha256}     (port 8000)
    IPs     -> enrichment-portal-simple GET /api/ip/{ip}              (port 5001)
    domains -> ioc-simple-dns           GET /api/v1/domain/{name}     (port 8010)

Every lookup returns one plain dict, whatever happens:
    {"status": "enriched" or "not enriched", "verdict": "malicious", "score": 90,
     "source": "hash backend", "note": "VirusTotal: 49 engines say malicious"}

A backend that is down, slow or confused gives "not enriched" with a note. It never crashes the app.
Only IOCs with ioc["enrich"] == True (see iocs.py, the privacy filter) are ever sent.
"""

import os
from concurrent.futures import ThreadPoolExecutor, as_completed

import requests

HASH_URL = os.environ.get("HASH_BACKEND_URL", "http://127.0.0.1:8000")
IP_URL = os.environ.get("IP_BACKEND_URL", "http://127.0.0.1:5001")
DOMAIN_URL = os.environ.get("DOMAIN_BACKEND_URL", "http://127.0.0.1:8010")

# (seconds to connect, seconds to wait for the answer)
HEALTH_TIMEOUT = (2, 2)
HASH_TIMEOUT = (2, 30)    # the hash backend itself gives up after 12 s
IP_TIMEOUT = (2, 30)      # three sources one after another
DOMAIN_TIMEOUT = (2, 75)  # crt.sh alone can take about 60 s

# Most new lookups sent per press of "Enrich" (cached answers don't count). The rest wait
# for "Enrich more", so one big log cannot flood the backends or their free-tier limits.
MAX_NEW_PER_RUN = {"sha256": 4,   # VirusTotal's free tier allows 4 lookups a minute
                   "ip": 20,
                   "domain": 20}
WAIT_NOTES = {"sha256": "waiting: VirusTotal allows 4 hashes a minute, press Enrich more in a minute",
              "ip": "waiting: at most 20 new IPs per run, press Enrich more to continue",
              "domain": "waiting: at most 20 new domains per run, press Enrich more to continue"}
SOURCES = {"sha256": "hash backend", "ip": "IP backend", "domain": "DNS backend"}

# How many lookups run at the same time. Each lookup mostly waits for a backend (and the backend
# for the internet), so running a few side by side makes the total about as long as the slowest
# one instead of all of them added up. 4 keeps the load on each backend small.
MAX_AT_ONCE = 4

# Results kept in memory while the app runs: (type, value) -> result. Errors are never kept.
_cache = {}


def not_enriched(note, source=""):
    return {"status": "not enriched", "verdict": "", "score": None, "source": source, "note": note}


# ---------- reading each backend's answer (pure functions, tested offline) ----------

def read_hash_answer(status_code, body):
    """hash-enrich-2: 200 with body["verdict"] = {"score", "label", "reasons", ...}."""
    if status_code != 200 or "verdict" not in body:
        return not_enriched(body.get("error", f"hash backend answered HTTP {status_code}"), "hash backend")
    verdict = body["verdict"]
    note = "; ".join(verdict.get("reasons", [])[:3])
    if verdict.get("failed_sources"):
        note += " (failed: " + ", ".join(verdict["failed_sources"]) + ")"
    return {"status": "enriched", "verdict": verdict["label"], "score": verdict["score"],
            "source": "hash backend", "note": note}


def read_ip_answer(status_code, body):
    """enrichment-portal-simple: 200 with body["verdict"] = {"level", "score", "summary", ...}."""
    if status_code == 503:
        return not_enriched("every IP source was unavailable, try again later", "IP backend")
    if status_code != 200 or "verdict" not in body:
        return not_enriched(body.get("message", f"IP backend answered HTTP {status_code}"), "IP backend")
    verdict = body["verdict"]
    if verdict["level"] == "not_applicable":
        return not_enriched("private or reserved address, not judged", "IP backend")
    return {"status": "enriched", "verdict": verdict["level"], "score": verdict["score"],
            "source": "IP backend", "note": verdict.get("summary") or "; ".join(verdict.get("reasons", []))}


def read_domain_answer(status_code, body):
    """ioc-simple-dns: 200 with body["assessment"] = {"verdict", "verdict_label", "average", ...}."""
    if status_code != 200 or "assessment" not in body:
        return not_enriched(body.get("error", f"DNS backend answered HTTP {status_code}"), "DNS backend")
    assessment = body["assessment"]
    if assessment["verdict"] == "not_graded":
        return not_enriched("no DNS source could be reached", "DNS backend")
    note = assessment["verdict_label"]
    if assessment.get("verdict_note"):
        note += f" ({assessment['verdict_note']})"
    return {"status": "enriched", "verdict": assessment["verdict"], "score": assessment["average"],
            "source": "DNS backend", "note": note}


def simple_verdict(result):
    """Turn each backend's own words into 'malicious', 'suspicious' or '' for our verdict.

    The DNS backend only judges registration facts ("not a malware test"), so its 'likely'
    counts as suspicious and only 'definitely' counts as malicious.
    """
    word = result.get("verdict", "")
    if word in ("malicious", "definitely_malware"):
        return "malicious"
    if word in ("suspicious", "likely_malware"):
        return "suspicious"
    return ""


# ---------- talking to the backends ----------

def ask(url, timeout, reader, source):
    """GET one URL and read the answer. Every failure becomes 'not enriched'."""
    try:
        response = requests.get(url, timeout=timeout)
    except requests.exceptions.ConnectTimeout:
        # On Windows a port nobody listens on often looks like a connect timeout.
        return not_enriched("backend is not running", source)
    except requests.exceptions.Timeout:
        return not_enriched("no answer in time", source)
    except requests.exceptions.ConnectionError:
        return not_enriched("backend is not running", source)
    except requests.exceptions.RequestException:
        # Any other request problem (e.g. an invalid URL, too many redirects).
        return not_enriched("the request failed", source)
    try:
        body = response.json()
    except ValueError:
        return not_enriched("the answer was not JSON", source)
    # Every backend answers with a JSON object (a dict). Anything else, or a dict with missing
    # fields, means the backend changed: say so instead of crashing the page.
    if not isinstance(body, dict):
        return not_enriched("the backend's answer had an unexpected shape", source)
    try:
        return reader(response.status_code, body)
    except (KeyError, TypeError, AttributeError):
        return not_enriched("the backend's answer had an unexpected shape", source)


def enrich_one(ioc):
    """Look up one IOC (only if the privacy filter allowed it)."""
    if not ioc["enrich"]:
        return not_enriched(ioc["why_not"])

    key = (ioc["type"], ioc["value"])
    if key in _cache:
        return _cache[key]

    if ioc["type"] == "sha256":
        result = ask(f"{HASH_URL}/api/v1/hash/{ioc['value']}", HASH_TIMEOUT, read_hash_answer, "hash backend")
    elif ioc["type"] == "ip":
        result = ask(f"{IP_URL}/api/ip/{ioc['value']}", IP_TIMEOUT, read_ip_answer, "IP backend")
    elif ioc["type"] == "domain":
        result = ask(f"{DOMAIN_URL}/api/v1/domain/{ioc['value']}", DOMAIN_TIMEOUT,
                     read_domain_answer, "DNS backend")
    else:
        return not_enriched("no enrichment backend for this type")

    if result["status"] == "enriched":
        _cache[key] = result
    return result


def enrich_all(iocs, on_progress=None):
    """Enrich every allowed IOC. Returns {(type, value): result}.

    At most MAX_NEW_PER_RUN new lookups of each type are sent per run (4 hashes, 20 IPs,
    20 domains; cached ones don't count). The rest are marked so the analyst can press
    "Enrich more" later. Up to MAX_AT_ONCE lookups run at the same time; on_progress(number,
    total, ioc) is called each time one is answered.
    """
    results = {}
    sent = {"sha256": 0, "ip": 0, "domain": 0}  # new lookups sent in this run, per type
    to_do = [i for i in iocs if i["type"] in ("sha256", "ip", "domain")]

    # 1. Decide, one by one as before, which IOCs are looked up now (the limits stay exact).
    to_look_up = []
    for ioc in to_do:
        key = (ioc["type"], ioc["value"])
        if ioc["enrich"] and key not in _cache:
            if sent[ioc["type"]] >= MAX_NEW_PER_RUN[ioc["type"]]:
                results[key] = not_enriched(WAIT_NOTES[ioc["type"]], SOURCES[ioc["type"]])
                continue
            sent[ioc["type"]] += 1
        to_look_up.append(ioc)  # also blocked and cached ones: enrich_one answers them at once

    # 2. Look them up side by side. A "thread pool" is a small team of helpers (here at most
    #    MAX_AT_ONCE) that each run enrich_one for one IOC; pool.submit hands out the work.
    #    as_completed gives the lookups back in the order they finish, so the progress bar
    #    moves as soon as any backend answers.
    with ThreadPoolExecutor(max_workers=MAX_AT_ONCE) as pool:
        running = {pool.submit(enrich_one, ioc): ioc for ioc in to_look_up}
        for number, finished in enumerate(as_completed(running), start=1):
            ioc = running[finished]
            results[(ioc["type"], ioc["value"])] = finished.result()
            if on_progress:
                on_progress(number, len(running), ioc)
    return results


def check_health():
    """Return {"Hash backend": True/False, "IP backend": ..., "DNS backend": ...}."""
    def answers(url, any_status_is_ok=False):
        try:
            response = requests.get(url, timeout=HEALTH_TIMEOUT)
        except requests.exceptions.RequestException:
            return False
        return response.status_code < 500 if any_status_is_ok else response.status_code == 200

    return {
        "Hash backend": answers(f"{HASH_URL}/api/v1/health"),
        # The IP backend has no health route. "/api/ip/" with no address is answered with a
        # 400 at once, without calling any outside source, so any answer means "running".
        "IP backend": answers(f"{IP_URL}/api/ip/", any_status_is_ok=True),
        "DNS backend": answers(f"{DOMAIN_URL}/api/v1/health"),
    }


def clear_cache():
    _cache.clear()
