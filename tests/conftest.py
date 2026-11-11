"""Shared test setup: no test may touch the network, and the enrichment cache starts empty."""

import json
import socket
from pathlib import Path

import pytest

from triage import enrich

BACKEND_FIXTURES = Path(__file__).parent / "fixtures" / "backends"


@pytest.fixture(autouse=True)
def no_network(monkeypatch):
    def refuse(*args, **kwargs):
        raise RuntimeError("a test tried to use the network")
    monkeypatch.setattr(socket.socket, "connect", refuse)


@pytest.fixture(autouse=True)
def empty_cache():
    enrich.clear_cache()
    yield
    enrich.clear_cache()


def load_backend_answer(name):
    """Return (status_code, body) of a saved backend answer."""
    data = json.loads((BACKEND_FIXTURES / name).read_text(encoding="utf-8"))
    if "body" in data and "status_code" in data:
        return data["status_code"], data["body"]
    status = 400 if name.startswith("ip_400") else 200
    return status, data
