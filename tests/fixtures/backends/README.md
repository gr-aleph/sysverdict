# Saved backend answers

The enrichment tests replay these files instead of calling the backends, so `pytest` needs no
network, no running backend and no API key. This is the same pattern the three backend repos use.

| File | Backend answer | Where it comes from |
| --- | --- | --- |
| `hash_found.json` | `GET /api/v1/hash/<Mirai sha256>`, malicious | Recorded by hash-enrich-2 (`tests/fixtures/portal/found.json`), copied unchanged |
| `hash_not_found.json` | `GET /api/v1/hash/<64 zeros>`, unknown hash | same repo, `not_found.json` |
| `hash_one_source_error.json` | malicious, but ThreatFox failed | same repo, `one_source_error.json` |
| `ip_ok.json` | `GET /api/ip/8.8.8.8` (HTTP 200) | Recorded by enrichment-portal-simple (`mcp_server/tests/samples/backend_ok.json`), unchanged |
| `ip_private.json` | `GET /api/ip/192.168.1.1` (HTTP 200, all sources skipped) | same repo, `backend_private.json` |
| `ip_400_ipv6.json` | `GET /api/ip/2001:4860:4860::8888` (HTTP 400) | same repo, `backend_400_ipv6.json` |
| `domain_ok.json` | `GET /api/v1/domain/example.com` (HTTP 200) | **Not recorded**: built from the example answer in ioc-simple-dns `design.md` (API contract v1), because that repo saves source replies, not whole API answers. Replace it with a real recording when the DNS backend runs: `curl.exe -o domain_ok.json http://127.0.0.1:8010/api/v1/domain/example.com` (then wrap it as `{"status_code": 200, "body": ...}`). |

The hash and domain files are wrapped as `{"status_code": ..., "body": ...}`; the IP files are the
bare body (their status code is in the table). None of them contains an API key.
