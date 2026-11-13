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


# ---------- 1a: recon ----------

# ---------- 1b: lookalike ----------

def test_brand_owned_domain_is_not_a_lookalike():
    teams = USER + "\\AppData\\Local\\Microsoft\\Teams\\ms-teams.exe"
    events = [event(1, 22, "2026-02-01 09:00:00.000", Image=teams, QueryName="teams.cloud.microsoft"),
              event(2, 22, "2026-02-01 09:00:01.000", Image=teams, QueryName="cloud.microsoft")]
    assert run_checks(events) == []


# ---------- 1c: services ----------

# ---------- 1d: LSASS ----------

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

# ---------- Block 2: privacy ----------

# ---------- Block 3: encoding does not hide a command from the rule lists ----------

def encoded(script):
    import base64
    return "powershell -NoProfile -EncodedCommand " + base64.b64encode(script.encode("utf-16-le")).decode()


# ---------- Block 4: the page never crashes ----------

# ---------- Block 5: accuracy ----------

def ps_strength(script):
    events = [event(1, 1, "2026-02-01 09:00:00.000", ProcessGuid="{p}", Image=PS, ParentProcessGuid="{d}",
                    ParentImage=USER + "\\Downloads\\helper.exe", CommandLine="powershell -c " + script)]
    return strengths(events, "suspicious_powershell")


def test_ransom_note_names_and_paths_with_spaces():
    def opened(command):
        return [event(1, 1, "2026-02-01 09:00:00.000", ProcessGuid="{n}", Image=SYS + "notepad.exe",
                      ParentImage=USER + "\\Downloads\\x.exe", CommandLine=command)]
    assert "ransom_note" in checks_fired(opened("notepad.exe C:\\Users\\Public\\RESTORE_MY_FILES.txt"))
    assert "ransom_note" in checks_fired(opened("notepad.exe C:\\Users\\a\\Desktop\\HOW TO RECOVER.txt"))
    assert "ransom_note" not in checks_fired(opened("notepad.exe C:\\Program Files\\App\\readme.txt"))


# ---------- new Low checks (policy: unsure = Suspicious) ----------

def test_script_host_going_online_is_low():
    def connect(image, ip, initiated="true"):
        return [event(1, 3, "2026-02-01 09:00:00.000", ProcessGuid="{s}", Image=image,
                      DestinationIp=ip, DestinationPort="443", Initiated=initiated)]
    assert strengths(connect(PS, "93.184.216.34"), "script_host_online") == ["Weak"]
    assert strengths(connect(SYS + "mshta.exe", "93.184.216.34"), "script_host_online") == ["Weak"]
    assert "script_host_online" not in checks_fired(connect(PS, "10.0.0.5"))                 # private
    assert "script_host_online" not in checks_fired(connect(PS, "93.184.216.34", "false"))   # incoming
    assert "script_host_online" not in checks_fired(connect(SYS + "svchost.exe", "93.184.216.34"))


def test_remote_access_tool_is_low_once_per_tool():
    tool = "C:\\Program Files (x86)\\AnyDesk\\AnyDesk.exe"
    events = [event(n, 1, "2026-02-01 09:00:0%d.000" % n, ProcessGuid="{a%d}" % n, Image=tool) for n in (1, 2)]
    assert strengths(events, "remote_access_tool") == ["Weak"]
    assert "remote_access_tool" not in checks_fired([event(1, 1, "2026-02-01 09:00:00.000", Image=SYS + "mstsc.exe")])


# ---------- web shell and data theft ----------

W3WP = SYS + "inetsrv\\w3wp.exe"


def test_web_server_starting_a_shell_is_strong_and_backs_up_its_recon():
    events = [event(1, 1, "2026-02-01 09:00:00.000", ProcessGuid="{w3}", Image=W3WP),
              event(2, 1, "2026-02-01 09:00:01.000", ProcessGuid="{c}", ParentProcessGuid="{w3}",
                    Image=SYS + "cmd.exe", ParentImage=W3WP, CommandLine="cmd /c whoami & ipconfig"),
              event(3, 1, "2026-02-01 09:00:01.100", ProcessGuid="{w}", ParentProcessGuid="{c}",
                    Image=SYS + "whoami.exe", ParentImage=SYS + "cmd.exe"),
              event(4, 1, "2026-02-01 09:00:01.200", ProcessGuid="{i}", ParentProcessGuid="{c}",
                    Image=SYS + "ipconfig.exe", ParentImage=SYS + "cmd.exe")]
    assert strengths(events, "web_shell") == ["Strong"]
    assert strengths(events, "recon_burst") == ["Strong"]          # backed up by the web shell
    # A web server starting its own helper (not a shell) is normal.
    helper = [event(1, 1, "2026-02-01 09:00:00.000", ProcessGuid="{h}", Image="C:\\php\\php-cgi.exe",
                    ParentImage=W3WP)]
    assert "web_shell" not in checks_fired(helper)


def archive_run(command):
    return [event(1, 1, "2026-02-01 09:00:00.000", ProcessGuid="{z}", Image="C:\\Program Files\\7-Zip\\7z.exe",
                  CommandLine=command)]


def test_archive_is_low_and_a_disguised_archive_is_strong():
    assert strengths(archive_run('7z.exe a -pSecret1 "C:\\Users\\Public\\out.7z" C:\\docs'), "archive") == ["Weak"]
    assert strengths(archive_run("7z a backup C:\\docs"), "archive") == ["Weak"]          # 7-Zip adds .7z
    assert strengths(archive_run("tar -czf out.tgz docs"), "archive") == ["Weak"]
    assert strengths(archive_run("7z a -tzip C:\\Users\\Public\\holiday.jpg C:\\docs"), "archive") == ["Strong"]
    assert "archive" not in checks_fired(archive_run("7z x C:\\Downloads\\setup.zip"))   # unpacking
    assert "archive" not in checks_fired(archive_run("tar -xf a.tar -C out"))


def files_on(drive, count, ending=".docx"):
    return [event(n, 11, "2026-02-01 09:%02d:%02d.000" % (n // 60, n % 60), ProcessGuid="{x}",
                  Image="C:\\Windows\\explorer.exe", TargetFilename=f"{drive}:\\copy\\file{n}{ending}")
            for n in range(1, count + 1)]


def test_bulk_copy_or_archive_to_another_drive_is_low():
    assert strengths(files_on("E", 20), "copy_to_other_drive") == ["Weak"]
    assert "copy_to_other_drive" not in checks_fired(files_on("E", 19))      # a few files: normal
    assert "copy_to_other_drive" not in checks_fired(files_on("C", 50))      # the system drive
    assert strengths(files_on("F", 1, ending=".7z"), "copy_to_other_drive") == ["Weak"]


def test_transfer_sites_and_upload_tools_are_low():
    edge = "C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe"
    lookups = [event(1, 22, "2026-02-01 09:00:00.000", Image=edge, QueryName="eu.gofile.io"),
               event(2, 22, "2026-02-01 09:00:01.000", Image=edge, QueryName="www.dropbox.com")]
    assert strengths(lookups, "cloud_upload") == ["Weak"]                   # gofile only
    tool = [event(1, 1, "2026-02-01 09:00:00.000", ProcessGuid="{r}", Image="C:\\Users\\Public\\rclone.exe",
                  CommandLine="rclone copy C:\\docs remote:backup")]
    assert strengths(tool, "cloud_upload") == ["Weak"]


