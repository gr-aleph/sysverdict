# One-click start for SysVerdict: opens the three enrichment backends and the app,
# each in its own PowerShell window, then opens the app in the browser.
#
# Run from cmd.exe:   powershell -ExecutionPolicy Bypass -File start.ps1
# or double-click start.cmd.
#
# The three backends live side by side in one folder, $BackendsDir (by default
# "enrichment-backends" next to this project; change it below if yours is elsewhere),
# each installed as its README says, with its own virtual environment.
# A missing backend is skipped: the app then shows "not running" / "not enriched" for it.

$Here = $PSScriptRoot
$BackendsDir = Join-Path (Split-Path $Here -Parent) "enrichment-backends"
$HashDir = Join-Path $BackendsDir "hash-enrich-2"             # needs VT_API_KEY and ABUSECH_AUTH_KEY in its .env
$IpDir = Join-Path $BackendsDir "enrichment-portal-simple"    # AbuseIPDB key optional
$DnsDir = Join-Path $BackendsDir "ioc-simple-dns"             # no keys

# Find a project's Python: its .venv or venv folder.
function Find-Python($Folder) {
    foreach ($Name in ".venv", "venv") {
        $Python = Join-Path $Folder "$Name\Scripts\python.exe"
        if (Test-Path $Python) { return $Python }
    }
    return $null
}

# Open a new PowerShell window, minimized to the taskbar, that runs one command in one folder.
# Click it in the taskbar to read errors; close it to stop that program.
function Start-Window($Title, $Folder, $Command) {
    $Script = "`$Host.UI.RawUI.WindowTitle = '$Title'; Set-Location '$Folder'; $Command"
    Start-Process powershell -ArgumentList "-NoExit", "-Command", $Script -WindowStyle Minimized
    Write-Host "Started (minimized): $Title"
}

function Start-Backend($Title, $Folder, $WorkFolder, $Arguments) {
    $Python = Find-Python $Folder
    if (-not $Python) {
        Write-Host "Skipped: $Title (no project with a .venv found at $Folder)" -ForegroundColor Yellow
        return
    }
    Start-Window $Title $WorkFolder "& '$Python' $Arguments"
}

Start-Backend "Hash backend :8000" $HashDir $HashDir "-m uvicorn backend.main:app --host 127.0.0.1 --port 8000 --no-use-colors"
Start-Backend "IP backend :5001" $IpDir (Join-Path $IpDir "backend") "-m flask --app api run --host 127.0.0.1 --port 5001"
Start-Backend "DNS backend :8010" $DnsDir $DnsDir "-m backend.app"

$AppPython = Find-Python $Here
if (-not $AppPython) {
    Write-Host "SysVerdict is not installed yet. See README.md, section Install." -ForegroundColor Red
    exit 1
}
Start-Window "SysVerdict :8501" $Here "& '$AppPython' -m streamlit run app.py --server.headless true"

Start-Sleep -Seconds 4
Start-Process "http://127.0.0.1:8501"
