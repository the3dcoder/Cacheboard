# Set up several Claude subscriptions side by side.
#
# Claude Code keeps its entire auth state under CLAUDE_CONFIG_DIR, so pointing
# it at a different folder gives a completely separate login. That means all
# your accounts can be signed in at once — no logging out to switch.
#
# This creates one profile folder per account, signs each in, wires them into
# the backend's .env, and verifies each one against the live usage endpoint.

$ErrorActionPreference = 'Stop'

$exe      = Join-Path $env:APPDATA 'npm\node_modules\@anthropic-ai\claude-code\bin\claude.exe'
$root     = Join-Path $env:USERPROFILE 'claude-profiles'
$envFile  = 'C:\Users\ehaye\Desktop\Cacheboard\server\.env'
$composeF = 'C:\Users\ehaye\Desktop\Cacheboard\server\docker-compose.yml'
$srvDir   = 'C:\Users\ehaye\Desktop\Cacheboard\server'

if (-not (Test-Path $exe)) { Write-Host "Claude CLI not found at $exe" -ForegroundColor Red; Read-Host "Enter to close"; exit 1 }

Write-Host ""
Write-Host " Claude multi-account setup" -ForegroundColor Cyan
Write-Host " ---------------------------------------------------------------"
Write-Host " Each account gets its own profile folder and stays signed in."
Write-Host " Sign-in is copy/paste: a browser opens, you copy the CODE it"
Write-Host " shows, then paste it back into this window."
Write-Host " ---------------------------------------------------------------"
Write-Host ""

$names = Read-Host " Short names for your accounts, comma separated (e.g. max20,max5,pro)"
$names = ($names -split ',' | ForEach-Object { ($_ -replace '[^A-Za-z0-9_]','').Trim() } | Where-Object { $_ })
if (-not $names) { Write-Host " No usable names given." -ForegroundColor Red; Read-Host "Enter to close"; exit 1 }

$configured = @()
foreach ($n in $names) {
    $dir = Join-Path $root $n
    New-Item -ItemType Directory -Force -Path $dir | Out-Null
    Write-Host ""
    Write-Host " =========================================================" -ForegroundColor Cyan
    Write-Host "  Account: $n" -ForegroundColor Cyan
    Write-Host "  Profile: $dir"
    Write-Host " =========================================================" -ForegroundColor Cyan

    $env:CLAUDE_CONFIG_DIR = $dir
    $status = & $exe auth status 2>&1 | Out-String
    if ($status -match '"loggedIn":\s*true') {
        $mail = if ($status -match '"email":\s*"([^"]+)"') { $Matches[1] } else { 'unknown' }
        Write-Host "  Already signed in as $mail - skipping." -ForegroundColor Green
    } else {
        Write-Host "  Sign in to the Gmail account you want as '$n'."
        Write-Host "  (Use 'Continue with Google' on the page if you like.)"
        Write-Host ""
        & $exe auth login
        $status = & $exe auth status 2>&1 | Out-String
    }

    if ($status -match '"loggedIn":\s*true') {
        $mail = if ($status -match '"email":\s*"([^"]+)"') { $Matches[1] } else { '' }
        $plan = if ($status -match '"subscriptionType":\s*"([^"]+)"') { $Matches[1] } else { '' }
        Write-Host "  OK: $mail ($plan)" -ForegroundColor Green
        $configured += [pscustomobject]@{ Name = $n; Dir = $dir; Email = $mail; Plan = $plan }
    } else {
        Write-Host "  Not signed in - skipping '$n'. Re-run to try again." -ForegroundColor Red
    }
    Remove-Item Env:\CLAUDE_CONFIG_DIR -ErrorAction SilentlyContinue
}

if (-not $configured) { Write-Host ""; Write-Host " Nothing configured." -ForegroundColor Red; Read-Host "Enter to close"; exit 1 }

# --- wire into .env (container paths) ---
$lines = [System.IO.File]::ReadAllLines($envFile) | Where-Object { $_ -notmatch '^\s*CLAUDE_CREDENTIALS_FILE_' }
$add = @("", "# Claude profiles - written by setup-claude-profiles")
foreach ($c in $configured) { $add += "CLAUDE_CREDENTIALS_FILE_$($c.Name.ToUpper())=/profiles/$($c.Name)/.credentials.json" }
[System.IO.File]::WriteAllLines($envFile, @($lines) + $add)
Write-Host ""
Write-Host " Wrote $($configured.Count) entries to server\.env" -ForegroundColor Green

# --- mount the profile root read-only ---
$yml = [System.IO.File]::ReadAllText($composeF)
if ($yml -notmatch '/profiles:ro') {
    $mount = "      - `${CLAUDE_PROFILES_HOST_DIR:-./.no-profiles}:/profiles:ro`r`n      # Rotated OAuth refresh tokens survive restarts here."
    $yml = $yml.Replace("      # Rotated OAuth refresh tokens survive restarts here.", $mount)
    [System.IO.File]::WriteAllText($composeF, $yml)
    Write-Host " Added the /profiles mount to docker-compose.yml" -ForegroundColor Green
}
$envLines = [System.IO.File]::ReadAllLines($envFile) | Where-Object { $_ -notmatch '^\s*CLAUDE_PROFILES_HOST_DIR=' }
[System.IO.File]::WriteAllLines($envFile, @($envLines) + @("CLAUDE_PROFILES_HOST_DIR=$($root -replace '\\','/')"))

Write-Host " Restarting the backend..."
Push-Location $srvDir
try { docker compose up -d 2>&1 | Select-Object -Last 1 | Out-Host } finally { Pop-Location }
Start-Sleep -Seconds 7

# --- verify each account end to end ---
$dash = ((Get-Content $envFile | Where-Object { $_ -like 'DASHBOARD_TOKEN=*' }) -split '=', 2)[1]
Write-Host ""
Write-Host " ---------------- verifying ----------------" -ForegroundColor Cyan
foreach ($c in $configured) {
    try {
        $r = Invoke-WebRequest "http://localhost:8787/usage/claude-plan?account=$($c.Name.ToLower())" `
             -Headers @{ Authorization = "Bearer $dash" } -UseBasicParsing -TimeoutSec 60
        $j = $r.Content | ConvertFrom-Json
        Write-Host ""
        Write-Host "  $($c.Name)  [$($c.Email) - $($c.Plan)]" -ForegroundColor Green
        foreach ($s in $j.series) { "     {0,-24} {1,5}% used" -f $s.label, $s.used | Write-Host }
    } catch {
        $resp = $_.Exception.Response
        $msg = if ($resp) { $sr = New-Object System.IO.StreamReader($resp.GetResponseStream()); $sr.ReadToEnd() } else { $_.Exception.Message }
        Write-Host "  $($c.Name): FAILED - $msg" -ForegroundColor Red
    }
}

Write-Host ""
Write-Host " ---------------------------------------------------------------" -ForegroundColor Cyan
Write-Host " In the dashboard, add one card per account:"
foreach ($c in $configured) {
    Write-Host "   + Add Account > Claude Code > Plan limits"
    Write-Host "     Claude account: $($c.Name.ToLower())    Owner: $($c.Email)"
}
Write-Host ""
Write-Host " To actually WORK in a given account:"
Write-Host "   `$env:CLAUDE_CONFIG_DIR='$root\<name>'; claude"
Write-Host ""
Read-Host "Press Enter to close"
