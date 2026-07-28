# Adds a Claude account token to the Cacheboard backend.
#
# You paste a token from `claude setup-token`; this writes it into
# server/.env under the right variable name, restarts the container, and
# verifies the account actually works. The token is read without echoing to
# the console and is never printed back.

$ErrorActionPreference = 'Stop'
$envFile = 'C:\Users\ehaye\Desktop\Cacheboard\server\.env'
$srvDir  = 'C:\Users\ehaye\Desktop\Cacheboard\server'

if (-not (Test-Path $envFile)) {
    Write-Host "Can't find $envFile" -ForegroundColor Red
    Read-Host "Press Enter to close"; exit 1
}

Write-Host ""
Write-Host " Add a Claude account to Cacheboard" -ForegroundColor Cyan
Write-Host " ---------------------------------------------------------------"
Write-Host " First, in a normal PowerShell window, run:   claude setup-token"
Write-Host " Copy the token it gives you, then come back here."
Write-Host " ---------------------------------------------------------------"
Write-Host ""

$name = Read-Host " Short name for this account (e.g. personal, work)"
$name = ($name -replace '[^A-Za-z0-9_]', '').Trim()
if (-not $name) { Write-Host " That name can't be used." -ForegroundColor Red; Read-Host "Enter to close"; exit 1 }

# Read without echoing, so the token doesn't sit in console scrollback.
$secure = Read-Host " Paste the token (input is hidden)" -AsSecureString
$bstr   = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secure)
$token  = [Runtime.InteropServices.Marshal]::PtrToStringAuto($bstr).Trim()
[Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)

if ($token.Length -lt 20) {
    Write-Host " That doesn't look like a token (too short)." -ForegroundColor Red
    Read-Host "Press Enter to close"; exit 1
}
if ($token -notmatch '^sk-ant-') {
    Write-Host " Warning: tokens normally start with 'sk-ant-'. Continuing anyway." -ForegroundColor Yellow
}

$key = "CLAUDE_TOKEN_$($name.ToUpper())"
$lines = [System.IO.File]::ReadAllLines($envFile)
$replaced = $false
$out = foreach ($line in $lines) {
    if ($line -match "^\s*$([regex]::Escape($key))\s*=") { $replaced = $true; "$key=$token" }
    else { $line }
}
if (-not $replaced) { $out = @($out) + @("", "# Added by add-claude-account", "$key=$token") }
[System.IO.File]::WriteAllLines($envFile, $out)

Write-Host ""
Write-Host " $(if($replaced){'Updated'}else{'Added'}) $key in server\.env" -ForegroundColor Green
Write-Host " Restarting the backend..."
Push-Location $srvDir
try { docker compose up -d 2>&1 | Select-Object -Last 1 | Out-Host } finally { Pop-Location }
Start-Sleep -Seconds 6

# Verify against the live endpoint.
$dash = ((Get-Content $envFile | Where-Object { $_ -like 'DASHBOARD_TOKEN=*' }) -split '=', 2)[1]
Write-Host ""
Write-Host " ---------------- verifying ----------------" -ForegroundColor Cyan
try {
    $r = Invoke-WebRequest "http://localhost:8787/usage/claude-plan?account=$($name.ToLower())" `
         -Headers @{ Authorization = "Bearer $dash" } -UseBasicParsing -TimeoutSec 60
    $j = $r.Content | ConvertFrom-Json
    Write-Host " WORKING - $($j.series.Count) limit windows:" -ForegroundColor Green
    foreach ($s in $j.series) { "   {0,-24} {1,5}% used" -f $s.label, $s.used | Write-Host }
    Write-Host ""
    Write-Host " Now in the dashboard: + Add Account > Claude Code > Plan limits,"
    Write-Host " put '$($name.ToLower())' in the Claude account field, then Refresh."
} catch {
    $resp = $_.Exception.Response
    if ($resp) {
        $sr = New-Object System.IO.StreamReader($resp.GetResponseStream())
        $body = $sr.ReadToEnd()
        try { Write-Host " FAILED: $(($body | ConvertFrom-Json).error)" -ForegroundColor Red }
        catch { Write-Host " FAILED: $body" -ForegroundColor Red }
    } else {
        Write-Host " FAILED: $($_.Exception.Message)" -ForegroundColor Red
    }
}
Write-Host ""
Read-Host "Press Enter to close"
