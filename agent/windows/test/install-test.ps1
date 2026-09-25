# End-to-end test of certportal-agent.msi on a Windows host (run elevated).
# Starts the mock control plane, installs the MSI, checks the service enrolls,
# polls, locks down its data, restarts after a crash, and uninstalls cleanly.
#
#   pwsh agent/windows/test/install-test.ps1 -Msi agent/windows/dist/certportal-agent.msi

param([Parameter(Mandatory)][string]$Msi)
$ErrorActionPreference = 'Stop'
$Msi = (Resolve-Path $Msi).Path
$Url = 'http://127.0.0.1:8787'
$DataDir = Join-Path $env:ProgramData 'CertPortal\Agent'
$InstallDir = Join-Path $env:ProgramFiles 'CertPortal\Agent'
$Shortcut = Join-Path $env:ProgramData 'Microsoft\Windows\Start Menu\Programs\CertPortal Agent Status.url'
$Logs = (Get-Location).Path   # msiexec logs land here

function DumpLogs {
  Get-ChildItem "$DataDir\logs" -ErrorAction SilentlyContinue | ForEach-Object {
    Write-Host "--- $($_.Name)"; Get-Content $_.FullName -Tail 40
  }
}

function Fail($msg) { Write-Host "FAIL: $msg" -ForegroundColor Red; DumpLogs; exit 1 }
function Pass($msg) { Write-Host "ok: $msg" -ForegroundColor Green }
function Msiexec([string[]]$ArgList) {
  $p = Start-Process msiexec.exe -ArgumentList $ArgList -Wait -PassThru
  return $p.ExitCode
}
function Stats { Invoke-RestMethod "$Url/_stats" }
function WaitFor([scriptblock]$Cond, [string]$What, [int]$Seconds = 60) {
  $deadline = (Get-Date).AddSeconds($Seconds)
  while ((Get-Date) -lt $deadline) { if (& $Cond) { return } Start-Sleep -Seconds 2 }
  Fail "timed out waiting for $What"
}
$mock = Start-Process node -ArgumentList (Join-Path $PSScriptRoot 'mock-control-plane.js') -PassThru -NoNewWindow
try {
  WaitFor { try { Stats; $true } catch { $false } } 'mock control plane' 15

  # 1. without a token the install is refused (launch condition -> 1603)
  $code = Msiexec @('/i', "`"$Msi`"", '/qn', '/l*v', "`"$Logs\no-token.log`"")
  if ($code -ne 1603) { Fail "install without token exited $code, expected 1603" }
  if (Get-Service CertPortalAgent -ErrorAction SilentlyContinue) { Fail 'service exists after refused install' }
  Pass 'install without a token is refused'

  # 2. install
  $code = Msiexec @('/i', "`"$Msi`"", "CONTROL_PLANE_URL=$Url", 'ENROLL_TOKEN=test-token', 'AGENT_NAME="ci agent"', '/qn', '/l*v', "`"$Logs\install.log`"")
  if ($code -ne 0) { Fail "install exited $code" }
  if (Select-String -Path "$Logs\install.log" -Pattern 'test-token' -Quiet) { Fail 'enrollment token appears in the install log' }
  Pass 'installed; token kept out of the install log'

  $svc = Get-CimInstance Win32_Service -Filter "Name='CertPortalAgent'"
  if (-not $svc) { Fail 'service not registered' }
  if ($svc.StartMode -ne 'Auto') { Fail "start mode is $($svc.StartMode)" }
  if ($svc.StartName -notmatch 'LocalService') { Fail "runs as $($svc.StartName)" }
  Pass "service registered (auto start, $($svc.StartName))"

  WaitFor { (Stats).polls -ge 1 } 'the agent to enroll and poll' 90
  $s = Stats
  if ($s.enrolls -ne 1) { Fail "enrolled $($s.enrolls) times" }
  if ($s.lastAuth -ne 'Bearer agent-1.secret-1') { Fail "polled with '$($s.lastAuth)'" }
  Pass "enrolled and polling (agent version $($s.lastVersion))"

  $cfg = Get-Content "$DataDir\config.json" -Raw | ConvertFrom-Json
  if ($cfg.PSObject.Properties.Name -contains 'ENROLL_TOKEN') { Fail 'config.json still holds the enrollment token' }
  if ($cfg.CONTROL_PLANE_URL -ne $Url -or $cfg.AGENT_NAME -ne 'ci agent') { Fail "config.json: $($cfg | ConvertTo-Json -Compress)" }
  if (-not (Test-Path "$DataDir\agent.json")) { Fail 'agent.json missing' }
  Pass 'config written, token removed after enrollment'

  $st = Invoke-RestMethod 'http://127.0.0.1:47801/status.json'
  if (-not $st.connected -or $st.agentId -ne 'agent-1' -or $st.agentName -ne 'ci agent') { Fail "status page: $($st | ConvertTo-Json -Compress)" }
  $html = (Invoke-WebRequest 'http://127.0.0.1:47801/' -UseBasicParsing).Content
  if ($html -notmatch 'Connected') { Fail 'status page does not say Connected' }
  if (-not (Test-Path $Shortcut)) { Fail "Start menu shortcut missing: $Shortcut" }
  Pass 'status page reports connected; Start menu shortcut installed'

  $acl = Get-Acl $DataDir
  if (-not $acl.AreAccessRulesProtected) { Fail 'data folder still inherits permissions' }
  $who = $acl.Access | ForEach-Object { $_.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value } | Sort-Object -Unique
  $extra = $who | Where-Object { $_ -notin @('S-1-5-18', 'S-1-5-32-544', 'S-1-5-19') }
  if ($extra) { Fail "unexpected access to the data folder: $extra" }
  Pass "data folder limited to SYSTEM, Administrators, LocalService"

  # 3. crash recovery: kill the agent, the service should bring it back
  $before = (Stats).polls
  Get-Process certportal-agent | Stop-Process -Force
  Start-Sleep -Seconds 3
  WaitFor { (Get-Process certportal-agent -ErrorAction SilentlyContinue) -and (Stats).polls -gt $before + 1 } 'the agent to restart' 90
  Pass 'agent restarted after being killed'

  # 4. uninstall removes the service, program files and data
  $code = Msiexec @('/x', "`"$Msi`"", '/qn', '/l*v', "`"$Logs\uninstall.log`"")
  if ($code -ne 0) { Fail "uninstall exited $code" }
  if (Get-Service CertPortalAgent -ErrorAction SilentlyContinue) { Fail 'service still registered' }
  if (Test-Path $InstallDir) { Fail "$InstallDir still exists" }
  if (Test-Path $DataDir) { Fail "$DataDir still exists" }
  if (Test-Path $Shortcut) { Fail 'Start menu shortcut still exists' }
  Pass 'uninstalled cleanly'
}
catch { DumpLogs; throw }
finally {
  Stop-Process -Id $mock.Id -ErrorAction SilentlyContinue
}
Write-Host 'all checks passed' -ForegroundColor Green
