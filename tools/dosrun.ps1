<#
.SYNOPSIS
    Run a DOS command line under DOSBox-X and bring its output back.

.DESCRIPTION
    Period compilers -- Microsoft C, Lattice C, MASM, Turbo C -- are DOS
    programs. To use them for anything automated you need to drive them
    headlessly and read what they printed, which DOSBox-X does not do on its
    own: it has no host stdout.

    The trick is to redirect inside DOS to a file on a mounted drive, then read
    that file from Windows afterwards. This wraps that up.

.PARAMETER Command
    The DOS command to run, e.g. "CL -c -AS HELLO.C".

.PARAMETER Mounts
    Hashtable of drive letter to host directory, e.g.
    @{ C = $env:MSC_HOME; D = $buildDir }

.PARAMETER WorkDrive
    Drive to change to before running the command. Defaults to the last mount.

.PARAMETER Env
    DOS environment variables to set, e.g. @{ PATH = 'C:\BIN'; LIB = 'C:\LIB' }

.PARAMETER DosBox
    Path to dosbox-x.exe.

.PARAMETER TimeoutSeconds
    Kill the emulator if it has not exited by then. A DOS compiler that hits an
    interactive prompt will otherwise hang forever.

.EXAMPLE
    .\dosrun.ps1 -Command "CL -c -AS LIBREF.C" `
        -Mounts @{ C = $env:MSC_HOME; D = $buildDir } `
        -Env @{ PATH = 'C:\BIN'; LIB = 'C:\LIB'; INCLUDE = 'C:\INCLUDE' }

    The DOS-side paths (C:\BIN and friends) are inside the emulator, relative
    to whatever the host directory was mounted as -- those stay literal.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$Command,
    [Parameter(Mandatory = $true)][hashtable]$Mounts,
    [string]$WorkDrive,
    [hashtable]$Env = @{},
    [string]$DosBox = $env:DOSBOX,
    [int]$TimeoutSeconds = 180,
    [switch]$UseErrout
)

$ErrorActionPreference = 'Stop'
if (-not $DosBox) {
    throw "DOSBox-X location unknown. Pass -DosBox, or set `$env:DOSBOX " +
          "(see env.example.ps1 in the package root)."
}
if (-not (Test-Path $DosBox)) { throw "dosbox-x.exe not found at $DosBox" }

$letters = @($Mounts.Keys | Sort-Object)
if (-not $WorkDrive) { $WorkDrive = $letters[-1] }
$hostWork = $Mounts[$WorkDrive]
if (-not (Test-Path $hostWork)) { throw "work directory does not exist: $hostWork" }

$logName = 'DOSRUN.LOG'
$hostLog = Join-Path $hostWork $logName
if (Test-Path $hostLog) { Remove-Item $hostLog -Force }

# DOSBox-X is a GUI program: its -c arguments are unreliable and it has no host
# stdout at all. Driving it through a generated config file with an [autoexec]
# section is the approach that actually works, and it sidesteps every quoting
# problem with paths containing spaces.
$lines = @('[sdl]', 'autolock=false', 'windowposition=', '',
           '[dosbox]', 'memsize=16', '',
           '[cpu]', 'core=auto', 'cycles=max', '',
           '[autoexec]')
foreach ($d in $letters) { $lines += "mount $d `"$($Mounts[$d])`"" }
foreach ($k in $Env.Keys) { $lines += "set $k=$($Env[$k])" }
$lines += "${WorkDrive}:"
# DOSBox's shell has no 2>&1. MS C ships ERROUT for exactly this: it folds a
# tool's stderr into stdout so a single > captures the whole error list.
if ($UseErrout) {
    $lines += "ERROUT $Command > $logName"
} else {
    $lines += "$Command > $logName"
}
$lines += 'exit'

$conf = Join-Path $env:TEMP ("dosrun-" + [guid]::NewGuid().ToString('N') + ".conf")
Set-Content -Path $conf -Value $lines -Encoding ASCII

$proc = Start-Process -FilePath $DosBox -ArgumentList @('-conf', "`"$conf`"") `
                      -PassThru -WindowStyle Minimized
if (-not $proc.WaitForExit($TimeoutSeconds * 1000)) {
    Write-Host "dosrun: timed out after ${TimeoutSeconds}s, killing emulator" -ForegroundColor Yellow
    try { $proc.Kill() } catch { }
    Start-Sleep -Milliseconds 500
}

Remove-Item $conf -Force -ErrorAction SilentlyContinue

if (Test-Path $hostLog) {
    Get-Content $hostLog
} else {
    Write-Host "dosrun: no output captured (command may not have run)" -ForegroundColor Yellow
}
