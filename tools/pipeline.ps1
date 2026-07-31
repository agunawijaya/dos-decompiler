<#
.SYNOPSIS
    Run the full decompilation pipeline over a DOS executable.

.DESCRIPTION
    Drop a game's .EXE in, get back a structural report, a Ghidra project with
    recovered functions, decompiled C, and a per-function fingerprint file.

    The three Ghidra stages are deliberately separate invocations. Chaining
    -postScript flags in one headless run silently discards the first script's
    changes.

.PARAMETER Exe
    The DOS executable to analyse.

.PARAMETER OutDir
    Where to write results. Defaults to .\decompile-<exename>.

.PARAMETER Ghidra
    Ghidra installation directory.

.PARAMETER JavaHome
    JDK 21+ installation directory.

.PARAMETER SkipRecovery
    Skip RecoverFunctions.java. Use only to compare against plain
    auto-analysis; it typically loses a third of the functions.

.EXAMPLE
    .\pipeline.ps1 -Exe C:\games\GAME.EXE
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$Exe,
    [string]$OutDir,
    [string]$Ghidra   = $env:GHIDRA_HOME,
    [string]$JavaHome = $env:JAVA_HOME,
    [switch]$SkipRecovery
)

$ErrorActionPreference = 'Stop'
$toolDir = Split-Path -Parent $MyInvocation.MyCommand.Path

if (-not (Test-Path $Exe)) { throw "executable not found: $Exe" }
$exeItem = Get-Item $Exe
if (-not $OutDir) { $OutDir = Join-Path (Get-Location) ("decompile-" + $exeItem.BaseName) }

if (-not $Ghidra)   { throw "Ghidra directory unknown. Pass -Ghidra or set GHIDRA_HOME." }
if (-not $JavaHome) { throw "JDK directory unknown. Pass -JavaHome or set JAVA_HOME." }

$headless = Join-Path $Ghidra 'support\analyzeHeadless.bat'
if (-not (Test-Path $headless)) { throw "analyzeHeadless.bat not found under $Ghidra" }

$env:JAVA_HOME = $JavaHome
New-Item -ItemType Directory -Force $OutDir | Out-Null
$projDir  = Join-Path $OutDir 'ghidra-project'
$scripts  = Join-Path $toolDir 'ghidra_scripts'
$projName = 'target'
New-Item -ItemType Directory -Force $projDir | Out-Null

function Invoke-Headless {
    param([string[]]$HeadlessArgs, [string]$Label)
    Write-Host "  $Label" -ForegroundColor DarkGray

    # Ghidra writes its entire log to stderr. Under $ErrorActionPreference =
    # 'Stop' the first INFO line would be treated as a terminating error and
    # the run would abort with no output at all, so relax it just for the
    # native call.
    $previous = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try {
        $out = & $headless @HeadlessArgs 2>&1 | ForEach-Object { "$_" }
    } finally {
        $ErrorActionPreference = $previous
    }

    $out | Select-String -Pattern 'ERROR|Exception' |
        Select-Object -First 5 |
        ForEach-Object { Write-Host "    $_" -ForegroundColor Red }
    $out | Select-String -Pattern 'RecoverFunctions:|ExportDecompiledC:|Using Language/Compiler|Import succeeded' |
        ForEach-Object { Write-Host "    $_" -ForegroundColor DarkCyan }
}

Write-Host "`n[1/4] Structure" -ForegroundColor Cyan
$report = Join-Path $OutDir 'mzinfo.txt'
python (Join-Path $toolDir 'mzinfo.py') $exeItem.FullName | Tee-Object -FilePath $report
python (Join-Path $toolDir 'mzinfo.py') $exeItem.FullName --json |
    Set-Content (Join-Path $OutDir 'mzinfo.json')

# A packed file decompiles into its own decompressor. Stop rather than waste
# an hour producing confident nonsense.
if (Select-String -Path $report -Pattern '\[ERROR\] packer' -Quiet) {
    Write-Host "`nSTOP: this file appears to be packed. Unpack it before decompiling." -ForegroundColor Yellow
    Write-Host "See $report" -ForegroundColor Yellow
    return
}

Write-Host "`n[2/4] Import and analyse" -ForegroundColor Cyan
Invoke-Headless -HeadlessArgs @($projDir, $projName, '-import', $exeItem.FullName, '-overwrite') 'importing'

if (-not $SkipRecovery) {
    Write-Host "`n[3/4] Recover missed functions" -ForegroundColor Cyan
    Invoke-Headless -HeadlessArgs @($projDir, $projName, '-process', $exeItem.Name, '-noanalysis',
                      '-scriptPath', $scripts, '-postScript', 'RecoverFunctions.java') 'recovering'
} else {
    Write-Host "`n[3/4] Recovery skipped" -ForegroundColor DarkYellow
}

Write-Host "`n[4/4] Decompile and fingerprint" -ForegroundColor Cyan
Invoke-Headless -HeadlessArgs @($projDir, $projName, '-process', $exeItem.Name, '-noanalysis',
                  '-scriptPath', $scripts, '-postScript', 'ExportDecompiledC.java', $OutDir) 'exporting'

Write-Host "`nResults in $OutDir" -ForegroundColor Green
Get-ChildItem $OutDir -File | ForEach-Object {
    "  {0,-18} {1,10:N0} bytes" -f $_.Name, $_.Length
}
Write-Host @"

Next:
  * read mzinfo.txt findings before trusting anything else
  * decompiled.c holds the pseudocode; every line is a hypothesis
  * functions.json holds per-function fingerprints for tools/match.py
  * with reference source:  python tools/srcinv.py SRCDIR --json src.json
                            python tools/match.py src.json functions.json --align
"@ -ForegroundColor DarkGray
