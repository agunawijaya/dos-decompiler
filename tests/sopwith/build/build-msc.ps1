<#
.SYNOPSIS
    Rebuild Sopwith with the toolchain SW.MAK actually names: Microsoft C 5.0.

.DESCRIPTION
    The Watcom build (build.ps1) is free and automatic, but its code generation
    is nothing like a 1980s compiler's -- it omits frame pointers, reorders
    aggressively, and the resulting binary is a poor stand-in for a real game
    of the era. This builds with the real thing.

    It matters more than it sounds. Measured on the same source, same pipeline:

        built with Open Watcom      identification precision 0.875, recall 0.583
        built with Microsoft C 5.0  identification precision 0.935, recall 0.717

    Microsoft C emits a stack frame for nearly every function (208 prologues
    against Watcom's 25), which makes function boundaries recoverable, and its
    output tracks the source structure closely enough that control-flow shape
    comparison works far better.

    So: validate against the Microsoft build when you can. It is the honest
    proxy for what you will actually be handed.

.PARAMETER Msc
    A Microsoft C 5.0 installation laid out as BIN/, LIB/, INCLUDE/.

    NOT SHIPPED WITH THIS PACKAGE. Microsoft C is abandonware -- decades out of
    sale, widely archived for preservation, never freely licensed. Obtaining it
    is your call. Disk images are commonly distributed as raw .IMG floppies;
    tools/fatextract.py will unpack them, and everything under BIN/LIB/INCLUDE
    can simply be pooled by extension.

.PARAMETER Watcom
    Still needed: MASM is not part of the C compiler package, so the assembly
    modules go through Open Watcom's wasm, which emits compatible OMF.

.NOTES
    Two source-level additions beyond the Watcom build's five fixes:
      * bmbstub.c stubs the unreleased BMB block-I/O layer, as before.
      * It also supplies isalpha/isdigit/isalnum as real functions. BMBLIB.C
        and SWSOUND.C call them without including <ctype.h>, so the usual
        macros never apply and the linker wants genuine symbols. The original
        build got them from the BMB library.

    The link uses a response file. The object list is far past DOS's 127-byte
    command line limit -- which is exactly why SW.MAK wrote "link @sw.lnk".
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$Source,
    [Parameter(Mandatory = $true)][string]$Work,
    [string]$Msc    = $env:MSC_HOME,
    [string]$Watcom = $env:WATCOM
)

$ErrorActionPreference = 'Stop'
if (-not $Msc) {
    throw "Microsoft C location unknown. Pass -Msc, or set `$env:MSC_HOME " +
          "(see env.example.ps1 in the package root)."
}
$here = $PSScriptRoot
# tests/sopwith/build -> tests/sopwith -> reference -> package root
$tools = Join-Path (Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $here))) 'tools'

foreach ($p in @("$Msc\BIN\CL.EXE", "$Msc\BIN\LINK.EXE", "$Msc\LIB\SLIBC.LIB")) {
    if (-not (Test-Path $p)) { throw "Microsoft C 5.0 not found: missing $p" }
}
if (-not $Watcom) { throw "Open Watcom directory unknown (needed for wasm)." }

New-Item -ItemType Directory -Force $Work | Out-Null
Copy-Item "$Source\*" $Work -Force
Copy-Item (Join-Path $here 'mixed.inc') $Work -Force
Copy-Item (Join-Path $here 'bmbstub.c') (Join-Path $Work 'BMBSTUB.C') -Force

Write-Host 'patching source' -ForegroundColor Cyan
Get-ChildItem "$Work\*" -Include *.c, *.h, *.asm, *.ha -File | ForEach-Object {
    $b = [IO.File]::ReadAllBytes($_.FullName)
    $i = [Array]::IndexOf($b, [byte]0x1A)
    if ($i -ge 0) { [IO.File]::WriteAllBytes($_.FullName, $b[0..($i - 1)]) }
}
$ha = Get-Content "$Work\sw.ha" -Raw
$ha = $ha -replace "K_ASYNACK\s+equ\s+40H\s*\r?\n\s*\r?\nK_ASYNACK\s+equ\s+40H", "K_ASYNACK`tequ`t40H"
Set-Content "$Work\sw.ha" -Value $ha -NoNewline
$u = Get-Content "$Work\swutil.asm" -Raw
$u = $u -replace '(?im)^(\w+)(\s+)equ(\s+@AB)', '$1$2=$3'
$u = $u -replace '(?im)^(\s*push\s+)(nextkey)\b', '$1word ptr $2'
Set-Content "$Work\swutil.asm" -Value $u -NoNewline
$a = Get-Content "$Work\_inta.asm" -Raw
$a = $a -replace '(?im)^(\s*push\s+)(CS:i\d+)\s*$', '$1word ptr $2'
Set-Content "$Work\_inta.asm" -Value $a -NoNewline

$env:PATH = "$Watcom\binnt64;$env:PATH"
Write-Host 'assembling with wasm' -ForegroundColor Cyan
foreach ($m in '_dkio', '_inta', '_ints', 'swcomm', 'swgrph', 'swhist', 'swutil') {
    Push-Location $Work
    $o = & wasm -ms -zq -dmodel=small -dlang=c "$m.asm" 2>&1
    Pop-Location
    if ($o | Select-String 'Error') { $o | Select-Object -First 3; throw "assemble failed: $m" }
}

# The exact flags from SW.MAK: small model, no stack probes, no default library
# records, floating point via calls, optimise for speed.
Write-Host 'compiling with Microsoft C 5.0 (flags from SW.MAK)' -ForegroundColor Cyan
$cmods = @('bmblib', '_intc', 'swasynio', 'swauto', 'swcollsn', 'swdisp', 'swend',
           'swgames', 'swground', 'swinit', 'swmain', 'swmisc', 'swmove', 'swmultio',
           'swobject', 'swplanes', 'swsound', 'swsymbol', 'swtitle', 'bmbstub')
foreach ($m in $cmods) {
    $out = & "$tools\dosrun.ps1" -Command "CL -c -AS -Gs -FPc -Osa -DIBMPC $m.C" -UseErrout `
        -Mounts @{ C = $Msc; D = $Work } `
        -Env @{ PATH = 'C:\BIN'; LIB = 'C:\LIB'; INCLUDE = 'C:\INCLUDE' } -TimeoutSeconds 240
    if ($out | Select-String 'error') { $out | Select-String 'error' | Select-Object -First 3; throw "compile failed: $m" }
}
Write-Host "  $($cmods.Count) modules compiled"

# Link order recovered from SW.MAK's dependency list.
$objs = '_ints', 'swcomm', '_inta', 'swgrph', 'swutil', '_dkio', '_intc', 'swasynio',
        'swmain', 'swmove', 'swinit', 'swauto', 'swdisp', 'swcollsn', 'swplanes',
        'swsymbol', 'swend', 'swgames', 'swground', 'swhist', 'swmisc', 'swmultio',
        'swobject', 'swsound', 'swtitle', 'bmblib', 'bmbstub'
$lines = @()
for ($i = 0; $i -lt $objs.Count; $i++) {
    $lines += if ($i -lt $objs.Count - 1) { "$($objs[$i])+" } else { $objs[$i] }
}
$lines += 'SOPWITH', 'SOPWITH', 'SLIBC+SLIBFP+EM+LIBH;'
Set-Content "$Work\SW.LNK" -Value $lines -Encoding ASCII

Write-Host 'linking with Microsoft LINK' -ForegroundColor Cyan
$out = & "$tools\dosrun.ps1" -Command "LINK /MAP @SW.LNK" -UseErrout `
    -Mounts @{ C = $Msc; D = $Work } `
    -Env @{ PATH = 'C:\BIN'; LIB = 'C:\LIB'; INCLUDE = 'C:\INCLUDE' } -TimeoutSeconds 420
$bad = $out | Select-String 'error|Unresolved'
if ($bad) { $bad | Select-Object -First 8; throw 'link failed' }

Write-Host ("built {0} ({1} bytes)" -f (Join-Path $Work 'SOPWITH.EXE'),
            (Get-Item "$Work\SOPWITH.EXE").Length) -ForegroundColor Green
Write-Host ("map   {0}" -f (Join-Path $Work 'SOPWITH.MAP')) -ForegroundColor Green
