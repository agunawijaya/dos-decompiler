<#
.SYNOPSIS
    Rebuild Sopwith from its GPL source into a ground-truth binary + linker map.

.DESCRIPTION
    Produces a binary whose function-to-address mapping is known exactly, which
    is what makes it possible to measure decompilation accuracy instead of
    guessing at it.

    This is NOT a faithful reproduction of the 1987 build. The original used
    Microsoft C 5.x, MASM and Microsoft LINK (see SW.MAK); this uses Open
    Watcom, which is free, still maintained, and scriptable. The code generated
    differs -- notably Watcom omits frame pointers, so the classic
    "push bp / mov bp,sp" prologue is rare here and common in the shipped
    SOPWITH.EXE. That difference is itself useful: it exercises the pipeline
    against two different compilers.

    Five source-level fixes are applied to the working copy. The pristine
    source is never modified. Each is a place where a modern toolchain refuses
    something the 1980s one accepted:

      1. Ctrl-Z (0x1A) end-of-file marker inside SWDEVE.H
      2. mixed.inc, absent from the release -- recreated empty, since Sopwith
         uses no macros from it
      3. K_ASYNACK defined twice in SW.HA
      4. swauto.c mixes "return;" and "return(value);" in one function
      5. wasm reads "push CS:label" / "push var" as an immediate push;
         MASM read it as PUSH m16, so "word ptr" is made explicit

    compat.c supplies the C runtime functions the original took from the
    Microsoft library, plus stubs for the unreleased BMB block-I/O layer
    (bopen/bread/bwrite/bseek/bioerr) which SWMULTIO.C references and no
    published file defines. Multiplayer therefore does not work in this build.

.PARAMETER Source
    Directory holding the Sopwith GPL source release.

.PARAMETER Work
    Scratch directory for the build. Contents are overwritten.

.PARAMETER Watcom
    Open Watcom installation (needs binnt64, h, lib286).

.PARAMETER Variant
    Build with different code generation -- optimise for size, target the 286 --
    producing a second binary with identical semantics and a different
    instruction stream. Both have linker maps, so together they give complete
    ground truth for cross-binary function matching, which is what
    tools/emuverify.py is scored against.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$Source,
    [Parameter(Mandatory = $true)][string]$Work,
    [string]$Watcom = $env:WATCOM,
    [switch]$Variant
)

$ErrorActionPreference = 'Stop'
if (-not $Watcom) { throw "Open Watcom directory unknown. Pass -Watcom or set WATCOM." }
$wcc = Join-Path $Watcom 'binnt64\wcc.exe'
if (-not (Test-Path $wcc)) { throw "wcc.exe not found under $Watcom (need the 16-bit compiler)" }

$here = Split-Path -Parent $MyInvocation.MyCommand.Path
New-Item -ItemType Directory -Force $Work | Out-Null
Copy-Item (Join-Path $Source '*') $Work -Force
Copy-Item (Join-Path $here 'compat.c')  $Work -Force
Copy-Item (Join-Path $here 'sw.lnk')    $Work -Force
Copy-Item (Join-Path $here 'mixed.inc') $Work -Force

Push-Location $Work
try {
    $env:WATCOM = $Watcom
    $env:PATH   = (Join-Path $Watcom 'binnt64') + ';' + $env:PATH
    $inc = Join-Path $Watcom 'h'

    Write-Host 'patching source for a modern toolchain' -ForegroundColor Cyan

    # 1. DOS end-of-file marker; period compilers stopped reading there.
    Get-ChildItem '*' -Include *.c, *.h, *.asm, *.ha -File | ForEach-Object {
        $bytes = [IO.File]::ReadAllBytes($_.FullName)
        $i = [Array]::IndexOf($bytes, [byte]0x1A)
        if ($i -ge 0) {
            [IO.File]::WriteAllBytes($_.FullName, $bytes[0..($i - 1)])
            Write-Host "  stripped Ctrl-Z from $($_.Name)"
        }
    }

    # 3. Duplicated equate.
    $ha = Get-Content 'sw.ha' -Raw
    $ha = $ha -replace "K_ASYNACK\s+equ\s+40H\s*\r?\n\s*\r?\nK_ASYNACK\s+equ\s+40H", "K_ASYNACK`tequ`t40H"
    Set-Content 'sw.ha' -Value $ha -NoNewline

    # 4. Mixed return forms. aim()'s value is never consumed by any caller.
    $auto = Get-Content 'swauto.c' -Raw
    $auto = $auto -replace "(?m)^\t\tob->ob_accel = MAX_THROTTLE;\r?\n\t\treturn;",
                           "`t`tob->ob_accel = MAX_THROTTLE;`r`n`t`treturn( 0 );"
    Set-Content 'swauto.c' -Value $auto -NoNewline

    # 5. Memory operands that wasm would otherwise read as immediates.
    $inta = Get-Content '_inta.asm' -Raw
    $inta = $inta -replace '(?im)^(\s*push\s+)(CS:i\d+)\s*$', '$1word ptr $2'
    Set-Content '_inta.asm' -Value $inta -NoNewline

    $util = Get-Content 'swutil.asm' -Raw
    $util = $util -replace '(?im)^(\w+)(\s+)equ(\s+@AB)', '$1$2=$3'   # redefinable frame offsets
    $util = $util -replace '(?im)^(\s*push\s+)(nextkey)\b', '$1word ptr $2'
    Set-Content 'swutil.asm' -Value $util -NoNewline

    # -ecc matters: it restores the Microsoft leading-underscore, stack-based
    # convention the assembly modules were written against. Watcom's default
    # register convention leaves every cross-module reference unresolved.
    if ($Variant) {
        $cpu = '-2'; $opt = '-os'
        Write-Host 'compiling C (small model, 286, size-optimised, __cdecl)' -ForegroundColor Cyan
    } else {
        $cpu = '-0'; $opt = ''
        Write-Host 'compiling C (small model, 8086, __cdecl)' -ForegroundColor Cyan
    }
    $cModules = @('bmblib', '_intc', 'swasynio', 'swauto', 'swcollsn', 'swdisp', 'swend',
                  'swgames', 'swground', 'swinit', 'swmain', 'swmisc', 'swmove', 'swmultio',
                  'swobject', 'swplanes', 'swsound', 'swsymbol', 'swtitle', 'compat')
    foreach ($m in $cModules) {
        $flags = @('-ms', $cpu, '-ecc', '-zq', '-DIBMPC', "-i=$inc", "-i=$Work")
        if ($opt) { $flags += $opt }
        $out = & wcc @flags "$m.c" 2>&1
        $err = $out | Select-String 'Error!'
        if ($err) { $err | ForEach-Object { Write-Host "  $_" -ForegroundColor Red }; throw "compile failed: $m" }
    }
    Write-Host "  $($cModules.Count) modules compiled"

    Write-Host 'assembling' -ForegroundColor Cyan
    foreach ($a in @('_dkio', '_inta', '_ints', 'swcomm', 'swgrph', 'swhist', 'swutil')) {
        $out = & wasm -ms -zq -dmodel=small -dlang=c "$a.asm" 2>&1
        $err = $out | Select-String 'Error'
        if ($err) { $err | ForEach-Object { Write-Host "  $_" -ForegroundColor Red }; throw "assemble failed: $a" }
    }
    Write-Host '  7 modules assembled'

    Write-Host 'linking' -ForegroundColor Cyan
    $out = & wlink '@sw.lnk' 2>&1
    $err = $out | Select-String 'Error'
    if ($err) { $err | Select-Object -First 10 | ForEach-Object { Write-Host "  $_" -ForegroundColor Red }; throw 'link failed' }

    $exe = Join-Path $Work 'sopwith.exe'
    $map = Join-Path $Work 'sopwith.map'
    Write-Host "`nbuilt $exe ($((Get-Item $exe).Length) bytes)" -ForegroundColor Green
    Write-Host "map   $map" -ForegroundColor Green
}
finally {
    Pop-Location
}
