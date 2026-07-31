<#
.SYNOPSIS
    Build a C runtime library signature database for libsig.py.

.DESCRIPTION
    Compiles and links libref.c -- a program written purely to reference as
    much of the C library as possible -- then extracts a masked byte signature
    for every library function the linker pulled in.

    Why this matters: measured on Sopwith, excluding recognised library
    functions raised identification precision from 0.696 to 0.826 with an
    inferred module order, and from 0.800 to 0.838 with a known one. That is a
    larger gain than knowing the link order, and unlike the link order it
    needs no surviving makefile.

    The database is toolchain-specific. `watcom-16bit-small.json` in this
    directory covers Open Watcom V2, 16-bit, small model, __cdecl. To cover a
    different compiler or memory model, rebuild with that toolchain: the
    signatures only match binaries built the same way.

    A database for Microsoft C 4/5 would be more valuable still, since that is
    what most commercial 1980s DOS games were built with. It cannot be
    generated here because those libraries are not freely distributable; if
    you have a licensed copy, compile libref.c with it and point this script
    at the result.

.PARAMETER Watcom
    Open Watcom installation (needs binnt64, h, lib286).

.PARAMETER Work
    Scratch directory for the build.

.PARAMETER Output
    Where to write the signature database.
#>
[CmdletBinding()]
param(
    [string]$Watcom = $env:WATCOM,
    [string]$Work   = (Join-Path $PWD 'libsig-build'),
    [string]$Output = (Join-Path $PSScriptRoot 'watcom-16bit-small.json')
)

$ErrorActionPreference = 'Stop'
if (-not $Watcom) { throw "Open Watcom directory unknown. Pass -Watcom or set WATCOM." }

$here = $PSScriptRoot
# signatures/ -> repository root
$tools = Join-Path (Split-Path -Parent $here) 'tools'

New-Item -ItemType Directory -Force $Work | Out-Null
Copy-Item (Join-Path $here 'libref.c')   $Work -Force
Copy-Item (Join-Path $here 'libref.lnk') $Work -Force

Push-Location $Work
try {
    $env:WATCOM = $Watcom
    $env:PATH   = (Join-Path $Watcom 'binnt64') + ';' + $env:PATH

    # Same flags as the Sopwith ground-truth build. They must match the target
    # binary's model and calling convention or the bytes will not line up.
    Write-Host 'compiling libref.c' -ForegroundColor Cyan
    $out = & wcc -ms -0 -ecc -zq -i="$(Join-Path $Watcom 'h')" libref.c 2>&1
    $err = $out | Select-String 'Error!'
    if ($err) { $err | ForEach-Object { Write-Host "  $_" -ForegroundColor Red }; throw 'compile failed' }

    Write-Host 'linking' -ForegroundColor Cyan
    $out = & wlink '@libref.lnk' 2>&1
    $err = $out | Select-String 'Error'
    if ($err) { $err | ForEach-Object { Write-Host "  $_" -ForegroundColor Red }; throw 'link failed' }

    Write-Host 'extracting signatures' -ForegroundColor Cyan
    python (Join-Path $tools 'libsig.py') build `
        (Join-Path $Work 'libref.exe') (Join-Path $Work 'libref.map') --json $Output
}
finally {
    Pop-Location
}
