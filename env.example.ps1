# env.example.ps1 -- where your copies of the external tools live.
#
# Copy this to env.ps1 and edit the paths, then dot-source it before using the
# package:
#
#     . .\env.ps1
#     .\tools\pipeline.ps1 -Exe C:\games\GAME.EXE -OutDir .\out
#
# env.ps1 is git-ignored on purpose: every machine puts these somewhere
# different, and hard-coded paths are what stops a package like this from
# being usable by anyone but its author.
#
# Nothing here is bundled. Ghidra, the JDK, Open Watcom, radare2 and DOSBox-X
# are all freely available. Microsoft C is abandonware -- decades out of sale,
# never freely licensed, widely archived for preservation. Obtaining it is your
# decision; the package works without it, just with weaker ground truth.

# --- required for the decompilation pipeline -------------------------------

# Ghidra 12.x installation (the directory containing support\analyzeHeadless.bat)
$env:GHIDRA_HOME = 'C:\Applications\ghidra\ghidra_12.1.2_PUBLIC'

# JDK 21 or newer, required by Ghidra
$env:JAVA_HOME = 'C:\Applications\jdk21\jdk-21.0.12+8'

# --- required only for rebuilding ground truth ------------------------------

# Open Watcom V2 (needs binnt64, h, lib286). Used for the free, automatic
# Sopwith rebuild, and for wasm when assembling with the Microsoft toolchain.
$env:WATCOM = 'C:\Applications\watcom-snap'

# Microsoft C 5.0, laid out as BIN\ LIB\ INCLUDE\. Optional, but it produces a
# far better ground truth: identification scores 0.935 against a Microsoft
# build versus 0.875 against a Watcom one.
$env:MSC_HOME = 'C:\Applications\msc50'

# --- optional ---------------------------------------------------------------

# DOSBox-X, to run period DOS toolchains and the games themselves
$env:DOSBOX = 'C:\DOSBox-X\dosbox-x.exe'

# radare2, used only as a second opinion when Ghidra looks wrong
$env:RADARE2 = 'C:\Applications\radare2\radare2-6.1.8-w64\bin\radare2.exe'
