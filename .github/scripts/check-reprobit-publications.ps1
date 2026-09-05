#!/usr/bin/env pwsh
# Gate the ReproBit run outcome: every certification claim must hold, the run
# must be clean (no reference-byte exception ran; the pinned boundary passed in
# by the workflow is the empty one), the expected publications must exist, and
# the byte-exact binaries must hash identical to the authenticated retail
# references.
$ErrorActionPreference = "Stop"

foreach ($claim in @("ACCEPTED", "BYTE_EXACT", "LOGIC_CERTIFIED", "TOOLCHAIN_ORIGIN", "REPORT_PRODUCED", "CLEAN")) {
  if ((Get-Item "env:$claim").Value -ne "true") {
    throw "ReproBit did not certify $claim"
  }
}
if ($env:QUARANTINED -ne "false") {
  throw "A reference-byte exception ran; ISLE no longer accepts any"
}
$expectedQuarantine = @{
  QUARANTINE_COUNT = $env:EXPECTED_QUARANTINE_COUNT
  QUARANTINE_BYTES = $env:EXPECTED_QUARANTINE_BYTES
  QUARANTINE_RANGES = $env:EXPECTED_QUARANTINE_RANGES
  QUARANTINE_DIGEST = $env:EXPECTED_QUARANTINE_DIGEST
}
foreach ($claim in $expectedQuarantine.Keys) {
  if (-not $expectedQuarantine[$claim]) {
    throw "The workflow did not pin an expected value for $claim"
  }
  $actual = (Get-Item "env:$claim").Value
  if ($actual -ne $expectedQuarantine[$claim]) {
    throw "ISLE's reviewed quarantine boundary changed ${claim}: $actual"
  }
}
foreach ($path in @(
  "build/CONFIG.EXE",
  "build/ISLE.EXE",
  "build/LEGO1.DLL",
  "build/reprobit-debug/CONFIG.EXE",
  "build/reprobit-debug/CONFIG.PDB",
  "build/reprobit-debug/ISLE.EXE",
  "build/reprobit-debug/ISLE.PDB",
  "build/reprobit-debug/LEGO1.DLL",
  "build/reprobit-debug/LEGO1.PDB"
)) {
  if (-not (Test-Path -PathType Leaf $path)) {
    throw "ReproBit did not publish $path"
  }
}
foreach ($path in @(
  "build/CONFIG.PDB", "build/ISLE.PDB", "build/LEGO1.PDB"
)) {
  if (Test-Path $path) {
    throw "Unexpected sibling comparison output is present: $path"
  }
}
foreach ($name in @("CONFIG.EXE", "ISLE.EXE", "LEGO1.DLL")) {
  $built = (Get-FileHash "build/$name" -Algorithm SHA256).Hash
  $retail = (Get-FileHash "legobin/$name" -Algorithm SHA256).Hash
  if ($built -ne $retail) {
    throw "Published $name does not match its authenticated retail reference"
  }
}
