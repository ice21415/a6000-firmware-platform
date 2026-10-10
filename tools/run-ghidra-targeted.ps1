param(
  [Parameter(Mandatory=$true)][string]$GhidraRoot,
  [Parameter(Mandatory=$true)][string]$ProjectDir,
  [Parameter(Mandatory=$true)][string]$ProjectName,
  [Parameter(Mandatory=$true)][string]$Binary,
  [Parameter(Mandatory=$true)][ValidateSet('camera-request-chain','camera-ee-neutral','app-event-primary','event-manager-init','event-manager-count','event-manager-destroy','event-manager-owner-init','event-manager-constructor','paramlist-lifetime','paramlist-owner-use','request-event-factory','event-core','param-set','param-set-exceptions','param-set-callers','param-pair','param-string','param-objmsg','param-struct','param-lifecycle-field-audit','param-destructor-field-audit','paramlist-virtual-dispatch-audit','param-cntinfolist')][string]$Profile,
  [Parameter(Mandatory=$true)][string]$Output
)

$ErrorActionPreference = "Stop"
$headless = Join-Path $GhidraRoot "support\analyzeHeadless.bat"
if (!(Test-Path -LiteralPath $headless)) { throw "Ghidra analyzeHeadless.bat not found: $headless" }
if (!(Test-Path -LiteralPath $Binary)) { throw "ELF input not found: $Binary" }
$binaryPath = [System.IO.Path]::GetFullPath($Binary)
$outputPath = [System.IO.Path]::GetFullPath($Output)
$projectPath = [System.IO.Path]::GetFullPath($ProjectDir)
$scriptDir = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot "..\ghidra-scripts"))
$parent = Split-Path -Parent $outputPath
if ($parent) { New-Item -ItemType Directory -Force -Path $parent | Out-Null }
Remove-Item -LiteralPath $outputPath -Force -ErrorAction SilentlyContinue

# ParamListTargets is intentionally run with -noanalysis.  Its output can
# contain firmware-derived instruction/decompiler text and must stay private.
& $headless $projectPath $ProjectName -import $binaryPath -overwrite -noanalysis `
  -scriptPath $scriptDir -postScript ParamListTargets.java $outputPath $Profile
$exitCode = $LASTEXITCODE
if ($exitCode -ne 0) { throw "Targeted Ghidra export failed with exit code $exitCode (profile=$Profile)" }
if (!(Test-Path -LiteralPath $outputPath)) { throw "Targeted Ghidra export is missing: $outputPath" }
$tail = Get-Content -LiteralPath $outputPath -Tail 1
if ($tail -ne "COMPLETE_TARGET_EXPORT") { throw "Targeted Ghidra export lacks COMPLETE_TARGET_EXPORT (profile=$Profile)" }
Write-Output "profile=$Profile"
Write-Output "output=$outputPath"
Write-Output ("bytes=" + (Get-Item -LiteralPath $outputPath).Length)
