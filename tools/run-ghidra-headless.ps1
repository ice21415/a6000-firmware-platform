param(
  [Parameter(Mandatory=$true)][string]$GhidraRoot,
  [Parameter(Mandatory=$true)][string]$ProjectDir,
  [Parameter(Mandatory=$true)][string]$ProjectName,
  [Parameter(Mandatory=$true)][string]$Binary,
  [string]$Output = "reports/ghidra-analysis.jsonl",
  [string]$RunId = ""
)
$ErrorActionPreference = "Stop"
$headless = Join-Path $GhidraRoot "support\analyzeHeadless.bat"
if (!(Test-Path -LiteralPath $headless)) { throw "Ghidra analyzeHeadless.bat not found: $headless" }
if (!(Test-Path -LiteralPath $Binary)) { throw "ELF input not found: $Binary" }
$binaryPath = [System.IO.Path]::GetFullPath($Binary)
$outputPath = [System.IO.Path]::GetFullPath($Output)
$projectPath = [System.IO.Path]::GetFullPath($ProjectDir)
$scriptDir = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot "..\ghidra-scripts"))
$sha256 = (Get-FileHash -LiteralPath $binaryPath -Algorithm SHA256).Hash.ToLowerInvariant()
$properties = Join-Path $GhidraRoot "Ghidra\application.properties"
$ghidraVersion = "unknown"
if (Test-Path -LiteralPath $properties) {
  $versionLine = Select-String -LiteralPath $properties -Pattern '^application\.version=' | Select-Object -First 1
  if ($versionLine) { $ghidraVersion = ($versionLine.Line -split '=', 2)[1].Trim() }
}
if ([string]::IsNullOrWhiteSpace($RunId)) { $RunId = "ghidra-$sha256" }
$parent = Split-Path -Parent $outputPath
if ($parent) { New-Item -ItemType Directory -Force -Path $parent | Out-Null }
# AnalyzeBinary.java truncates the JSONL itself; removing an old output here
# also makes a failed run visibly incomplete instead of looking successful.
Remove-Item -LiteralPath $outputPath -Force -ErrorAction SilentlyContinue
$args = @($projectPath, $ProjectName, "-import", $binaryPath, "-overwrite", "-scriptPath", $scriptDir,
         "-postScript", "AnalyzeBinary.java", $outputPath, $RunId, $sha256, $ghidraVersion)
& $headless @args
$exitCode = $LASTEXITCODE
if ($exitCode -ne 0) { throw "Ghidra headless failed with exit code $exitCode (run=$RunId)" }
if (!(Test-Path -LiteralPath $outputPath)) { throw "Ghidra completed without output: $outputPath" }
$lineCount = (Get-Content -LiteralPath $outputPath | Measure-Object -Line).Lines
if ($lineCount -lt 1) { throw "Ghidra produced an empty output: $outputPath" }
Write-Output "run_id=$RunId"
Write-Output "binary_sha256=$sha256"
Write-Output "ghidra_version=$ghidraVersion"
Write-Output "output=$outputPath"
Write-Output "records=$lineCount"
