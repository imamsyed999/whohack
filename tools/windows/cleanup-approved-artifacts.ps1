# User-run fallback for the four approved artifact paths that automatic tool
# approval review refused to delete. Default is a read-only inventory.
param([switch]$Apply)
$ErrorActionPreference = 'Stop'
$workspace = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../..')).TrimEnd('\')
if (!(Test-Path -LiteralPath (Join-Path $workspace 'Cargo.toml')) -or
    !(Test-Path -LiteralPath (Join-Path $workspace 'target/release/vigil-service.exe'))) {
    throw 'Expected Vigil workspace and preserved release are missing.'
}
$relativePaths = @('target/debug', '.vigil/checks/native-tests',
    '.vigil/checks/downloads/bin', '.vigil/checks/vigil-service.exe')

function Assert-PlainWorkspacePath([string]$target) {
    $absolute = [IO.Path]::GetFullPath($target)
    if (!$absolute.StartsWith($workspace + '\', [StringComparison]::OrdinalIgnoreCase)) {
        throw "Target escapes the Vigil workspace: $absolute"
    }
    $cursor = $absolute
    while ($cursor) {
        if (Test-Path -LiteralPath $cursor) {
            $entry = Get-Item -LiteralPath $cursor -Force
            if ($entry.Attributes -band [IO.FileAttributes]::ReparsePoint) {
                throw "Refusing a link or junction: $cursor"
            }
        }
        $parent = Split-Path -Parent $cursor
        if ($parent -eq $cursor) { break }
        $cursor = $parent
    }
    if (Test-Path -LiteralPath $absolute -PathType Container) {
        foreach ($entry in Get-ChildItem -LiteralPath $absolute -Recurse -Force) {
            if ($entry.Attributes -band [IO.FileAttributes]::ReparsePoint) {
                throw "Refusing a linked descendant: $($entry.FullName)"
            }
        }
    }
}

$targets = @()
foreach ($relative in $relativePaths) {
    $target = [IO.Path]::GetFullPath((Join-Path $workspace $relative))
    Assert-PlainWorkspacePath $target
    if (Test-Path -LiteralPath $target) { $targets += $target }
}
$processes = @(Get-CimInstance Win32_Process)
foreach ($process in $processes) {
    if ($process.Name -in @('cargo.exe', 'rustc.exe')) { throw 'A Rust build is running.' }
    if (!$process.ExecutablePath) { continue }
    foreach ($target in $targets) {
        if ($process.ExecutablePath.Equals($target, [StringComparison]::OrdinalIgnoreCase) -or
            $process.ExecutablePath.StartsWith($target + '\', [StringComparison]::OrdinalIgnoreCase)) {
            throw "An artifact is still running: PID $($process.ProcessId)"
        }
    }
}
$inventory = @($targets | ForEach-Object {
    $item = Get-Item -LiteralPath $_
    $bytes = if ($item.PSIsContainer) {
        (Get-ChildItem -LiteralPath $_ -Recurse -File -Force | Measure-Object Length -Sum).Sum
    } else { $item.Length }
    [PSCustomObject]@{ Path = $_; Bytes = [long]$bytes }
})
$inventory | Format-Table -AutoSize
if (($inventory | Measure-Object Bytes -Sum).Sum -gt 3000000000) {
    throw 'Artifacts grew beyond the reviewed 3 GB budget. Inspect before deleting.'
}
if (!$Apply) {
    Write-Output 'Read-only inventory. Run this same script with -Apply to remove these approved artifacts.'
    return
}

# Preserve all small test evidence and the already-retained owned-process fixture.
$fixture = Join-Path $workspace '.vigil/checks/fixtures/owned-process.exe'
Assert-PlainWorkspacePath $fixture
if (!(Test-Path -LiteralPath $fixture) -or
    (Get-FileHash -LiteralPath $fixture -Algorithm SHA256).Hash.ToLowerInvariant() -ne
    '86619bac49b298ed028aa96314db1e946f6d2022d011fda1ee95a14125db53ec') {
    throw 'The preserved test fixture is missing or changed.'
}
$evidence = Join-Path $workspace '.vigil/checks/storage/native-test-evidence'
Assert-PlainWorkspacePath $evidence
New-Item -ItemType Directory -Path $evidence -Force | Out-Null
$tests = Join-Path $workspace '.vigil/checks/native-tests'
if (Test-Path -LiteralPath $tests) {
    foreach ($entry in Get-ChildItem -LiteralPath $tests -Force) {
        if ($entry.PSIsContainer -or $entry.Extension -notin @('.exe', '.log', '.json')) {
            throw "Unrecognized test artifact; preserve and inspect: $($entry.Name)"
        }
        if ($entry.Extension -eq '.exe') { continue }
        $destination = Join-Path $evidence $entry.Name
        Assert-PlainWorkspacePath $destination
        if (Test-Path -LiteralPath $destination) {
            if ((Get-FileHash -LiteralPath $destination).Hash -ne (Get-FileHash -LiteralPath $entry.FullName).Hash) {
                throw "A different evidence backup already exists: $destination"
            }
        } else {
            Copy-Item -LiteralPath $entry.FullName -Destination $destination
        }
        if ((Get-FileHash -LiteralPath $destination).Hash -ne (Get-FileHash -LiteralPath $entry.FullName).Hash) {
            throw 'Evidence copy verification failed.'
        }
    }
}
foreach ($target in $targets) {
    Assert-PlainWorkspacePath $target
    Remove-Item -LiteralPath $target -Recurse -Force
}
Write-Output 'Approved copied artifacts removed; release, model, runtime and evidence paths preserved.'
