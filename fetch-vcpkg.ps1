[CmdletBinding()]
param(
    [ValidateSet('windows', 'linux')]
    [string]$Platform = 'windows',

    [Parameter(Mandatory = $true)]
    [string]$PrivateKey,

    [string]$RequestVerifyKey,
    [string]$Output,
    [string]$WorkDir,
    [long]$Run,
    [int]$Attempt,
    [ValidatePattern('^[0-9a-f]{40}$')]
    [string]$BuilderSha,
    [switch]$InstallDependencies
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

if ($env:GITHUB_ACTIONS -eq 'true') {
    throw 'fetch-vcpkg.ps1 is for a trusted local workstation only.'
}

$root = Split-Path -Parent $MyInvocation.MyCommand.Path
$privateKeyPath = (Resolve-Path -LiteralPath $PrivateKey).Path

if ([string]::IsNullOrWhiteSpace($env:GH_TOKEN) -and
    [string]::IsNullOrWhiteSpace($env:GITHUB_TOKEN)) {
    $gh = Get-Command gh -ErrorAction SilentlyContinue
    if ($null -eq $gh) {
        throw 'Set GH_TOKEN/GITHUB_TOKEN or install/authenticate GitHub CLI (gh).'
    }
    $token = (& $gh.Source auth token 2>$null | Out-String).Trim()
    if ([string]::IsNullOrWhiteSpace($token)) {
        throw 'GitHub CLI did not return an authentication token.'
    }
    $env:GH_TOKEN = $token
}

$py = Get-Command py -ErrorAction SilentlyContinue
if ($null -ne $py) {
    $pythonExe = $py.Source
    $pythonPrefix = @('-3.12')
} else {
    $pythonExe = (Get-Command python -ErrorAction Stop).Source
    $pythonPrefix = @()
}

Push-Location $root
try {
    if ($InstallDependencies) {
        & $pythonExe @pythonPrefix -m pip install --disable-pip-version-check --require-hashes --only-binary=:all: -r (Join-Path $root 'requirements.lock')
        if ($LASTEXITCODE -ne 0) {
            throw 'Failed to install hash-pinned local retrieval dependencies.'
        }
    }

    $arguments = @(
        '-m', 'secure_release.fetch_sdk_local',
        '--platform', $Platform,
        '--private-key', $privateKeyPath
    )

    if (-not [string]::IsNullOrWhiteSpace($RequestVerifyKey)) {
        $arguments += @('--request-verify-key', (Resolve-Path -LiteralPath $RequestVerifyKey).Path)
    }
    if (-not [string]::IsNullOrWhiteSpace($Output)) {
        $arguments += @('--output', [IO.Path]::GetFullPath($Output))
    }
    if (-not [string]::IsNullOrWhiteSpace($WorkDir)) {
        $arguments += @('--work-dir', [IO.Path]::GetFullPath($WorkDir))
    }
    if ($Run -gt 0) {
        $arguments += @('--run', [string]$Run)
        if ($Attempt -gt 0) {
            $arguments += @('--attempt', [string]$Attempt)
        }
    } elseif ($Attempt -gt 0) {
        throw '-Attempt requires -Run.'
    }
    if (-not [string]::IsNullOrWhiteSpace($BuilderSha)) {
        $arguments += @('--builder-sha', $BuilderSha)
    }

    & $pythonExe @pythonPrefix @arguments
    if ($LASTEXITCODE -ne 0) {
        throw 'Encrypted SDK retrieval failed.'
    }
}
finally {
    Pop-Location
}
