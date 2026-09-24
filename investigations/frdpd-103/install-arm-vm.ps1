$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$root = 'C:\frdpd-msys2'
$evidence = Join-Path $env:RUNNER_TEMP 'native-private'
New-Item -ItemType Directory -Force $evidence | Out-Null
if (Test-Path $root) { throw 'Refusing to replace an existing MSYS2 installation' }
$installer = Join-Path $env:RUNNER_TEMP 'msys2-arm64-20260611.exe'
Invoke-WebRequest 'https://github.com/msys2/msys2-installer/releases/download/2026-06-11/msys2-arm64-20260611.exe' -OutFile $installer
$hash = (Get-FileHash -Algorithm SHA256 $installer).Hash.ToLowerInvariant()
if ($hash -ne '6e29f2a62a7beb9181b14fa4a72a920527726e4f5c366fd13f5df36ae82600c4') { throw 'MSYS2 installer checksum mismatch' }
$p = Start-Process -FilePath $installer -ArgumentList @('in','--confirm-command','--accept-messages','--root',$root) -Wait -PassThru -RedirectStandardOutput (Join-Path $evidence 'msys-install.log') -RedirectStandardError (Join-Path $evidence 'msys-install-error.log')
if ($p.ExitCode -ne 0) { throw ('MSYS2 installer exit ' + $p.ExitCode) }
Remove-Item $installer
$bash = Join-Path $root 'usr\bin\bash.exe'
if (!(Test-Path $bash)) { throw 'Missing MSYS2 shell' }
$env:MSYSTEM = 'CLANGARM64'
$env:CHERE_INVOKING = '1'
$env:MSYS2_PATH_TYPE = 'minimal'
& $bash -lc 'true' *> (Join-Path $evidence 'msys-initialization.log')
if ($LASTEXITCODE -ne 0) { throw 'MSYS2 initialization failed' }
# Core-runtime updates may terminate the first shell; always use a new shell
# and require the second full update and the signed package transaction to pass.
& $bash -lc 'pacman -Syu --noconfirm' *> (Join-Path $evidence 'msys-core-update.log')
$firstUpdate = $LASTEXITCODE
& $bash -lc 'pacman -Syu --noconfirm' *> (Join-Path $evidence 'msys-full-update.log')
if ($LASTEXITCODE -ne 0) { throw 'MSYS2 full update failed' }
& $bash -lc 'pacman -S --needed --noconfirm mingw-w64-clang-aarch64-qemu mingw-w64-clang-aarch64-qemu-image-util' *> (Join-Path $evidence 'msys-qemu-install.log')
if ($LASTEXITCODE -ne 0) { throw 'Signed native QEMU package installation failed' }
& $bash -lc 'pacman -Q' > (Join-Path $evidence 'vm-packages.txt')
if ($LASTEXITCODE -ne 0) { throw 'Package inventory failed' }
@{ installer_sha256=$hash; first_core_update_exit=$firstUpdate; root=$root; signature_policy='unchanged pacman defaults' } | ConvertTo-Json | Set-Content (Join-Path $evidence 'vm-install.json')
"msys2-location=$root" >> $env:GITHUB_OUTPUT
