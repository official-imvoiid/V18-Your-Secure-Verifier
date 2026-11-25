#Requires -Version 5.1
<#
  V18 one-click setup. Started by SETUP.bat (which asks for admin rights first).
  Installs every tool V18 needs, then installs, builds and tests the project.

  setup.ps1                 asks which setup you want
  setup.ps1 -Mode full      everything, including the Android app tools
  setup.ps1 -Mode light     server, website kit and Windows app only
  setup.ps1 -CheckOnly      only reports what is installed or missing; changes nothing
#>
param(
  [ValidateSet('', 'full', 'light')][string]$Mode = '',
  [switch]$CheckOnly
)

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

$Root = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
$Tools = 'C:\V18Tools'
$Downloads = Join-Path $Tools 'downloads'
$LogFile = Join-Path $Root 'setup-log.txt'

$NodeMajor = 22
$NodeMinMinor = 12
$PythonMin = [version]'3.9'
$FlutterVersion = '3.47.7'
$AndroidApi = '36'
$AndroidBuildTools = '36.0.0'
$NdkVersion = '28.2.13676358'
$SystemImage = "system-images;android-$AndroidApi;google_apis;x86_64"
$AvdName = 'v18_api36'

$script:Results = New-Object System.Collections.ArrayList
$script:NeedsRestart = $false

# ---------------------------------------------------------------- helpers

function Say([string]$Text, [string]$Color = 'Gray') { Write-Host $Text -ForegroundColor $Color }

function Invoke-Step([string]$Name, [scriptblock]$Body) {
  Say ''
  Say "==> $Name" 'Cyan'
  try {
    $note = & $Body
    if ($null -eq $note) { $note = '' }
    [void]$script:Results.Add([pscustomobject]@{ Step = $Name; Result = 'OK'; Note = "$note" })
    Say '    OK' 'Green'
  } catch {
    [void]$script:Results.Add([pscustomobject]@{ Step = $Name; Result = 'FAILED'; Note = $_.Exception.Message })
    Say "    FAILED: $($_.Exception.Message)" 'Red'
  }
}

function Invoke-Native([string]$Exe, [string[]]$ArgList, [string]$WorkDir = $Root) {
  # npm.ps1 and npx.ps1 rebuild their arguments from the caller's source line, which breaks when
  # they are called through a variable. The .cmd versions take plain arguments.
  if ($Exe -eq 'npm' -or $Exe -eq 'npx') { $Exe = "$Exe.cmd" }
  Push-Location $WorkDir
  try {
    & $Exe @ArgList
    if ($LASTEXITCODE -ne 0) { throw "'$Exe $($ArgList -join ' ')' stopped with error code $LASTEXITCODE" }
  } finally { Pop-Location }
}

function Update-SessionPath {
  $machine = [Environment]::GetEnvironmentVariable('Path', 'Machine')
  $user = [Environment]::GetEnvironmentVariable('Path', 'User')
  $env:Path = "$machine;$user"
}

function Add-UserPath([string]$Dir) {
  $user = [Environment]::GetEnvironmentVariable('Path', 'User')
  if (-not $user) { $user = '' }
  $parts = @($user.Split(';') | Where-Object { $_ })
  if ($parts -notcontains $Dir) {
    [Environment]::SetEnvironmentVariable('Path', (($parts + $Dir) -join ';'), 'User')
  }
  if (@($env:Path.Split(';')) -notcontains $Dir) { $env:Path = "$env:Path;$Dir" }
}

function Set-UserVariable([string]$Name, [string]$Value) {
  [Environment]::SetEnvironmentVariable($Name, $Value, 'User')
  Set-Item -Path "Env:$Name" -Value $Value
}

function Test-Command([string]$Name) { [bool](Get-Command $Name -ErrorAction SilentlyContinue) }

function Get-File([string]$Url, [string]$Dest) {
  New-Item -ItemType Directory -Force -Path (Split-Path $Dest) | Out-Null
  if (Test-Path $Dest) { Remove-Item $Dest -Force }
  Say "    Downloading $Url"
  & curl.exe -L --fail --retry 5 --retry-delay 3 --progress-bar -o $Dest $Url
  if ($LASTEXITCODE -ne 0) { throw "Download failed: $Url" }
}

function Get-Text([string]$Url) {
  $content = (Invoke-WebRequest $Url -UseBasicParsing).Content
  if ($content -is [byte[]]) { return [Text.Encoding]::UTF8.GetString($content) }
  return [string]$content
}

function Assert-Hash([string]$File, [string]$Expected, [string]$Algorithm = 'SHA256') {
  $actual = (Get-FileHash -Path $File -Algorithm $Algorithm).Hash
  if ($actual -ne $Expected.ToUpper()) {
    Remove-Item $File -Force
    throw "The download $([IO.Path]::GetFileName($File)) is damaged or was changed ($Algorithm does not match). Run SETUP.bat again."
  }
  Say "    $Algorithm checked" 'DarkGray'
}

function Install-Winget([string]$Id, [string]$Override = '', [string]$Scope = '') {
  $wingetArgs = @('install', '--id', $Id, '-e', '--silent', '--accept-package-agreements', '--accept-source-agreements', '--disable-interactivity')
  if ($Scope) { $wingetArgs += @('--scope', $Scope) }
  if ($Override) { $wingetArgs += @('--override', $Override) }
  & winget @wingetArgs
  # 0 = installed. -1978335189 = already installed, no newer version.
  if ($LASTEXITCODE -ne 0 -and $LASTEXITCODE -ne -1978335189) {
    throw "winget could not install $Id (error code $LASTEXITCODE)"
  }
  Update-SessionPath
}

# ---------------------------------------------------------------- what is installed

function Get-NodeVersion {
  if (-not (Test-Command 'node')) { return $null }
  $v = & node --version
  if ("$v" -match 'v(\d+)\.(\d+)\.(\d+)') { return [version]"$($Matches[1]).$($Matches[2]).$($Matches[3])" }
  return $null
}

function Get-PythonVersion {
  foreach ($name in @('python', 'py')) {
    $cmd = Get-Command $name -ErrorAction SilentlyContinue
    if ($cmd -and $cmd.Source -notlike '*WindowsApps*') {
      try {
        $out = & $name --version
        if ("$out" -match 'Python (\d+)\.(\d+)') { return [version]"$($Matches[1]).$($Matches[2])" }
      } catch { }
    }
  }
  return $null
}

function Get-VsCppPath {
  $vswhere = Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio\Installer\vswhere.exe'
  if (-not (Test-Path $vswhere)) { return $null }
  $path = & $vswhere -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath | Select-Object -First 1
  if ($path) { return "$path" }
  return $null
}

function Get-JdkHome {
  if ($env:JAVA_HOME -and (Test-Path (Join-Path $env:JAVA_HOME 'bin\java.exe'))) {
    $rel = Join-Path $env:JAVA_HOME 'release'
    if ((Test-Path $rel) -and ((Get-Content $rel -Raw) -match 'JAVA_VERSION="(1[7-9]|2\d)')) { return $env:JAVA_HOME }
  }
  $candidates = @(Get-ChildItem 'C:\Program Files\Microsoft' -Directory -Filter 'jdk-17*' -ErrorAction SilentlyContinue) +
                @(Get-ChildItem 'C:\Android\jdk' -Directory -Filter 'jdk-17*' -ErrorAction SilentlyContinue)
  $hit = $candidates | Where-Object { Test-Path (Join-Path $_.FullName 'bin\java.exe') } | Select-Object -First 1
  if ($hit) { return $hit.FullName }
  return $null
}

function Get-FlutterBin {
  $cmd = Get-Command 'flutter' -ErrorAction SilentlyContinue
  if ($cmd) { return (Split-Path $cmd.Source) }
  foreach ($dir in @("$Tools\flutter\bin", 'C:\Android\flutter\bin', 'C:\flutter\bin', 'C:\src\flutter\bin')) {
    if (Test-Path (Join-Path $dir 'flutter.bat')) { return $dir }
  }
  return $null
}

function Get-FlutterVersion([string]$Bin) {
  $json = Join-Path $Bin 'cache\flutter.version.json'
  if (Test-Path $json) {
    try { return (Get-Content $json -Raw | ConvertFrom-Json).frameworkVersion } catch { }
  }
  $versionFile = Join-Path (Split-Path $Bin) 'version'
  if (Test-Path $versionFile) { return (Get-Content $versionFile -Raw).Trim() }
  return $null
}

function Get-AndroidSdk {
  foreach ($dir in @($env:ANDROID_HOME, $env:ANDROID_SDK_ROOT, "$Tools\android-sdk", 'C:\Android\sdk', "$env:LOCALAPPDATA\Android\Sdk")) {
    if ($dir -and (Test-Path (Join-Path $dir 'cmdline-tools\latest\bin\sdkmanager.bat'))) { return $dir }
  }
  return $null
}

function Show-Status {
  $node = Get-NodeVersion
  $py = Get-PythonVersion
  $flutterBin = Get-FlutterBin
  $flutterVer = $null
  if ($flutterBin) { $flutterVer = Get-FlutterVersion $flutterBin }
  $rows = @(
    @{ Tool = 'winget';              Found = (Test-Command 'winget') },
    @{ Tool = 'Git';                 Found = (Test-Command 'git') },
    @{ Tool = "Node.js $NodeMajor";  Found = $(if ($node) { "$node" } else { $false }) },
    @{ Tool = 'Python 3';            Found = $(if ($py) { "$py" } else { $false }) },
    @{ Tool = 'C++ Build Tools';     Found = $(if (Get-VsCppPath) { $true } else { $false }) },
    @{ Tool = 'Rust (cargo)';        Found = (Test-Command 'cargo') -or (Test-Path "$env:USERPROFILE\.cargo\bin\cargo.exe") },
    @{ Tool = 'Java 17 (JDK)';       Found = $(if (Get-JdkHome) { Get-JdkHome } else { $false }) },
    @{ Tool = 'Flutter';             Found = $(if ($flutterVer) { $flutterVer } else { $false }) },
    @{ Tool = 'Android SDK';         Found = $(if (Get-AndroidSdk) { Get-AndroidSdk } else { $false }) }
  )
  Say ''
  Say 'What this PC has now:' 'White'
  foreach ($r in $rows) {
    if ($r.Found) {
      $detail = ''
      if ($r.Found -isnot [bool]) { $detail = " ($($r.Found))" }
      Say ("  [yes] {0}{1}" -f $r.Tool, $detail) 'Green'
    } else {
      Say ("  [no]  {0}" -f $r.Tool) 'Yellow'
    }
  }
}

# ---------------------------------------------------------------- install steps

function Install-Git {
  if (Test-Command 'git') { return 'already installed' }
  Install-Winget 'Git.Git' '' 'machine'
  if (-not (Test-Command 'git')) { throw 'Git was installed but is not on PATH yet. Restart the PC and run SETUP.bat again.' }
}

function Install-Node {
  $v = Get-NodeVersion
  if ($v -and ($v.Major -gt $NodeMajor -or ($v.Major -eq $NodeMajor -and $v.Minor -ge $NodeMinMinor))) { return "already installed ($v)" }
  $index = Invoke-RestMethod 'https://nodejs.org/dist/index.json'
  $release = $index | Where-Object { $_.version -like "v$NodeMajor.*" } | Select-Object -First 1
  if (-not $release) { throw "Could not find Node.js $NodeMajor on nodejs.org" }
  $ver = $release.version
  $msi = "node-$ver-x64.msi"
  $dest = Join-Path $Downloads $msi
  Get-File "https://nodejs.org/dist/$ver/$msi" $dest
  $sums = Get-Text "https://nodejs.org/dist/$ver/SHASUMS256.txt"
  $line = ($sums -split "`n") | Where-Object { $_ -match [regex]::Escape($msi) } | Select-Object -First 1
  if (-not $line) { throw 'Could not find the Node.js checksum' }
  Assert-Hash $dest (($line.Trim() -split '\s+')[0])
  $p = Start-Process msiexec.exe -ArgumentList "/i `"$dest`" /qn /norestart" -Wait -PassThru
  if ($p.ExitCode -ne 0 -and $p.ExitCode -ne 3010) { throw "The Node.js installer stopped with code $($p.ExitCode)" }
  Update-SessionPath
  return "installed $ver"
}

function Install-Python {
  $v = Get-PythonVersion
  if ($v -and $v -ge $PythonMin) { return "already installed ($v)" }
  Install-Winget 'Python.Python.3.12' '/quiet InstallAllUsers=1 PrependPath=1 Include_launcher=1' 'machine'
  if (-not (Get-PythonVersion)) { throw 'Python was installed but is not on PATH yet. Restart the PC and run SETUP.bat again.' }
}

function Install-CppBuildTools {
  if (Get-VsCppPath) { return 'already installed' }
  Say '    This one is big (about 3 GB) and can take 10 to 30 minutes. Please wait.' 'Yellow'
  Install-Winget 'Microsoft.VisualStudio.2022.BuildTools' '--wait --quiet --norestart --nocache --add Microsoft.VisualStudio.Workload.VCTools --includeRecommended'
  if (-not (Get-VsCppPath)) { throw 'The C++ Build Tools did not install. Restart the PC and run SETUP.bat again.' }
}

function Install-Rust([bool]$WithAndroid) {
  $cargoBin = Join-Path $env:USERPROFILE '.cargo\bin'
  if (-not (Test-Command 'cargo') -and -not (Test-Path (Join-Path $cargoBin 'cargo.exe'))) {
    $exe = Join-Path $Downloads 'rustup-init.exe'
    $base = 'https://static.rust-lang.org/rustup/dist/x86_64-pc-windows-msvc/rustup-init.exe'
    Get-File $base $exe
    $expected = ((Get-Text "$base.sha256").Trim() -split '\s+')[0]
    Assert-Hash $exe $expected
    Invoke-Native $exe @('-y', '--default-toolchain', 'stable', '--profile', 'minimal')
  }
  Add-UserPath $cargoBin
  if ($WithAndroid) {
    Invoke-Native 'rustup' @('target', 'add', 'aarch64-linux-android', 'x86_64-linux-android')
    if (-not (Test-Command 'cargo-ndk')) { Invoke-Native 'cargo' @('install', 'cargo-ndk', '--locked') }
  }
  return (& cargo --version)
}

function Install-Jdk {
  $jdk = Get-JdkHome
  if (-not $jdk) {
    Install-Winget 'Microsoft.OpenJDK.17' '' 'machine'
    $jdk = Get-JdkHome
    if (-not $jdk) { throw 'Java 17 was installed but could not be found.' }
  }
  Set-UserVariable 'JAVA_HOME' $jdk
  return $jdk
}

function Install-Flutter {
  $bin = Get-FlutterBin
  if ($bin -and ((Get-FlutterVersion $bin) -eq $FlutterVersion)) {
    Add-UserPath $bin
    return "already installed ($FlutterVersion)"
  }
  $feed = Invoke-RestMethod 'https://storage.googleapis.com/flutter_infra_release/releases/releases_windows.json'
  $rel = $feed.releases | Where-Object { $_.version -eq $FlutterVersion -and $_.channel -eq 'stable' } | Select-Object -First 1
  if (-not $rel) { throw "Flutter $FlutterVersion was not found in Google's release list" }
  $zip = Join-Path $Downloads ([IO.Path]::GetFileName($rel.archive))
  Say '    Flutter is about 1.5 GB.' 'Yellow'
  Get-File "$($feed.base_url)/$($rel.archive)" $zip
  Assert-Hash $zip $rel.sha256
  $target = Join-Path $Tools 'flutter'
  if (Test-Path $target) { Remove-Item $target -Recurse -Force }
  Invoke-Native 'tar' @('-xf', $zip, '-C', $Tools)
  $bin = Join-Path $target 'bin'
  Add-UserPath $bin
  Invoke-Native (Join-Path $bin 'flutter.bat') @('config', '--no-analytics')
  return "installed $FlutterVersion"
}

function Get-CmdlineToolsUrl {
  [xml]$repo = Get-Text 'https://dl.google.com/android/repository/repository2-3.xml'
  $pkg = $repo.SelectNodes("//*[local-name()='remotePackage'][@path='cmdline-tools;latest']") | Select-Object -First 1
  if (-not $pkg) { throw "Could not find Android's command-line tools in Google's list" }
  foreach ($archive in $pkg.SelectNodes(".//*[local-name()='archive']")) {
    $os = $archive.SelectSingleNode(".//*[local-name()='host-os']")
    if ($os -and $os.InnerText -eq 'windows') {
      $url = $archive.SelectSingleNode(".//*[local-name()='complete']/*[local-name()='url']").InnerText
      $sha1 = $archive.SelectSingleNode(".//*[local-name()='complete']/*[local-name()='checksum']").InnerText
      return @{ Url = "https://dl.google.com/android/repository/$url"; Sha1 = $sha1 }
    }
  }
  throw "Could not find the Windows download of Android's command-line tools"
}

function Install-AndroidSdk {
  $sdk = Get-AndroidSdk
  if (-not $sdk) {
    $sdk = Join-Path $Tools 'android-sdk'
    $info = Get-CmdlineToolsUrl
    $zip = Join-Path $Downloads 'android-cmdline-tools.zip'
    Get-File $info.Url $zip
    Assert-Hash $zip $info.Sha1 'SHA1'
    $tmp = Join-Path $sdk '_tmp'
    New-Item -ItemType Directory -Force -Path $tmp | Out-Null
    Invoke-Native 'tar' @('-xf', $zip, '-C', $tmp)
    $latest = Join-Path $sdk 'cmdline-tools\latest'
    if (Test-Path $latest) { Remove-Item $latest -Recurse -Force }
    New-Item -ItemType Directory -Force -Path (Split-Path $latest) | Out-Null
    Move-Item (Join-Path $tmp 'cmdline-tools') $latest
    Remove-Item $tmp -Recurse -Force
  }
  Set-UserVariable 'ANDROID_HOME' $sdk
  Set-UserVariable 'ANDROID_SDK_ROOT' $sdk
  Add-UserPath (Join-Path $sdk 'platform-tools')
  Add-UserPath (Join-Path $sdk 'emulator')

  $sdkmanager = Join-Path $sdk 'cmdline-tools\latest\bin\sdkmanager.bat'
  Say '    Accepting the Android SDK licences.'
  ("y`n" * 40) | & $sdkmanager "--sdk_root=$sdk" --licenses | Out-Null
  Say '    Installing Android parts (about 6 GB). This can take a while.' 'Yellow'
  Invoke-Native $sdkmanager @("--sdk_root=$sdk", 'platform-tools', "platforms;android-$AndroidApi", "build-tools;$AndroidBuildTools", "ndk;$NdkVersion", 'emulator', $SystemImage)

  $flutter = Join-Path (Get-FlutterBin) 'flutter.bat'
  Invoke-Native $flutter @('config', "--android-sdk=$sdk")
  if ($env:JAVA_HOME) { Invoke-Native $flutter @('config', "--jdk-dir=$env:JAVA_HOME") }
  ("y`n" * 40) | & $flutter doctor --android-licenses | Out-Null

  $avdmanager = Join-Path $sdk 'cmdline-tools\latest\bin\avdmanager.bat'
  $avds = & $avdmanager list avd -c
  if (@($avds) -notcontains $AvdName) {
    'no' | & $avdmanager create avd -n $AvdName -k $SystemImage -d pixel_7 | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'Could not create the Android emulator' }
  }
  return $sdk
}

function Enable-EmulatorAcceleration {
  $feature = Get-WindowsOptionalFeature -Online -FeatureName HypervisorPlatform
  if ($feature.State -eq 'Enabled') { return 'already on' }
  Enable-WindowsOptionalFeature -Online -FeatureName HypervisorPlatform -All -NoRestart | Out-Null
  $script:NeedsRestart = $true
  return 'turned on (restart the PC before using the Android emulator)'
}

# ---------------------------------------------------------------- project steps

$NpmFolders = @('connectors', 'sdk-web\verify-node', 'server', 'sdk-web\widget', 'sdk-web\demo-site', 'windows', 'tests')

function Install-ProjectPackages {
  foreach ($folder in $NpmFolders) {
    $dir = Join-Path $Root $folder
    Say "    npm packages for $folder"
    if (Test-Path (Join-Path $dir 'package-lock.json')) {
      Invoke-Native 'npm' @('ci', '--no-audit', '--no-fund') $dir
    } else {
      Invoke-Native 'npm' @('install', '--no-audit', '--no-fund') $dir
    }
  }
  Invoke-Native 'python' @('-m', 'pip', 'install', '--upgrade', '--quiet', 'pip')
  Invoke-Native 'python' @('-m', 'pip', 'install', '--quiet', 'cryptography>=41', 'pytest>=7')
}

function Get-AadhaarFiles {
  Say '    The official Anon Aadhaar circuit files are about 900 MB.' 'Yellow'
  Invoke-Native 'npm' @('run', 'fetch-artifacts') (Join-Path $Root 'server')
}

function Build-Project { Invoke-Native 'npm' @('run', 'build') $Root }

function Prepare-Mobile {
  $flutter = Join-Path (Get-FlutterBin) 'flutter.bat'
  Invoke-Native $flutter @('pub', 'get') (Join-Path $Root 'mobile')
}

function Test-Project([bool]$WithMobile) {
  # Every part's tests plus the end-to-end product tests, with one summary table.
  # run-all.mjs also runs the Android app's tests whenever Flutter is installed.
  if ($WithMobile) { Add-UserPath (Get-FlutterBin) }
  Invoke-Native 'node' @('tests\run-all.mjs') $Root
  return 'all tests passed'
}

function New-DesktopShortcut {
  $desktop = [Environment]::GetFolderPath('Desktop')
  $shell = New-Object -ComObject WScript.Shell
  $link = $shell.CreateShortcut((Join-Path $desktop 'Start V18.lnk'))
  $link.TargetPath = Join-Path $Root 'START-V18.bat'
  $link.WorkingDirectory = $Root
  $link.Description = 'Start the V18 server and demo website'
  $link.Save()
  return (Join-Path $desktop 'Start V18.lnk')
}

# ---------------------------------------------------------------- main

Say ''
Say '==============================================================' 'White'
Say '  V18 setup' 'White'
Say '  This installs everything V18 needs on this PC.' 'White'
Say '==============================================================' 'White'
Say "  Project folder: $Root"

if ($CheckOnly) {
  Show-Status
  Say ''
  Say 'Checking that every download source answers (nothing is downloaded or installed):' 'White'
  try {
    $index = Invoke-RestMethod 'https://nodejs.org/dist/index.json'
    $nodeRel = ($index | Where-Object { $_.version -like "v$NodeMajor.*" } | Select-Object -First 1).version
    Say "  Node.js:   $nodeRel  https://nodejs.org/dist/$nodeRel/node-$nodeRel-x64.msi" 'Green'
  } catch { Say "  Node.js:   FAILED ($($_.Exception.Message))" 'Red' }
  try {
    $rustSum = ((Get-Text 'https://static.rust-lang.org/rustup/dist/x86_64-pc-windows-msvc/rustup-init.exe.sha256').Trim() -split '\s+')[0]
    Say "  Rust:      rustup-init.exe (sha256 $($rustSum.Substring(0, 12))...)" 'Green'
  } catch { Say "  Rust:      FAILED ($($_.Exception.Message))" 'Red' }
  try {
    $feed = Invoke-RestMethod 'https://storage.googleapis.com/flutter_infra_release/releases/releases_windows.json'
    $fl = $feed.releases | Where-Object { $_.version -eq $FlutterVersion -and $_.channel -eq 'stable' } | Select-Object -First 1
    if (-not $fl) { throw "Flutter $FlutterVersion not listed" }
    Say "  Flutter:   $($feed.base_url)/$($fl.archive)" 'Green'
  } catch { Say "  Flutter:   FAILED ($($_.Exception.Message))" 'Red' }
  try {
    $ct = Get-CmdlineToolsUrl
    Say "  Android:   $($ct.Url)" 'Green'
  } catch { Say "  Android:   FAILED ($($_.Exception.Message))" 'Red' }
  Say ''
  Say 'Check only: nothing was installed or changed.' 'White'
  exit 0
}

$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
  Say 'Please start setup by double-clicking SETUP.bat, and click "Yes" when Windows asks for permission.' 'Red'
  exit 1
}

if (-not (Test-Command 'winget')) {
  Say 'Windows "App Installer" (winget) is missing. Trying to repair it...' 'Yellow'
  try { Add-AppxPackage -RegisterByFamilyName -MainPackage Microsoft.DesktopAppInstaller_8wekyb3d8bbwe } catch { }
  Update-SessionPath
  if (-not (Test-Command 'winget')) {
    Say 'Please install "App Installer" from the Microsoft Store (it opens now), then run SETUP.bat again.' 'Red'
    Start-Process 'ms-windows-store://pdp/?productid=9NBLGGH4NNS1'
    exit 1
  }
}

Show-Status

if (-not $Mode) {
  Say ''
  Say 'Which setup do you want?' 'White'
  Say '  1) Full (recommended): server, website, Windows app AND Android app tools. About 25 GB.'
  Say '  2) Light: server, website and Windows app only. About 6 GB.'
  $answer = Read-Host 'Type 1 or 2, then press Enter (just Enter = 1)'
  if ($answer -eq '2') { $Mode = 'light' } else { $Mode = 'full' }
}
$full = ($Mode -eq 'full')

$needGb = 8
if ($full) { $needGb = 30 }
$freeGb = [math]::Floor((Get-PSDrive C).Free / 1GB)
if ($freeGb -lt $needGb) {
  Say "Drive C: has $freeGb GB free, but this setup needs about $needGb GB. Free some space and run SETUP.bat again." 'Red'
  exit 1
}

New-Item -ItemType Directory -Force -Path $Downloads | Out-Null
try { Start-Transcript -Path $LogFile -Append | Out-Null } catch { }

Say ''
Say "Starting the $Mode setup. Leave this window open. It can take an hour on a slow connection." 'White'

Invoke-Step 'Git' { Install-Git }
Invoke-Step "Node.js $NodeMajor" { Install-Node }
Invoke-Step 'Python 3' { Install-Python }
Invoke-Step 'Microsoft C++ Build Tools' { Install-CppBuildTools }
Invoke-Step 'Rust' { Install-Rust $full }
if ($full) {
  Invoke-Step 'Java 17' { Install-Jdk }
  Invoke-Step "Flutter $FlutterVersion" { Install-Flutter }
  Invoke-Step 'Android SDK, NDK and emulator' { Install-AndroidSdk }
  Invoke-Step 'Emulator speed-up (Windows Hypervisor Platform)' { Enable-EmulatorAcceleration }
}
Update-SessionPath
Invoke-Step 'V18 packages (npm and Python)' { Install-ProjectPackages }
Invoke-Step 'Anon Aadhaar circuit files' { Get-AadhaarFiles }
Invoke-Step 'Build V18' { Build-Project }
if ($full) { Invoke-Step 'Android app packages' { Prepare-Mobile } }
Invoke-Step 'Run all tests' { Test-Project $full }
Invoke-Step 'Desktop shortcut "Start V18"' { New-DesktopShortcut }

Say ''
Say '==============================================================' 'White'
Say '  Summary' 'White'
Say '==============================================================' 'White'
foreach ($r in $script:Results) {
  $color = 'Green'
  if ($r.Result -ne 'OK') { $color = 'Red' }
  $line = '  {0,-7} {1}' -f $r.Result, $r.Step
  if ($r.Note) { $line = "$line  ($($r.Note))" }
  Say $line $color
}
$failed = @($script:Results | Where-Object { $_.Result -ne 'OK' })
Say ''
if ($failed.Count -eq 0) {
  Say 'Everything is set up.' 'Green'
  Say 'To start V18, double-click "Start V18" on the desktop (or START-V18.bat in the project folder).' 'White'
} else {
  Say "$($failed.Count) step(s) failed. Restart the PC and run SETUP.bat again; finished steps are skipped." 'Yellow'
  Say "If it still fails, send the file setup-log.txt from the project folder to whoever gave you V18." 'Yellow'
}
if ($script:NeedsRestart) { Say 'Restart the PC before using the Android emulator.' 'Yellow' }
try { Stop-Transcript | Out-Null } catch { }
if ($failed.Count -gt 0) { exit 1 }
exit 0
