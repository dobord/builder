$ErrorActionPreference='Stop'
Add-Type -AssemblyName UIAutomationClient
Add-Type -AssemblyName UIAutomationTypes
$directory=Join-Path $env:RUNNER_TEMP 'native-private'
New-Item -ItemType Directory -Force -Path $directory | Out-Null
$rdp=Join-Path $directory 'consent-preflight.rdp'
# Port 9 is not a test server: this step proves only that the first-use dialog
# is actually closed. It never counts a connection dialog as a RemoteApp pass.
@('full address:s:localhost:9','prompt for credentials:i:1','authentication level:i:2','redirectclipboard:i:0','redirectprinters:i:0','redirectsmartcards:i:0','disableconnectionsharing:i:1') | Set-Content -Encoding Unicode $rdp
$client=$null;$seen=$false;$closed=$false
try {
    $client=Start-Process -FilePath "$env:WINDIR\System32\mstsc.exe" -ArgumentList ('"'+$rdp+'"') -PassThru
    $root=[System.Windows.Automation.AutomationElement]::RootElement
    $process=New-Object System.Windows.Automation.PropertyCondition([System.Windows.Automation.AutomationElement]::ProcessIdProperty,$client.Id)
    $verification=New-Object System.Windows.Automation.PropertyCondition([System.Windows.Automation.AutomationElement]::AutomationIdProperty,'VerificationCheckBox')
    for($attempt=0;$attempt -lt 25;$attempt++) {
        Start-Sleep -Milliseconds 500
        $windows=$root.FindAll([System.Windows.Automation.TreeScope]::Children,$process)
        $present=$false
        foreach($window in $windows) {
            if($null -ne $window.FindFirst([System.Windows.Automation.TreeScope]::Descendants,$verification)) {$present=$true}
        }
        if($present) {
            $seen=$true
            & (Join-Path $PSScriptRoot 'native-consent.ps1') -ClientProcessId $client.Id -EvidenceDirectory $directory
        } elseif($seen) {$closed=$true;break}
    }
    @{first_use_dialog_seen=$seen;first_use_dialog_closed=$closed;rdp_connection_tested=$false} | ConvertTo-Json | Set-Content -Encoding UTF8 (Join-Path $directory 'consent-preflight.json')
    if(-not ($seen -and $closed)) {throw 'RDP first-use consent preflight did not prove dialog closure'}
} finally {
    if($null -ne $client) {Stop-Process -Id $client.Id -Force -ErrorAction SilentlyContinue}
    Remove-Item $rdp -Force -ErrorAction SilentlyContinue
}
