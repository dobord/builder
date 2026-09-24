param([Parameter(Mandatory=$true)][int]$ClientProcessId,[Parameter(Mandatory=$true)][string]$EvidenceDirectory)
$ErrorActionPreference='Stop'
Add-Type -AssemblyName UIAutomationClient
Add-Type -AssemblyName UIAutomationTypes
$root=[System.Windows.Automation.AutomationElement]::RootElement
$condition=New-Object System.Windows.Automation.PropertyCondition([System.Windows.Automation.AutomationElement]::ProcessIdProperty,$ClientProcessId)
$windows=$root.FindAll([System.Windows.Automation.TreeScope]::Children,$condition)
$evidence=@()
$actions=@()
foreach($window in $windows) {
    $elements=$window.FindAll([System.Windows.Automation.TreeScope]::Descendants,[System.Windows.Automation.Condition]::TrueCondition)
    $names=@()
    foreach($element in $elements) {
        $names += $element.Current.Name
        if($evidence.Count -lt 200) {
            $evidence += @{name=$element.Current.Name;type=$element.Current.ControlType.ProgrammaticName;id=$element.Current.AutomationId;enabled=$element.Current.IsEnabled}
        }
    }
    # Authorize only the one-time education dialog and the signed localhost fixture.
    # This does not modify Windows policy or click through certificate/authentication errors.
    $education='I understand and allow RDP files to open on this device for my account'
    $educationFound=$false
    foreach($element in $elements) {
        if($element.Current.ControlType -eq [System.Windows.Automation.ControlType]::CheckBox -and $element.Current.Name.Trim().Replace('&','') -eq $education) {
            $toggle=$element.GetCurrentPattern([System.Windows.Automation.TogglePattern]::Pattern)
            if($toggle.Current.ToggleState -eq [System.Windows.Automation.ToggleState]::Off) {$toggle.Toggle()}
            $educationFound=$true
            $actions += 'fixture-education-accepted'
        }
    }
    $signedFixture=($names -join "`n") -match 'Disposable RemoteApp test' -and ($names -join "`n") -match 'localhost'
    foreach($element in $elements) {
        if($element.Current.ControlType -ne [System.Windows.Automation.ControlType]::Button -or -not $element.Current.IsEnabled) {continue}
        $name=$element.Current.Name.Replace('&','')
        if(($educationFound -and $name -eq 'OK') -or ($signedFixture -and $name -in @('Connect','Continue'))) {
            $invoke=$element.GetCurrentPattern([System.Windows.Automation.InvokePattern]::Pattern)
            $invoke.Invoke()
            $actions += ('fixture-button-'+$name)
            break
        }
    }
}
@{controls=$evidence;actions=$actions} | ConvertTo-Json -Depth 5 | Set-Content -Encoding UTF8 (Join-Path $EvidenceDirectory 'uia-dialog.json')
