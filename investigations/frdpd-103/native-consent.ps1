param([Parameter(Mandatory=$true)][int]$ClientProcessId,[Parameter(Mandatory=$true)][string]$EvidenceDirectory)
$ErrorActionPreference='Stop'
Add-Type -AssemblyName UIAutomationClient
Add-Type -AssemblyName UIAutomationTypes
if(-not ('FixtureTaskDialog' -as [type])) {
Add-Type @'
using System;
using System.Runtime.InteropServices;
public static class FixtureTaskDialog {
 [DllImport("user32.dll",SetLastError=true)]
 public static extern bool PostMessage(IntPtr hWnd,uint message,IntPtr wParam,IntPtr lParam);
 [DllImport("user32.dll")]
 public static extern uint GetWindowThreadProcessId(IntPtr hWnd,out uint processId);
}
'@
}
$root=[System.Windows.Automation.AutomationElement]::RootElement
$condition=New-Object System.Windows.Automation.PropertyCondition([System.Windows.Automation.AutomationElement]::ProcessIdProperty,$ClientProcessId)
$windows=$root.FindAll([System.Windows.Automation.TreeScope]::Children,$condition)
$evidence=@();$actions=@()
foreach($window in $windows) {
 try {
    $elements=$window.FindAll([System.Windows.Automation.TreeScope]::Descendants,[System.Windows.Automation.Condition]::TrueCondition)
    $names=@()
    foreach($element in $elements) {
        $names += $element.Current.Name
        if($evidence.Count -lt 200) {
            $patterns=@($element.GetSupportedPatterns() | ForEach-Object {$_.ProgrammaticName})
            $evidence += @{name=$element.Current.Name;type=$element.Current.ControlType.ProgrammaticName;id=$element.Current.AutomationId;enabled=$element.Current.IsEnabled;patterns=$patterns}
        }
    }
    # Only this generated localhost fixture's process is authorized. Do not
    # change machine security policy or accept certificate/authentication errors.
    $education='I understand and allow RDP files to open on this device for my account'
    $educationOn=$false
    foreach($element in $elements) {
        if($element.Current.ControlType -eq [System.Windows.Automation.ControlType]::CheckBox -and $element.Current.Name.Trim().Replace('&','') -eq $education) {
            $toggle=$element.GetCurrentPattern([System.Windows.Automation.TogglePattern]::Pattern)
            if($toggle.Current.ToggleState -eq [System.Windows.Automation.ToggleState]::Off) {$toggle.Toggle()}
            $educationOn=$toggle.Current.ToggleState -eq [System.Windows.Automation.ToggleState]::On
            if($educationOn) {$actions += 'fixture-education-checkbox-on'}
        }
    }
    $signedFixture=($names -join "`n") -match 'Disposable RemoteApp test' -and ($names -join "`n") -match 'localhost'
    foreach($element in $elements) {
        if(-not $element.Current.IsEnabled) {continue}
        $name=$element.Current.Name.Replace('&','')
        if($educationOn -and $name -eq 'OK' -and $element.Current.AutomationId -eq 'CommandButton_1') {
            # TaskDialog's command buttons are exposed as ControlType.Pane.
            # TDM_CLICK_BUTTON (WM_USER+102), IDOK=1 is its documented interface.
            $handle=[IntPtr]$window.Current.NativeWindowHandle
            [uint32]$owner=0
            [void][FixtureTaskDialog]::GetWindowThreadProcessId($handle,[ref]$owner)
            if($handle -eq [IntPtr]::Zero -or $owner -ne $ClientProcessId) {throw 'TaskDialog owner mismatch'}
            if(-not [FixtureTaskDialog]::PostMessage($handle,0x0466,[IntPtr]1,[IntPtr]::Zero)) {throw 'TaskDialog OK dispatch failed'}
            $actions += 'fixture-education-ok-posted'
            break
        }
        if($signedFixture -and $name -in @('Connect','Continue')) {
            $pattern=$null
            if($element.TryGetCurrentPattern([System.Windows.Automation.InvokePattern]::Pattern,[ref]$pattern)) {
                $pattern.Invoke();$actions += ('fixture-publisher-'+$name);break
            }
            if($element.TryGetCurrentPattern([System.Windows.Automation.LegacyIAccessiblePattern]::Pattern,[ref]$pattern)) {
                $pattern.DoDefaultAction();$actions += ('fixture-publisher-legacy-'+$name);break
            }
        }
    }
 } catch [System.Windows.Automation.ElementNotAvailableException] {
    # The owned dialog may disappear immediately after the verified action.
 }
}
@{controls=$evidence;actions=$actions} | ConvertTo-Json -Depth 6 | Set-Content -Encoding UTF8 (Join-Path $EvidenceDirectory 'uia-dialog.json')
