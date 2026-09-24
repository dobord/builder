param([Parameter(Mandatory=$true)][int]$ClientProcessId,[Parameter(Mandatory=$true)][string]$EvidenceDirectory)
$ErrorActionPreference='Stop'
Add-Type -AssemblyName UIAutomationClient
Add-Type -AssemblyName UIAutomationTypes
if(-not ('FixtureTaskDialog' -as [type])) {
Add-Type @'
using System;
using System.Runtime.InteropServices;
public static class FixtureTaskDialog {
 [StructLayout(LayoutKind.Sequential)] public struct Point { public int x,y; }
 [StructLayout(LayoutKind.Sequential)] public struct MouseInput {
  public int dx,dy; public uint mouseData,flags,time; public UIntPtr extra;
 }
 [StructLayout(LayoutKind.Explicit)] public struct InputUnion {
  [FieldOffset(0)] public MouseInput mouse;
 }
 [StructLayout(LayoutKind.Sequential)] public struct Input {
  public uint type; public InputUnion data;
 }
 [DllImport("user32.dll",SetLastError=true)] public static extern bool PostMessage(IntPtr hWnd,uint message,IntPtr wParam,IntPtr lParam);
 [DllImport("user32.dll")] public static extern uint GetWindowThreadProcessId(IntPtr hWnd,out uint processId);
 [DllImport("user32.dll")] static extern IntPtr WindowFromPoint(Point p);
 [DllImport("user32.dll")] static extern bool SetForegroundWindow(IntPtr hWnd);
 [DllImport("user32.dll",SetLastError=true)] static extern bool SetCursorPos(int x,int y);
 [DllImport("user32.dll",SetLastError=true)] static extern uint SendInput(uint n,Input[] input,int size);
 public static void ClickOwned(IntPtr window,uint pid,int x,int y) {
  uint owner; GetWindowThreadProcessId(window,out owner);
  if(window==IntPtr.Zero || owner!=pid) throw new InvalidOperationException("Dialog owner mismatch");
  SetForegroundWindow(window);
  GetWindowThreadProcessId(WindowFromPoint(new Point{x=x,y=y}),out owner);
  if(owner!=pid) throw new InvalidOperationException("Consent button is covered by another process");
  if(!SetCursorPos(x,y)) throw new InvalidOperationException("Unable to position fixture input");
  Input[] input=new Input[2];
  input[0].data.mouse.flags=0x0002; input[1].data.mouse.flags=0x0004;
  if(SendInput(2,input,Marshal.SizeOf(typeof(Input)))!=2) throw new InvalidOperationException("Fixture click was not delivered");
 }
}
'@
}
$root=[System.Windows.Automation.AutomationElement]::RootElement
$condition=New-Object System.Windows.Automation.PropertyCondition([System.Windows.Automation.AutomationElement]::ProcessIdProperty,$ClientProcessId)
$windows=$root.FindAll([System.Windows.Automation.TreeScope]::Children,$condition)
$evidence=@();$actions=@();$failure=$null
try {
 foreach($window in $windows) {
  try {
    $elements=$window.FindAll([System.Windows.Automation.TreeScope]::Descendants,[System.Windows.Automation.Condition]::TrueCondition)
    $names=@()
    foreach($element in $elements) {
        $names += $element.Current.Name
        if($evidence.Count -lt 200) {
            $patterns=@($element.GetSupportedPatterns() | ForEach-Object {$_.ProgrammaticName})
            $evidence += @{name=$element.Current.Name;type=$element.Current.ControlType.ProgrammaticName;id=$element.Current.AutomationId;enabled=$element.Current.IsEnabled;patterns=$patterns;window=$window.Current.Name}
        }
    }
    # Consent is restricted to this generated localhost fixture and its verified
    # publisher. Never dismiss TLS/authentication errors or change machine policy.
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
    $text=$names -join "`n"
    $signedFixture=$window.Current.Name -eq 'RemoteApp security warning' -and $text.Contains('Disposable RemoteApp test') -and $text.Contains('localhost') -and $text.Contains('FRDP xcalc')
    foreach($element in $elements) {
        if(-not $element.Current.IsEnabled) {continue}
        $name=$element.Current.Name.Replace('&','')
        if($educationOn -and $name -eq 'OK' -and $element.Current.AutomationId -eq 'CommandButton_1') {
            $handle=[IntPtr]$window.Current.NativeWindowHandle
            [uint32]$owner=0
            [void][FixtureTaskDialog]::GetWindowThreadProcessId($handle,[ref]$owner)
            if($handle -eq [IntPtr]::Zero -or $owner -ne $ClientProcessId) {throw 'TaskDialog owner mismatch'}
            if(-not [FixtureTaskDialog]::PostMessage($handle,0x0466,[IntPtr]1,[IntPtr]::Zero)) {throw 'TaskDialog OK dispatch failed'}
            $actions += 'fixture-education-ok-posted'
            break
        }
        if($signedFixture -and $name -eq 'Connect') {
            $pattern=$null
            if($element.TryGetCurrentPattern([System.Windows.Automation.InvokePattern]::Pattern,[ref]$pattern)) {
                $pattern.Invoke();$actions += 'fixture-publisher-invoke';break
            }
            # Managed UIAutomationClient has no LegacyIAccessiblePattern type.
            # DirectUI buttons without InvokePattern use real, owner-checked input.
            $rect=$element.Current.BoundingRectangle
            if($rect.IsEmpty -or $rect.Width -lt 10 -or $rect.Height -lt 10 -or $rect.Width -gt 300 -or $rect.Height -gt 100) {throw 'Invalid consent button bounds'}
            [FixtureTaskDialog]::ClickOwned([IntPtr]$window.Current.NativeWindowHandle,[uint32]$ClientProcessId,[int]($rect.X+$rect.Width/2),[int]($rect.Y+$rect.Height/2))
            $actions += 'fixture-publisher-owned-input'
            break
        }
    }
  } catch [System.Windows.Automation.ElementNotAvailableException] {
    # The dialog can disappear immediately after the verified action.
  }
 }
} catch {
 $failure=$_.Exception.Message
 throw
} finally {
 @{controls=$evidence;actions=$actions;failure=$failure} | ConvertTo-Json -Depth 6 | Set-Content -Encoding UTF8 (Join-Path $EvidenceDirectory 'uia-dialog.json')
}
