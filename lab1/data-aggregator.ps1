
#
# Small helper function to print out the pretty objects we make along the way
#
function printObj($name, $obj) {
	Write-Host "###################################"
	Write-Host "#"$name
	Write-Host "###################################"
	Write-Host (($obj) | Out-String)
}
##################################################################
##################### Time Info###################################
##################################################################
$time = New-Object PSObject
$time | Add-Member "Date" (Get-Date)
$time | Add-Member "Timezone" (Get-Timezone)
$time | Add-Member "Uptime" ((Get-Date) - (gcim Win32_OperatingSystem).LastBootUpTime)
printObj -name "Time Information" -obj $time

##################################################################
##################### Windows  ###################################
##################################################################
$windows = New-Object PSObject
$windows | Add-Member "Windows Version (M.m.B.R)" ([System.Environment]::OSVersion.Version)
$windows | Add-Member "Windows Name" (Get-WmiObject -class Win32_OperatingSystem).Caption
printObj -name "Windows Information" -obj $windows

##################################################################
##################### HARDWARE ###################################
##################################################################
$hardware =  New-Object PSObject
 
$hardware | Add-Member "CPU Brand and Type" (Get-WmiObject win32_processor).Name
$hardware | Add-Member "Memory Size (B)" (Get-WmiObject win32_computersystem).totalphysicalmemory
$hardware | Add-Member "HDD Size (B)" (Get-WmiObject win32_diskdrive | foreach size)
$hardware | Add-Member "Mounted Drives" (Get-PSDrive -PSProvider FileSystem | foreach Name)
$hardware | Add-Member "File Systems" (Get-WmiObject win32_logicalDisk | foreach VolumeName)
printObj -name "Hardware Information" -obj $hardware

##################################################################
##################### Host Info Info #############################
##################################################################
$hostinfo = New-Object PSobject
$hostinfo | Add-Member "Domain" (Get-WmiObject win32_computersystem).Domain
$hostinfo | Add-Member "Hostname" (Get-WmiObject win32_computersystem).Name
printObj -name "Host Information" -obj $hostinfo

##################################################################
##################### User Info ##################################
##################################################################
$users = @()
#grabs local users
foreach($account in (Get-WmiObject win32_useraccount | Select SID, Name, InstallDate)) {
	$account | Add-Member "Domain Name" "Local User"
    $users += $account
}
#grabs system users
foreach($account in (Get-WmiObject win32_systemaccount | Select SID, Name, InstallDate)) {
	$account | Add-Member "Domain Name" "System User"
    $users += $account
}
#for domain users we should check to see if we can access an active directory
$isDomain = (Get-CimInstance -ClassName Win32_ComputerSystem).PartOfDomain
if($isDomain -eq $true){
	#MSDN was very useful for this
	foreach($account in Get-ADUser -Filter * | Select Name, SID) {
		$account | Add-Member "Domain Name" (Get-ADDomainController).Name
		$account | Add-Member "DC Address" (Get-ADDomainController).IPv4Address
		$users += $account
	}
}else{
	Write-Host "No Domain users b/c there is no active directory associated with this computer"
}
#now for system accounts we simply check win32_systemaccount
foreach($account in (Get-WmiObject -ClassName win32_service | Select -uniq startname)) {
	#rename startname to Name
	$account | Add-Member Name ($account).startname
	$account = $account | Select Name
	$account | Add-Member "Domain Name" "Service User"
    $users += $account
}
printObj -name "User Information" -obj $users

##################################################################
##################### Start at Boot Services######################
##################################################################
$svcs = Get-Service | where {$_.StartType -eq 'Automatic'} | Select Name, DisplayName
printObj -name "Automatic Services on boot" -obj $svcs
$programs = Get-Ciminstance win32_startupcommand
printObj -name "Startup Programs on boot" -obj $programs