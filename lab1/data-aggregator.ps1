<# 
.SYNOPSIS 

DFIR Lab 1 script to poll a collection of information from a target computer

.DESCRIPTION

DFIR Lab 1 script to poll a collection of information from a target computer 
 
.OUTPUTS 
Console and CSV files locally

.PARAMETER Remote 
[Optional] IP or domain name of a target machine to run the script on.
	IF null it will run on this machine.
	Remotes can be multiple if you supply a comma seperated list
	
.PARAMETER Email
[Optional] If enabled, will prompt for an email address user/pass (gmail) to send the csvs
.PARAMETER EmailTarget
[Optional] Needed if Email is enabled, email address of where to send the email
#> 

# grab parameters.
Param([string]$Remotes = "null",[switch]$Email=$false, [string]$EmailTarget=$false)

if ($Email) {
	$EmailCredential = (Get-Credential -Message "Gmail username and password")
}

function aggregateData() {
	#keeps track of csvs we make as we go
	$emailList = @()
	#
	# Small helper function to print out the pretty objects we make along the way
	#
	function printObj($name, $obj) {
		Write-Host "###################################"
		Write-Host "#"$name
		Write-Host "###################################"
		Write-Host (($obj) | Out-String)
		$obj | Export-CSV ('./' + $name + '.csv')
		$emailList += ($name + '.csv')
	}
	function printSubHeader($name, $obj) {
		Write-Host "######"$name
		Write-Host (($obj) | Out-String)
		$obj | Export-CSV ('./' + $name + '.csv')
		$emailList += ($name + '.csv')
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
	#just grab the automatic ones - ones on startup
	$svcs = Get-Service | where {$_.StartType -eq 'Automatic'} | Select Name, DisplayName
	printObj -name "Automatic Services on boot" -obj $svcs
	#
	$programs = Get-WmiObject win32_startupcommand | Select Command, User, Location
	printObj -name "Startup Programs on boot" -obj $programs

	##################################################################
	##################### Scheduled Tasks ############################
	##################################################################
	$tasks = Get-ScheduledTask
	printObj -name "Scheduled Tasks" -obj $tasks

	##################################################################
	##################### Network ####################################
	##################################################################

	#
	# Note: Because of the nature of these instances of unrelated data,
	# we cannot form one simple table, so we are going to simply output
	# a set of information prefixed with a label 
	#
	Write-Host "###################################" #custom header
	Write-Host "###### Networking Information #####"
	Write-Host "###################################"
	$arpData = arp -a
	printSubHeader -name "Arp Data" -obj $arpData
	$macInterfaces = getmac
	printSubHeader -name "Mac Interfaces" -obj $macInterfaces
	$routeTable = Get-NetRoute
	printSubHeader -name "Routing Table" -obj $routeTable
	$ipConfig = Get-NetIPAddress | Select IPAddress, InterfaceAlias
	printSubHeader -name "Ip Addresses" -obj $ipConfig
	$dhcp = Get-WmiObject win32_networkadapterconfiguration | select DHCPServer
	printSubHeader -name "DHCP Server" -obj $dhcp
	$dns = Get-DnsClientServerAddress
	printSubHeader -name "DNS Servers" -obj $dns
	$ipv4 = Get-NetIPConfiguration | foreach IPv4defaultgateway | Select nexthop
	printSubHeader -name "IPv4 Gateway" -obj $ipv4
	$ipv6 = Get-NetIPConfiguration | foreach IPv46defaultgateway | Select nexthop
	printSubHeader -name "IPv6 Gateway" -obj $ipv6
	$listeningServices = Get-NetTCPConnection -State Listen | Select State, LocalPort, LocalAddress, RemoteAddress, OwningProcess
	foreach ($srvc in $listeningServices){ #get service name
		$srvc | Add-Member "Process Name" (Get-Process -Id $srvc.OwningProcess)
		$srvc | Add-Member "Protocol" "TCP"
	}
	printSubHeader -name "Listening Services" -obj $listeningServices
	$establishedConnections = Get-NetTCPConnection -State Established| Select State, LocalPort, LocalAddress, RemoteAddress, OwningProcess, CreationTime
	foreach ($srvc in $establishedConnections){ #get service name
		$srvc | Add-Member "Process Name" (Get-Process -Id $srvc.OwningProcess).ProcessName
		$srvc | Add-Member "Protocol" "TCP"
	}
	printSubHeader -name "Established Connections" -obj $listeningServices
	$dnsCache = Get-DnsClientCache
	printSubHeader -name "DNS Cache" -obj $dnsCache

	##################################################################
	##################### NWShares, printers, wifi ###################
	##################################################################
	$nwshares = get-smbshare
	$printers = Get-Printer
	$wifi = netsh wlan show profiles 
	printSubHeader -name "Network Shares" -obj $nwshares
	printSubHeader -name "Printers" -obj $printers
	printSubHeader -name "Wifi" -obj $wifi

	##################################################################
	##################### Installed Software #########################
	##################################################################
	Write-Host "Getting installed products, this may take a while..."
	$installedSoftware = Get-WmiObject -class win32_product | select Name
	printObj -name "Installed Products" -obj $installedSoftware

	##################################################################
	##################### Get process list  ##########################
	##################################################################
	$procs = Get-WmiObject win32_process | Select Name, ProcessId, ParentProcessId, ExecutablePath
	foreach($proc in $procs) {
		$proc | Add-Member "Owner" ($proc).GetOwner().User
	}
	printObj -name "Processes" -obj $procs

	##################################################################
	##################### Get drivers list  ##########################
	##################################################################
	$drivers = Get-WmiObject Win32_PnPSignedDriver | Select DriverName, StartMode, Path, DriverVersion, InstallDate, DriverProviderName
	printObj -name "Drivers" $drivers

	##################################################################
	##################### Get Documents/Downloaded Files of all users #################
	##################################################################
	#we just have to iterate over all users
	$locals = Get-ChildItem -Path "C:\Users" | Select Name
	$files = @()
	foreach ($user in $locals){
		try {
			$path = ("C:\Users\" + $user.Name)
			$downloads = Get-ChildItem -Path ($path + "\Downloads") | Select Name
			$documents = Get-ChildItem -Path ($path + "\Documents") | Select Name
			#make a few pretty objects to display
			foreach ($download in $downloads) {
				$file = New-Object PSObject
				$file | Add-Member FileName $download.Name
				$file | Add-Member Owner $user.Name
				$file | Add-Member Folder ($path + "\Downloads")
				$files += $file
			}
			foreach ($document in $documents) {
				$file = New-Object PSObject
				$file | Add-Member FileName $document.Name
				$file | Add-Member Owner $user.Name
				$file | Add-Member Folder ($path + "\Documents")
				$files += $file
			}
		} catch {
			Write-Host ("permission denied to " + $user)
		}
	}
	printObj -name "Documents/Downloads of all Users" -obj $files
	##
	## The stackpole list of forensics has been completed, now we get our 3 custom ones
	## 1) Application event log, 2) security event log, 3) bios info
	##
	$applicationLog = Get-EventLog Application -After (Get-Date).AddHours(-1)
	$securityLog = Get-EventLog Application -After (Get-Date).AddHours(-1)
	$bios = Get-WmiObject -Class Win32_BIOS
	printObj -name "Application Log" -obj $applicationLog
	printObj -name "Security Log" -obj $securityLog
	printObj -name "Bios Info" -obj $bios
	
	if ($Email -ne $false) {
		Write-Host "Attempting to send email ..."
		$emailList = $emailList | ? { $_ } | sort -uniq #remove duplicates
		Add-Type -Assembly System.IO.Compression.FileSystem
		$compressionLevel = [System.IO.Compression.CompressionLevel]::Optimal
		[System.IO.Compression.ZipFile]::CreateFromDirectory($PSScriptRoot, "dfir.zip", $compressionLevel, $false)
		Send-MailMessage -Credential $EmailCredential -From (($EmailCredential.UserName) + '@gmail.com') -To $EmailTarget -Subject "CSVS for DFIR" -Attachments 'dfir.zip' -SmtpServer "smtp.gmail.com" -Port 587 -UseSsl $true
	}
}

if ($Remotes -ne "null") {
	foreach ($remote in $Remotes -split ",") {
		$credentials = Get-Credential -Message $remote
		$session = New-PSSession -ComputerName $remote -credential $credentials
		Invoke-Command -Session $session -Scriptblock ${function:aggregateData}
		Remove-PSSession $session
	}
} else {
	aggregateData
}