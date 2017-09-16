<# 
.SYNOPSIS 

DFIR Lab 2 script to compile a csv from a data dump given by MFT

.DESCRIPTION

DFIR Lab 2 script to compile a csv from a data dump given by MFT
 
.OUTPUTS 
Console and CSV files locally

.PARAMETER path
	Required: CSV location of MFT dump
	Note that this is a fully qualified path, if you wish to reference a direcotry on desktop: "C:\users\billstackpole\desktop\csvfolder\mft.csv"
	If it is a local file simply "mft.csv"
	
.PARAMETER datadump
	Required: Location of the file where you would like to dump the $DATA stream
	
.PARAMETER d
	Optional: IF you have a unique delimiter, specify here, by default MFT does |, so that's setup here, otherwise specify directly
#> 

# grab parameters.
Param([string]$path, 
		[string]$d = "|", 
		[string]$datadump)

$csv = Import-Csv -Path $path -Delimiter $d

# print out stackpole's list: Filepath, file name, si times, fn times
$csv | Select -Property FilePath, FN_FileName, SI_CTime, SI_ATime, SI_MTime, SI_RTime, FN_CTime, FN_ATime, FN_MTime, FN_RTime | Format-Table -Auto
Write-Host "CSVINFO: "
Write-Host $csv

$csv = Import-Csv -Path $path -Delimiter $d
write-host("Below is timestomp test: ")
foreach ($obj in $csv) {
	# for timestopm test it's actually pretty easy, all we have to to is do a quick search for the mft date and time 
	if($_.type="File Accessed") {
		$filetime = $(get-item ($_.desc)).LastAccessTimeUTC
		Write-Host ($filetime) + " === " + (($_.date) + ($_.time))
	}
}

#get the file stream data associated with the file and just print the path with stream
$streams = Get-Item $path -stream * | select Stream
foreach ($stream in $streams) {
	Write-Host $path $stream.Stream
}