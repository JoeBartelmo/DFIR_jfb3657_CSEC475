#DFIR - LAB 1

To Run against local machine: `powershell ./data-aggregator.ps1`

To Run against target machine: `powershell ./data-aggregator.ps1 -Remotes targetMachine`

To Run and report email: `powershell ./data-aggregator.ps1 -Email -EmailTarget location@gmail.com`

_[only configured to work with gmail, rest are untested]_


All CSVS are saved locally to the powershell script, a zip file is made which is then emailed of all csv files
