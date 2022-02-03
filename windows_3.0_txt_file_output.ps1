<# For Getting Information on system's:

	Hostname
	Username
	Current Date and Time
	IP Address
	DNS Setting of system (Should fetch the DNS Server IP Configured on the system)
	NTP Settings of system (Should fetch the NTP Server IP/Domain configured on the system)
	MAC Address
	List of Users and Groups
	Address Resolution Protocol
	Netstat Information
	Type of Machine (Physical or VM)
	List of running services and the ports on which they are listening
	OS Name and version 
	List of running Processes
	List of Scheduled Tasks
	OS Patching details
	Antivirus name and version
	Webserver name and version (ex: iis 8.0 or apache tomcat 3.2...etc)
	CMS Platform name and version (ex: Drupal 7.6)
	Application Frameworks name and version (ex: struts 1.3)
	List of installed softwares, applications, plugins and their version
	
	Created by Prashant Sharma
#>

#To bypass execution policy
#powershell -ep bypass

#Hostname
$htname=$env:COMPUTERNAME
Write-Output "Hostname is:	" >a.txt		
$htname >>a.txt

Write-Output "" >>a.txt

#User
Write-Output "Current User:	" >>a.txt
$env:username >>a.txt

Write-Output "" >>a.txt

Write-Output "Current System Time: " + (get-date)

Write-Output "" >>a.txt

#Get IP address:
Write-Output "IP address is:	" >>a.txt
(Get-WmiObject -Class Win32_NetworkAdapterConfiguration | where {$_.DefaultIPGateway -ne $null}).IPAddress | select-object -first 1 >>a.txt

Write-Output "" >>a.txt

#Get Public IP address:
Write-Output "Public IP address is:	"  >>a.txt
Invoke-RestMethod http://ipinfo.io/json | Select -exp ip >>a.txt

Write-Output "" >>a.txt

#Get DNS server ip address
Write-Output "DNS server IP Address is:	" >>a.txt
Get-DnsClientServerAddress >>a.txt
# For Ethernet (DNS Servers)
#Get-DnsClientServerAddress -InterfaceAlias "Ethernet"

Write-Output "" >>a.txt

#Get Users and Groups:
Write-Output "Users`r`n  "	 >>a.txt
Write-Output "-----------------------------------------------------------`r`n  "	 >>a.txt
$adsi = [ADSI]"WinNT://$env:COMPUTERNAME"
    $adsi.Children | where {$_.SchemaClassName -eq 'user'} | Foreach-Object {
        $groups = $_.Groups() | Foreach-Object {$_.GetType().InvokeMember("Name", 'GetProperty', $null, $_, $null)}
        $output1 = $output1 +  "----------`r`n"
        $output1 = $output1 +  "Username: " + $_.Name +  "`r`n"
        $output1 = $output1 +  "Groups:   "  + $groups +  "`r`n"
    }
Write-Output "$output1" >>a.txt

Write-Output "" >>a.txt

#Get NTP server ip/domain address
# w32tm /query /computer:$Server /source
Write-Output "Details of NTP server:	" >>a.txt
function Get-TimeServer {

	[CmdletBinding(SupportsShouldProcess=$true)]
	param ( 
		$ComputerName=$env:COMPUTERNAME
	)
	begin {
		$HKLM = 2147483650
	}
	process {
		foreach ($Computer in $ComputerName) {
			$TestConnection = Test-Connection -ComputerName $Computer -Quiet -Count 1
			$Output = New-Object -TypeName psobject
			$Output | Add-Member -MemberType 'NoteProperty' -Name 'ComputerName' -Value $Computer
            $Output | Add-Member -MemberType 'NoteProperty' -Name 'TimeServer' -Value "WMI Error"
			$Output | Add-Member -MemberType 'NoteProperty' -Name 'Type' -Value "WMI Error"
			if ($TestConnection) {				
				try {
                    $reg = [wmiclass]"\\$Computer\root\default:StdRegprov"
				    $key = "SYSTEM\CurrentControlSet\Services\W32Time\Parameters"
				    $servervalue = "NtpServer"
				    $server = $reg.GetStringValue($HKLM, $key, $servervalue)
				    $ServerVar = $server.sValue -split ","
				    $Output.TimeServer = $ServerVar[0]
    				$typevalue = "Type"
                    $type = $reg.GetStringValue($HKLM, $key, $typevalue)
                    $Output.Type = $Type.sValue				
				    $Output
                } catch {
                }
			} else {
			}
		}
	}
}
Get-TimeServer >>a.txt

Write-Output "" >>a.txt

#Get MAC address with respective IP address
Write-Output "MAC address is:	" >>a.txt
Get-WmiObject win32_networkadapterconfiguration | Select-Object -Property @{name='IPAddress';Expression={($_.IPAddress[0])}},MacAddress | Where IPAddress -NE $null >>a.txt

Write-Output "" >>a.txt

Write-Output "Arp`r`n	" >>a.txt
Write-Output "-----------------------------------------------------------" >>a.txt
arp -a | out-string >>a.txt
Write-Output "" >>a.txt

Write-Output "NetStat`r`n	" >>a.txt
Write-Output "-----------------------------------------------------------" >>a.txt
netstat -ano | out-string >>a.txt
Write-Output "" >>a.txt

Write-Output "-----------------------------------------------------------"
Write-Output "Gathering Info, please wait! `r`n	 " 
Write-Output "-----------------------------------------------------------"

Write-Output "Hosts File Content`r`n	" >>a.txt
Write-Output "-----------------------------------------------------------" >>a.txt
get-content $env:windir\System32\drivers\etc\hosts | out-string >> a.txt
Write-Output "" >>a.txt
 
Write-Output "Current System Time: " + (get-date) >>a.txt
Write-Output "Gathering Processes, Services and Scheduled Tasks	" >>a.txt
Write-Output "-----------------------------------------------------------" >>a.txt
Write-Output "Processes`r`n" >>a.txt
Write-Output "-----------------------------------------------------------" >>a.txt
Get-WmiObject win32_process | Select-Object Name,ProcessID,@{n='Owner';e={$_.GetOwner().User}},CommandLine | sort name | format-table -wrap -autosize | out-string >> a.txt
Write-Output "" >>a.txt

Write-Output "Services`r`n" >>a.txt
Write-Output "-----------------------------------------------------------" >>a.txt
get-service | Select Name,DisplayName,Status | sort status | Format-Table -Property * -AutoSize | Out-String -Width 4096 >>a.txt
Write-Output "" >>a.txt


#Running Services with port:
Write-Output "List of running processes with port number:	" >>a.txt
get-nettcpconnection | select local*,remote*,state,@{Name="Process";Expression={(Get-Process -Id $_.OwningProcess).ProcessName}} >>a.txt

Write-Output "" >>a.txt

#Type of Machine:
Write-Output "Type of Machine is:	" >>a.txt
Function Get-MachineType
{
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    Param
    (
        # ComputerName
        [Parameter(Mandatory=$false,
                   ValueFromPipeline=$true,
                   ValueFromPipelineByPropertyName=$true,
                   Position=0)]
        [string[]]$ComputerName=$env:COMPUTERNAME,
        $Credential = [System.Management.Automation.PSCredential]::Empty
    )

    Begin
    {
    }
    Process
    {
        foreach ($Computer in $ComputerName) {
            Write-Verbose "Checking $Computer"
            try {
                # Check to see if $Computer resolves DNS lookup successfuly.
                $null = [System.Net.DNS]::GetHostEntry($Computer)
                
                $ComputerSystemInfo = Get-WmiObject -Class Win32_ComputerSystem -ComputerName $Computer -ErrorAction Stop -Credential $Credential
                
                switch ($ComputerSystemInfo.Model) {
                    
                    # Check for Hyper-V Machine Type
                    "Virtual Machine" {
                        $MachineType="VM"
                        }

                    # Check for VMware Machine Type
                    "VMware Virtual Platform" {
                        $MachineType="VM"
                        }

                    # Check for Oracle VM Machine Type
                    "VirtualBox" {
                        $MachineType="VM"
                        }

                    # Check for Xen
                    "HVM domU" {
                        $MachineType="VM"
                        }
              
                    # Otherwise it is a physical Box
                    default {
                        $MachineType="Physical"
                        }
                    }
                
                # Building MachineTypeInfo Object
                $MachineTypeInfo = New-Object -TypeName PSObject -Property ([ordered]@{
                    ComputerName=$ComputerSystemInfo.PSComputername
                    Type=$MachineType
                    Manufacturer=$ComputerSystemInfo.Manufacturer
                    Model=$ComputerSystemInfo.Model
                    })
                $MachineTypeInfo
                }
            catch [Exception] {
                Write-Output "$Computer`: $($_.Exception.Message)"
                }
            }
    }
    End
    {

    }
}
Get-MachineType >>a.txt

Write-Output "" >>a.txt

#OS name and Version
Write-Output "OS name and Version is:		" >>a.txt
Get-CimInstance Win32_OperatingSystem | Select-Object  Caption, InstallDate, version, OSArchitecture, BuildNumber, CSName | FL  >>a.txt

Write-Output "" >>a.txt

#List of installed updates
Write-Output "List of installed updates are:	"	>>a.txt
wmic qfe list	>>a.txt

Write-Output "" >>a.txt

#Get AntiVirus Version
Write-Output "Get AntiVirus Name and Version:		"	>>a.txt
 function Get-AntiVirusProduct {
    [CmdletBinding()]
    param (
    [parameter(ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
    [Alias('name')]
    $computername=$env:computername


    )

    #$AntivirusProducts = Get-WmiObject -Namespace "root\SecurityCenter2" -Query $wmiQuery  @psboundparameters # -ErrorVariable myError -ErrorAction 'SilentlyContinue' # did not work            
     $AntiVirusProducts = Get-WmiObject -Namespace "root\SecurityCenter2" -Class AntiVirusProduct  -ComputerName $computername

    $ret = @()
    foreach($AntiVirusProduct in $AntiVirusProducts){
        #Switch to determine the status of antivirus definitions and real-time protection.
        #The values in this switch-statement are retrieved from microsoft blogs (pre-defined ProductState values)
        switch ($AntiVirusProduct.productState) {
        "262144" {$defstatus = "Up to date" ;$rtstatus = "Disabled"}
            "262160" {$defstatus = "Out of date" ;$rtstatus = "Disabled"}
            "266240" {$defstatus = "Up to date" ;$rtstatus = "Enabled"}
            "266256" {$defstatus = "Out of date" ;$rtstatus = "Enabled"}
            "393216" {$defstatus = "Up to date" ;$rtstatus = "Disabled"}
            "393232" {$defstatus = "Out of date" ;$rtstatus = "Disabled"}
            "393488" {$defstatus = "Out of date" ;$rtstatus = "Disabled"}
            "397312" {$defstatus = "Up to date" ;$rtstatus = "Enabled"}
            "397328" {$defstatus = "Out of date" ;$rtstatus = "Enabled"}
            "397584" {$defstatus = "Out of date" ;$rtstatus = "Enabled"}
        default {$defstatus = "Unknown" ;$rtstatus = "Unknown"}
            }

        #Create hash-table for each computer
        $ht = @{}
        $ht.Computername = $computername
        $ht.Name = $AntiVirusProduct.displayName
        $ht.'Product GUID' = $AntiVirusProduct.instanceGuid
        $ht.'Product Executable' = $AntiVirusProduct.pathToSignedProductExe
        $ht.'Reporting Exe' = $AntiVirusProduct.pathToSignedReportingExe
 #       $ht.'Definition Status' = $defstatus
 #       $ht.'Real-time Protection Status' = $rtstatus


        #Create a new object for each computer
        $ret += New-Object -TypeName PSObject -Property $ht 
    }
    Return $ret
} 
Get-AntiVirusProduct	>>a.txt

Write-Output "" >>a.txt

##############################################################	
#List of installed Softwares
Write-Output "Gathering list of Installed Software/applications: `r`n	"	>>a.txt
Write-Output "-----------------------------------------------------------" >>a.txt
Write-Output "Installed Programs`r`n	"	>>a.txt
Write-Output "-----------------------------------------------------------" >>a.txt
get-wmiobject -Class win32_product | select Name, Version, Caption | ft -hidetableheaders -autosize| out-string -Width 4096 >>a.txt
Write-Output "" >>a.txt

Write-Output "Program Folders`r`n	"	>>a.txt
Write-Output "-----------------------------------------------------------" >>a.txt
Write-Output "`n`rC:\Program Files`r`n	"	>>a.txt
Write-Output "-------------" >>a.txt
get-childitem "C:\Program Files"  -EA SilentlyContinue  | select Name  | ft -hidetableheaders -autosize| out-string >>a.txt
Write-Output "" >>a.txt
Write-Output "C:\Program Files (x86)`r`n"	>>a.txt
Write-Output "-------------" >>a.txt
get-childitem "C:\Program Files (x86)"  -EA SilentlyContinue  | select Name  | ft -hidetableheaders -autosize| out-string >>a.txt
Write-Output "" >>a.txt



Get-ItemProperty HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* | Select-Object DisplayName, DisplayVersion, Publisher, InstallDate | Format-Table -AutoSize	>>a.txt
Write-Output "List of installed softwares/applications:		"	>>a.txt
Get-ItemProperty HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\* | Select-Object DisplayName, DisplayVersion, Publisher, InstallDate | Format-Table -AutoSize	>>a.txt

Write-Output "" >>a.txt

#Get Web server information:
try
{
	if ((Get-WindowsOptionalFeature -Online -FeatureName "IIS-WebServerRole").State -eq "Enabled")
	{
    Write-Output "IIS installed"	>>a.txt
	Write-Output "IIS version is:		" >>a.txt
	Function Get-IISVersion
	{
    $w3wpPath = $Env:WinDir + "\System32\inetsrv\w3wp.exe"
    If(Test-Path $w3wpPath) {
        $productProperty = Get-ItemProperty -Path $w3wpPath
        Write-Output $productProperty.VersionInfo.ProductVersion	>>a.txt
    }
    Else {
        Write-Output "Not find IIS."	>>a.txt
    }   
	}
	Get-IISVersion
	} 
	else
	{
	Write-Output "IIS not installed"	>>a.txt
	}
}
catch
{
	Write-Output "Getting running server information"	>>a.txt
}

Write-Output ""	>>a.txt
Start-Sleep -s 1

#Apache server version
Write-Output "Apache service status:"	>>a.txt
try
{
Get-Process -Name httpd -erroraction 'silentlycontinue'	>>a.txt
Write-Output ""	>>a.txt
Get-Service -Name Apache*	>>a.txt
C:\xampp\apache\bin\httpd.exe -v	>>a.txt
C:\Program` Files\Apache` Software` Foundation\*\bin\httpd.exe -v	>>a.txt
Get-Service -Name Apache*	>>a.txt
}
catch
{
Get-Service -Name Apache*	>>a.txt
Write-Output "Fetching server Information:		"	>>a.txt
}

Write-Output "";
Write-Output ""	>>a.txt

#Tomcat server status with version
Write-Output "Tomcat Status:"	>>a.txt
try{
	powershell -command Get-Service -Name Tomcat*	>>a.txt
}
catch{
	Write-Output "Tomcat not running..."	>>a.txt
}
#Get-Service | where-object {$_.name -like 'Tomcat?'}

Write-Output "Please check the output file!"
Write-Output ""
#Pause the script at the end
Start-Sleep -s 12