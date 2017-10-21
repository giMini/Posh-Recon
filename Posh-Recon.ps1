
# Prerequisite : Install Posh-Shodan
# iex (New-Object Net.WebClient).DownloadString("https://gist.githubusercontent.com/darkoperator/9378450/raw/7244d3db5c0234549a018faa41fc0a2af4f9592d/PoshShodanInstall.ps1")

function Get-ShodanInfoForRange
{
<# 
  .SYNOPSIS  
    Get the IP addresses in a range 
  .EXAMPLE 
   Get-ShodanInfoForRange -IP 151.25.25.161 -CIDR 32 
#> 
 
param 
( 
  [string]$IP, 
  [int]$CIDR 
) 
 
    function Read-OpenFileDialog([string]$InitialDirectory, [switch]$AllowMultiSelect) {      
        [System.Reflection.Assembly]::LoadWithPartialName("System.windows.forms") | Out-Null
        $openFileDialog = New-Object System.Windows.Forms.OpenFileDialog        
        $openFileDialog.ShowHelp = $True    # http://www.sapien.com/blog/2009/02/26/primalforms-file-dialog-hangs-on-windows-vista-sp1-with-net-30-35/
        $openFileDialog.initialDirectory = $initialDirectory
        $openFileDialog.filter = "csv files (*.csv)|*.csv|All files (*.*)| *.*"
        $openFileDialog.FilterIndex = 1
        $openFileDialog.ShowDialog() | Out-Null
        return $openFileDialog.filename
    }

    function Import-DataFromFile {	
        $fileOpen = Read-OpenFileDialog 
        if($fileOpen -ne '') {	
		    $colComputers = Import-Csv $fileOpen
        }
        $colComputers
    }

    function IP-toINT64 () { 
      param ($IP) 
 
      $octets = $IP.split(".") 
      return [int64]([int64]$octets[0]*16777216 +[int64]$octets[1]*65536 +[int64]$octets[2]*256 +[int64]$octets[3]) 
    } 
 
    function INT64-toIP() { 
      param ([int64]$int) 

      return (([math]::truncate($int/16777216)).tostring()+"."+([math]::truncate(($int%16777216)/65536)).tostring()+"."+([math]::truncate(($int%65536)/256)).tostring()+"."+([math]::truncate($int%256)).tostring() )
    } 
 
    if ($IP) {$IPAddress = [Net.IPAddress]::Parse($IP)} 
    if ($CIDR) {$maskAddress = [Net.IPAddress]::Parse((INT64-toIP -int ([convert]::ToInt64(("1"*$cidr+"0"*(32-$cidr)),2)))) } 
    if ($IP) {$networkAddress = new-object net.ipaddress ($maskAddress.address -band $IPAddress.address)} 
    if ($IP) {$broadcastAddress = new-object net.ipaddress (([system.net.ipaddress]::parse("255.255.255.255").address -bxor $maskAddress.address -bor $networkAddress.address))} 
 
    if ($IP) { 
      $startAddress = IP-toINT64 -ip $networkAddress.ipaddresstostring 
      $endAddress = IP-toINT64 -ip $broadcastAddress.ipaddresstostring 
    } 
 
    $objectToQuery = @()
    for ($i = $startAddress; $i -le $endAddress; $i++) { 
        $objectToQuery +=(INT64-toIP -int $i)
    }
    
    #$objectToQuery = Import-Csv C:\ipBBD.csv
    $SecurePassword = "Your_Password" | ConvertTo-SecureString -AsPlainText -Force

    Set-ShodanAPIKey -APIKey 'Your_API_KEY' -MasterPassword $SecurePassword -Verbose

    #$objectToQuery = Import-DataFromFile	
    $recordsCount = $objectToQuery.Count
    Write-Output "$recordsCount records found"
    foreach ($record in $objectToQuery){   
        #if(($($record.Type -eq "A"))) {                   
            $obj = Get-ShodanHostService -IPAddress $($record) -ErrorAction SilentlyContinue
            Write-Output $record
            if($obj){
                Write-Output "$record - $($obj.ports)"
            }
        #}
    }

}