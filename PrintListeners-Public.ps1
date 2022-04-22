#Function to check IP against Virus total API
function Check-VT {
[CmdletBinding()]
    param (
    [Parameter(Mandatory,Position=0)]
    [string]$singleRIP
    )
##Scan Vtotal for URL
$POSTParams = @{
    apikey = "#ENTER API KEY HERE"
    url = $singleRIP
    }

$result1 = Invoke-WebRequest -Method POST -Uri "https://www.virustotal.com/vtapi/v2/url/scan" -Body $POSTParams
$rawJSON1 = $result1.Content | ConvertFrom-Json
$resultID = $rawJSON1.scan_id

##Sleep for 17 sec for virus total to scan URL
Start-Sleep 17

##Get Result from Vtotal
$POSTParams2 = @{
    apikey = "#ENTER API KEY HERE"
    resource = "$resultID"
    }
$contentResult = Invoke-WebRequest -Method GET -Uri "https://www.virustotal.com/vtapi/v2/url/report" -Body $POSTParams2 
$rawJSON = $contentResult.Content
$objData = $rawJSON | ConvertFrom-Json
$objData
}

#Function to show notification on desktop at toast
function Show-Notification {
    [cmdletbinding()]
    Param (
        [string]
        $ToastTitle,
        [string]
        [parameter(ValueFromPipeline)]
        $ToastText
    )

    [Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications, ContentType = WindowsRuntime] > $null
    $Template = [Windows.UI.Notifications.ToastNotificationManager]::GetTemplateContent([Windows.UI.Notifications.ToastTemplateType]::ToastText02)

    $RawXml = [xml] $Template.GetXml()
    ($RawXml.toast.visual.binding.text|where {$_.id -eq "1"}).AppendChild($RawXml.CreateTextNode($ToastTitle)) > $null
    ($RawXml.toast.visual.binding.text|where {$_.id -eq "2"}).AppendChild($RawXml.CreateTextNode($ToastText)) > $null

    $SerializedXml = New-Object Windows.Data.Xml.Dom.XmlDocument
    $SerializedXml.LoadXml($RawXml.OuterXml)

    $Toast = [Windows.UI.Notifications.ToastNotification]::new($SerializedXml)
    $Toast.Tag = "PowerShell"
    $Toast.Group = "PowerShell"
    $Toast.ExpirationTime = [DateTimeOffset]::Now.AddMinutes(1)

    $Notifier = [Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier("PowerShell")
    $Notifier.Show($Toast);
}

#Set date
$timeDate = Get-Date
#Check for TCP listeners on host machine
$listeners = Get-NetTCPConnection -State Listen,Established | Where-Object RemoteAddress -CMatch "\b(([01]?\d?\d|2[0-4]\d|25[0-5])\.){3}([01]?\d?\d|2[0-4]\d|25[0-5])\b"
#Set variable for exclusions
$excluded = @("127.0.0.1", "0.0.0.0")
#Filter out exclusions
$listeners = $listeners | Where-Object RemoteAddress -NotIn $excluded
#Create array containing all remote IP's listeners are connected to
[array]$rIP = $listeners | Select-Object RemoteAddress
#Output remote IP's to csv file
$listeners | Out-File -FilePath E:\feeder\listeners.csv -Append
#Get currently running processes on machine
$processes = Get-Process | Where-Object {$_.Id -in $listeners.OwningProcess}
#Output to csv file
$processes | Out-File -FilePath E:\feeder\listeners.csv -Append
#Output datetime to csv file
$timeDate | Out-File -FilePath E:\feeder\listeners.csv -Append
#loop to call Virus total functions
$i = 0
for ($i=0; $i -lt $rIP.Count; $i++)
{
[string]$singleRIP = $rIP | Select-Object -Skip $i -First 1 #Takes first item in array then skips 1 more each iteration
#cleanup IP
$singleRIP = $singleRIP.TrimStart('{@{RemoteAddress=') 
$singleRIP = $singleRIP.TrimEnd('}}')
#$singleRIP
Check-VT($singleRIP) | Out-File -FilePath E:\feeder\listeners.csv -Append #call function and pass single remote IP variable
Start-Sleep 20 #sleep required for free API of virus total
 }
Show-Notification('V-Total Scans completed') #show toats completion