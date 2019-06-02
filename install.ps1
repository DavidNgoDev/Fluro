##############################################################
# Fluro Install Script                                       #
##############################################################
# Windows 10 Custom Installation Script, Using Powershell    #
##############################################################
# Instructions #
#############################################  
# 1) Run PowerShell as administrator        #
# 2) Type Set-ExecutionPolicy Unrestricted  # 
# 3) Run Fluro by typing ./install.ps1      #
#############################################

# Fireeye boxstarter Script

param (
  [string]$password = "",
  [bool]$nochecks = $false
)
function installBoxStarter()
{
  <#
  .SYNOPSIS
  Install BoxStarter on the current system  
  .DESCRIPTION
  Install BoxStarter on the current system. Returns $true or $false to indicate success or failure. On
  fresh windows 7 systems, some root certificates are not installed and updated properly. Therefore,
  this funciton also temporarily trust all certificates before installing BoxStarter.  
  #>  
  # https://stackoverflow.com/questions/11696944/powershell-v3-invoke-webrequest-https-error
  # Allows current PowerShell session to trust all certificates
  # Also a good find: https://www.briantist.com/errors/could-not-establish-trust-relationship-for-the-ssltls-secure-channel/
  try {
  Add-Type @"
  using System.Net;
  using System.Security.Cryptography.X509Certificates;
  public class TrustAllCertsPolicy : ICertificatePolicy {
  	public bool CheckValidationResult(
  		ServicePoint srvPoint, X509Certificate certificate,
  		WebRequest request, int certificateProblem) {
  		return true;
  	}
  }
"@
  } catch {
    Write-Debug "Failed to add new type"
  }  
  try {
  	$AllProtocols = [System.Net.SecurityProtocolType]'Ssl3,Tls,Tls11,Tls12'
  } catch {
  	Write-Debug "Failed to find SSL type...1"
  }  
  try {
  	$AllProtocols = [System.Net.SecurityProtocolType]'Ssl3,Tls'
  } catch {
  	Write-Debug "Failed to find SSL type...2"
  }  
  $prevSecProtocol = [System.Net.ServicePointManager]::SecurityProtocol
  $prevCertPolicy = [System.Net.ServicePointManager]::CertificatePolicy  
  Write-Host "[ * ] Installing Boxstarter"
  # Become overly trusting
  [System.Net.ServicePointManager]::SecurityProtocol = $AllProtocols
  [System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy  
  # download and instal boxstarter
  iex ((New-Object System.Net.WebClient).DownloadString('https://boxstarter.org/bootstrapper.ps1')); get-boxstarter -Force  
  # Restore previous trust settings for this PowerShell session
  # Note: SSL certs trusted from installing BoxStarter above will be trusted for the remaining PS session
  [System.Net.ServicePointManager]::SecurityProtocol = $prevSecProtocol
  [System.Net.ServicePointManager]::CertificatePolicy = $prevCertPolicy
  return $true
}

# Check to make sure script is run as administrator
Write-Host "[+] Checking if script is running as administrator.."
$currentPrincipal = New-Object Security.Principal.WindowsPrincipal( [Security.Principal.WindowsIdentity]::GetCurrent() )
if (-Not $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
  Write-Host "`t[ERR] Please run this script as administrator`n" -ForegroundColor Red
  Read-Host  "Press any key to continue"
  exit
}
else {
  Start-Sleep -Milliseconds 500
  Write-Host "`tphenomenal " -ForegroundColor Magenta -NoNewLine
  Start-Sleep -Milliseconds 500
  Write-Host "cosmic " -ForegroundColor Cyan -NoNewLine
  Start-Sleep -Milliseconds 500
  Write-Host "powers " -ForegroundColor Green
  Start-Sleep -Milliseconds 500
}

if ($nochecks -eq $false) {
  
  # Check to make sure host is supported
  Write-Host "[+] Checking to make sure Operating System is compatible"
  if (-Not (((Get-WmiObject -class Win32_OperatingSystem).Version -eq "6.1.7601") -or ([System.Environment]::OSVersion.Version.Major -eq 10))){
    Write-Host "`t[ERR] $((Get-WmiObject -class Win32_OperatingSystem).Caption) is not supported, please use Windows 7 Service Pack 1 or Windows 10" -ForegroundColor Red
    exit 
  }
  else
  {
    Write-Host "`t$((Get-WmiObject -class Win32_OperatingSystem).Caption) supported" -ForegroundColor Green
  }

  # Check to make sure host has been updated
  Write-Host "[+] Checking if host has been configured with updates"
  if (-Not (get-hotfix | where { (Get-Date($_.InstalledOn)) -gt (get-date).adddays(-30) })) {
    Write-Host "`t[ERR] This machine has not been updated in the last 30 days, please run Windows Updates to continue`n" -ForegroundColor Red
    Read-Host  "Press any key to continue"
    exit
  }
  else
  {
	  Write-Host "`tupdates appear to be in order" -ForegroundColor Green
  }

  #Check to make sure host has enough disk space
  Write-Host "[+] Checking if host has enough disk space"
  $disk = Get-PSDrive C
  Start-Sleep -Seconds 1
  if (-Not (($disk.used + $disk.free)/1GB -gt 58.8)){
    Write-Host "`t[ERR] This install requires a minimum 60 GB hard drive, please increase hard drive space to continue`n" -ForegroundColor Red
    Read-Host "Press any key to continue"
    exit
  }
  else
  {
    Write-Host "`t> 60 GB hard drive. looks good" -ForegroundColor Green
}

# Get user credentials for autologin during reboots
Write-Host "[ * ] Getting user credentials ..."
Set-ItemProperty "HKLM:\SOFTWARE\Microsoft\PowerShell\1\ShellIds" -Name "ConsolePrompting" -Value $True

if ([string]::IsNullOrEmpty($password)) {
	$cred=Get-Credential $env:username
} else {
	$spasswd=ConvertTo-SecureString -String $password -AsPlainText -Force
	$cred=New-Object -TypeName "System.Management.Automation.PSCredential" -ArgumentList $env:username, $spasswd
}
# TO DO - Verify credentials before continuing

# Install Boxstarter
Write-Host "[ * ] Installing Boxstarter"
try {
  iex ((New-Object System.Net.WebClient).DownloadString('https://boxstarter.org/bootstrapper.ps1')); get-boxstarter -Force
} catch {
  $rc = installBoxStarter
  if (-Not $rc) {
  	Write-Host "[ERR] Failed to install BoxStarter"
  	Read-Host  "      Press ANY key to continue..."
  	exit
  }
}

# Boxstarter options
$Boxstarter.RebootOk = $true    # Allow reboots?
$Boxstarter.NoPassword = $false # Is this a machine with no login password?
$Boxstarter.AutoLogin = $true # Save my password securely and auto-login after a reboot
}

#---- TEMPORARY ---
Disable-UAC


#--- Windows Desktop Experience Settings  ---

Disable-GameBarTips

Set-WindowsExplorerOptions -EnableShowHiddenFilesFoldersDrives -EnableShowProtectedOSFiles -EnableShowFileExtensions -EnableShowFullPathInTitleBar

# Privacy: Let apps use my advertising ID: Disable
If (-Not (Test-Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo")) {
    New-Item -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo | Out-Null
}
Set-ItemProperty -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo -Name Enabled -Type DWord -Value 0

# WiFi Sense: HotSpot Sharing: Disable
If (-Not (Test-Path "HKLM:\Software\Microsoft\PolicyManager\default\WiFi\AllowWiFiHotSpotReporting")) {
    New-Item -Path HKLM:\Software\Microsoft\PolicyManager\default\WiFi\AllowWiFiHotSpotReporting | Out-Null
}
Set-ItemProperty -Path HKLM:\Software\Microsoft\PolicyManager\default\WiFi\AllowWiFiHotSpotReporting -Name value -Type DWord -Value 0

# WiFi Sense: Shared HotSpot Auto-Connect: Disable
Set-ItemProperty -Path HKLM:\Software\Microsoft\PolicyManager\default\WiFi\AllowAutoConnectToWiFiSenseHotspots -Name value -Type DWord -Value 0

# Start Menu: Disable Bing Search Results
Set-ItemProperty -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Search -Name BingSearchEnabled -Type DWord -Value 0
# To Restore (Enabled):
# Set-ItemProperty -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Search -Name BingSearchEnabled -Type DWord -Value 1

# Disable Telemetry (requires a reboot to take effect)
# Note this may break Insider builds for your organization
# Set-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection -Name AllowTelemetry -Type DWord -Value 0
# Get-Service DiagTrack,Dmwappushservice | Stop-Service | Set-Service -StartupType Disabled

# Change Explorer home screen back to "This PC"
Set-ItemProperty -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced -Name LaunchTo -Type DWord -Value 1
# Change it back to "Quick Access" (Windows 10 default)
# Set-ItemProperty -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced -Name LaunchTo -Type DWord -Value 2

# Better File Explorer
Set-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced -Name NavPaneExpandToCurrentFolder -Value 1		
Set-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced -Name NavPaneShowAllFolders -Value 1		
Set-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced -Name MMTaskbarMode -Value 2

# Disable Xbox Gamebar
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\GameDVR" -Name AppCaptureEnabled -Type DWord -Value 0
Set-ItemProperty -Path "HKCU:\System\GameConfigStore" -Name GameDVR_Enabled -Type DWord -Value 0

# Turn off People in Taskbar
If (-Not (Test-Path "HKCU:SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\People")) {
    New-Item -Path HKCU:SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\People | Out-Null
}
Set-ItemProperty -Path "HKCU:SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\People" -Name PeopleBand -Type DWord -Value 0

#--- Windows Features ---
choco install Microsoft-Hyper-V-All -source windowsFeatures
choco install Containers -source windowsFeatures
choco install Microsoft-Windows-Subsystem-Linux -source windowsfeatures

#--- Tools ---
choco install nuget.commandline --pre
choco install docker-for-windows -y
Install-Module -Name posh-docker -Force
choco install powershell-core -y
choco install git -params '"/GitAndUnixToolsOnPath /WindowsTerminal"' -y
choco install hyper -y
choco install mRemoteNG -y

#--- Removing Shit ---

# Feedback Hub
Get-AppxPackage Microsoft.WindowsFeedbackHub | Remove-AppxPackage
 
# Get Started
Get-AppxPackage Microsoft.Getstarted | Remove-AppxPackage

# Messaging
Get-AppxPackage Microsoft.Messaging | Remove-AppxPackage

## Candy Crush
Get-AppxPackage king.com.CandyCrush* | Remove-AppxPackage

# Install Custom Software
Write-Host "[ * ] Installing Software"
choco install adobereader -y
choco install googlechrome -y
choco install jre8 -y
choco install firefox -y
choco install notepadplusplus.install -y
choco install 7zip.install -y
choco install vlc -y
choco install winrar -y
choco install git.install -y
choco install putty.install -y
choco install javaruntime -y
choco install skype -y
choco install ccleaner -y
choco install filezilla -y
choco install malwarebytes -y
choco install atom -y
choco install gimp -y
choco install itunes -y
choco install winscp.install -y
choco install dropbox -y
choco install virtualbox -y
choco install wireshark -y
choco install sublimetext3 -y
choco install audacity -y
choco install spotify -y
choco install steam -y
choco install googledrive -y
choco install dolphin -y
choco install mysql.workbench -y
choco install qbittorrent -y
choco install brackets -y
choco install rufus -y
choco install poweriso -y
choco install cpu-z.install -y
choco install nmap -y
choco install greenshot -y
choco install androidstudio -y
choco install adwcleaner -y
choco install arduino -y
choco install yumi -y
choco install handbrake -y
choco install discord -y
choco install kodi -y
choco install f.lux.install -y
choco install obs-studio -y
choco install gitkraken -y
choco install visualstudiocode -y
choco install git -y
choco install nodejs -y
choco install hyper -y
choco install vmwareworkstation -y
choco install windirstat -y
choco install visualstudio2019professional -y
choco install resharper-platform -y
choco install resharper -y
choco install dotpeek -y
choco install intellijidea-ultimate -y
choco install dotcover -y
choco install dottrace -y
choco install webstorm -y
choco install phpstorm -y
choco install datagrip -y
choco install dotmemory -y
choco install jetbrainstoolbox -y
choco install teamcityaddin -y
choco install goland -y
choco install pycharm -y
choco install rubymine -y
choco install goland -y
choco install adobe-creative-cloud -y
choco install office365business -y
choco install win32diskimager.install -y

# AUS Time Settings Change Here For Your Location
Set-TimeZone -Name "AUS Eastern Standard Time"

# Pinning Things
Install-ChocolateyPinnedTaskBarItem "$env:programfiles\Google\Chrome\Application\chrome.exe"

function PinToTaskbar {
  # https://stackoverflow.com/questions/31720595/pin-program-to-taskbar-using-ps-in-windows-10
  param (
    [parameter(Mandatory=$True, HelpMessage="Target item to pin")]
    [ValidateNotNullOrEmpty()]
    [string] $Target
  )
  if (-Not (Test-Path $Target)) {
    Write-Warning "$Target does not exist"
    throw [System.IO.FileNotFoundException] "$Target does not exist"
  }

  $KeyPath1  = "HKCU:\SOFTWARE\Classes"
  $KeyPath2  = "*"
  $KeyPath3  = "shell"
  $KeyPath4  = "{:}"
  $ValueName = "ExplorerCommandHandler"
  $ValueData =
  (Get-ItemProperty `
        ("HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\" + `
            "CommandStore\shell\Windows.taskbarpin")
  ).ExplorerCommandHandler

  $Key2 = (Get-Item $KeyPath1).OpenSubKey($KeyPath2, $true)
  $Key3 = $Key2.CreateSubKey($KeyPath3, $true)
  $Key4 = $Key3.CreateSubKey($KeyPath4, $true)
  $Key4.SetValue($ValueName, $ValueData)

  $Shell = New-Object -ComObject "Shell.Application"
  $Folder = $Shell.Namespace((Get-Item $Target).DirectoryName)
  $Item = $Folder.ParseName((Get-Item $Target).Name)
  $Item.InvokeVerb("{:}")

  $Key3.DeleteSubKey($KeyPath4)
  if ($Key3.SubKeyCount -eq 0 -and $Key3.ValueCount -eq 0) {
    $Key2.DeleteSubKey($KeyPath3)
  }
}

#### Pin Items to Taskbar ####
Write-Host "[-] Pinning items to Taskbar" -ForegroundColor Green
# Explorer
$target_file = Join-Path ${Env:WinDir} "explorer.exe"
try {
  PinToTaskbar $target_file
} catch {
  Write-Host "Could not pin $target_file to the tasbar"
}
# CMD prompt
$target_file = Join-Path ${Env:WinDir} "system32\cmd.exe"
$target_dir = ${Env:UserProfile}
$target_args = '/K "cd ' + ${Env:UserProfile} + '"'
$shortcut = Join-Path ${Env:UserProfile} "temp\CMD.lnk"
Install-ChocolateyShortcut -shortcutFilePath $shortcut -targetPath $target_file -Arguments $target_args -WorkingDirectory $target_dir -PinToTaskbar -RunasAdmin
try {
  PinToTaskbar $shortcut
} catch {
  Write-Host "Could not pin $target_file to the tasbar"
}
# Powershell
$target_file = Join-Path (Join-Path ${Env:WinDir} "system32\WindowsPowerShell\v1.0") "powershell.exe"
$target_dir = ${Env:UserProfile}
$target_args = '-NoExit -Command "cd ' + "${Env:UserProfile}" + '"'
$shortcut = Join-Path ${Env:UserProfile} "temp\PowerShell.lnk"
Install-ChocolateyShortcut -shortcutFilePath $shortcut -targetPath $target_file -Arguments $target_args -WorkingDirectory $target_dir -PinToTaskbar -RunasAdmin
try {
  PinToTaskbar $shortcut
} catch {
  Write-Host "Could not pin $target_file to the tasbar"
}

#--- Restore Temporary Settings ---
Enable-UAC
Enable-MicrosoftUpdate
Install-WindowsUpdate -acceptEula

#--- Rename the Computer ---
# Requires restart, or add the -Restart flag
$computername = "Fluro-Build"
if ($env:computername -ne $computername) {
Rename-Computer -NewName $computername -Restart
if (Test-PendingReboot) { Invoke-Reboot }
}
