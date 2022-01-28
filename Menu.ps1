Start-Transcript C:\onsys\PrepOutput.txt

If (-NOT ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator))
    {Start-Process powershell.exe "-File",('"{0}"' -f $MyInvocation.MyCommand.Path) -Verb RunAs
    Exit} 
# Variables:
# Designated Chocolatey Dir
$global:ChocolateyInstall = 'C:\onsys\Prep\Choco\'
# Start Menu
$global:StartMenuXML = @"
<LayoutModIficationTemplate xmlns:defaultlayout="http://schemas.microsoft.com/Start/2014/FullDefaultLayout" xmlns:start="http://schemas.microsoft.com/Start/2014/StartLayout" Version="1" xmlns:taskbar="http://schemas.microsoft.com/Start/2014/TaskbarLayout" xmlns="http://schemas.microsoft.com/Start/2014/LayoutModIfication">
<LayoutOptions StartTileGroupCellWidth="6" /> <DefaultLayoutOverride> <StartLayoutCollection> <defaultlayout:StartLayout GroupCellWidth="6" /> 
</StartLayoutCollection> </DefaultLayoutOverride> </LayoutModIficationTemplate>
"@
# Default Apps
$global:DefaultAppsXML = @"
<?xml version="1.0" encoding="UTF-8"?> <DefaultAssociations>
  <Association Identifier=".3mf" ProgId="AppXr0rz9yckydawgnrx5df1t9s57ne60yhn" ApplicationName="Print 3D" /> <Association Identifier=".arw" ProgId="AppX43hnxtbyyps62jhe9sqpdzxn1790zetc" ApplicationName="Photos" />
  <Association Identifier=".bmp" ProgId="AppX43hnxtbyyps62jhe9sqpdzxn1790zetc" ApplicationName="Photos" /> <Association Identifier=".cr2" ProgId="AppX43hnxtbyyps62jhe9sqpdzxn1790zetc" ApplicationName="Photos" />
  <Association Identifier=".crw" ProgId="AppX43hnxtbyyps62jhe9sqpdzxn1790zetc" ApplicationName="Photos" /> <Association Identifier=".dib" ProgId="AppX43hnxtbyyps62jhe9sqpdzxn1790zetc" ApplicationName="Photos" />
  <Association Identifier=".epub" ProgId="AppXvepbp3z66accmsd0x877zbbxjctkpr6t" ApplicationName="Microsoft Edge" /> <Association Identifier=".erf" ProgId="AppX43hnxtbyyps62jhe9sqpdzxn1790zetc" ApplicationName="Photos" />
  <Association Identifier=".fbx" ProgId="AppXmgw6pxxs62rbgfp9petmdyb4fx7rnd4k" ApplicationName="3D Viewer" /> <Association Identifier=".gif" ProgId="AppX43hnxtbyyps62jhe9sqpdzxn1790zetc" ApplicationName="Photos" />
  <Association Identifier=".glb" ProgId="AppXmgw6pxxs62rbgfp9petmdyb4fx7rnd4k" ApplicationName="3D Viewer" /> <Association Identifier=".gltf" ProgId="AppXmgw6pxxs62rbgfp9petmdyb4fx7rnd4k" ApplicationName="3D Viewer" />
  <Association Identifier=".htm" ProgId="ChromeHTML" ApplicationName="Google Chrome" /> <Association Identifier=".html" ProgId="ChromeHTML" ApplicationName="Google Chrome" />
  <Association Identifier=".jfif" ProgId="AppX43hnxtbyyps62jhe9sqpdzxn1790zetc" ApplicationName="Photos" /> <Association Identifier=".jpe" ProgId="AppX43hnxtbyyps62jhe9sqpdzxn1790zetc" ApplicationName="Photos" />
  <Association Identifier=".jpeg" ProgId="AppX43hnxtbyyps62jhe9sqpdzxn1790zetc" ApplicationName="Photos" /> <Association Identifier=".jpg" ProgId="AppX43hnxtbyyps62jhe9sqpdzxn1790zetc" ApplicationName="Photos" />
  <Association Identifier=".jxr" ProgId="AppX43hnxtbyyps62jhe9sqpdzxn1790zetc" ApplicationName="Photos" /> <Association Identifier=".kdc" ProgId="AppX43hnxtbyyps62jhe9sqpdzxn1790zetc" ApplicationName="Photos" />
  <Association Identifier=".MP2" ProgId="WMP11.AssocFile.MP3" ApplicationName="Windows Media Player" /> <Association Identifier=".mrw" ProgId="AppX43hnxtbyyps62jhe9sqpdzxn1790zetc" ApplicationName="Photos" />
  <Association Identifier=".nef" ProgId="AppX43hnxtbyyps62jhe9sqpdzxn1790zetc" ApplicationName="Photos" /> <Association Identifier=".nrw" ProgId="AppX43hnxtbyyps62jhe9sqpdzxn1790zetc" ApplicationName="Photos" />
  <Association Identifier=".obj" ProgId="AppXmgw6pxxs62rbgfp9petmdyb4fx7rnd4k" ApplicationName="3D Viewer" /> <Association Identifier=".orf" ProgId="AppX43hnxtbyyps62jhe9sqpdzxn1790zetc" ApplicationName="Photos" />
  <Association Identifier=".pdf" ProgId="AcroExch.Document.DC" ApplicationName="Adobe Acrobat Reader DC" /> <Association Identifier=".pef" ProgId="AppX43hnxtbyyps62jhe9sqpdzxn1790zetc" ApplicationName="Photos" />
  <Association Identifier=".ply" ProgId="AppXmgw6pxxs62rbgfp9petmdyb4fx7rnd4k" ApplicationName="3D Viewer" /> <Association Identifier=".png" ProgId="AppX43hnxtbyyps62jhe9sqpdzxn1790zetc" ApplicationName="Photos" />
  <Association Identifier=".raf" ProgId="AppX43hnxtbyyps62jhe9sqpdzxn1790zetc" ApplicationName="Photos" /> <Association Identifier=".raw" ProgId="AppX43hnxtbyyps62jhe9sqpdzxn1790zetc" ApplicationName="Photos" />
  <Association Identifier=".rw2" ProgId="AppX43hnxtbyyps62jhe9sqpdzxn1790zetc" ApplicationName="Photos" /> <Association Identifier=".rwl" ProgId="AppX43hnxtbyyps62jhe9sqpdzxn1790zetc" ApplicationName="Photos" />
  <Association Identifier=".sr2" ProgId="AppX43hnxtbyyps62jhe9sqpdzxn1790zetc" ApplicationName="Photos" /> <Association Identifier=".srw" ProgId="AppX43hnxtbyyps62jhe9sqpdzxn1790zetc" ApplicationName="Photos" />
  <Association Identifier=".stl" ProgId="AppXr0rz9yckydawgnrx5df1t9s57ne60yhn" ApplicationName="Print 3D" /> <Association Identifier=".tif" ProgId="PhotoViewer.FileAssoc.Tiff" ApplicationName="Windows Photo Viewer" />
  <Association Identifier=".tiff" ProgId="PhotoViewer.FileAssoc.Tiff" ApplicationName="Windows Photo Viewer" /> <Association Identifier=".txt" ProgId="txtfile" ApplicationName="Notepad" />
  <Association Identifier=".url" ProgId="IE.AssocFile.URL" ApplicationName="Internet Browser" /> <Association Identifier=".wdp" ProgId="AppX43hnxtbyyps62jhe9sqpdzxn1790zetc" ApplicationName="Photos" />
  <Association Identifier=".website" ProgId="IE.AssocFile.WEBSITE" ApplicationName="Internet Explorer" /> <Association Identifier="bingmaps" ProgId="AppXp9gkwccvk6fa6yyfq3tmsk8ws2nprk1p" ApplicationName="Maps" />
  <Association Identifier="http" ProgId="ChromeHTML" ApplicationName="Google Chrome" /> <Association Identifier="https" ProgId="ChromeHTML" ApplicationName="Google Chrome" />
  <Association Identifier="mailto" ProgId="Outlook.URL.mailto.15" ApplicationName="Outlook" />
  </DefaultAssociations>
"@
# 
$global:removeXML = @"
<Configuration>
  <Remove All="TRUE"/>
<Display Level="None" AcceptEULA="TRUE"/>
</Configuration>
"@
# O365 Config Settings
$global:setupXML = @"
<Configuration>
  <Add OfficeClientEdition="32">
    <Product ID="O365BusinessRetail">
      <Language ID="en-us" />
      <ExcludeApp ID="Teams" />
    </Product>
  </Add>  
</Configuration>
"@
# Menu Options
Function Show-Menu
    {param ([string]$Title = 'System Prep')
    Clear-Host
    Write-Host "================ $Title ================"
    Write-Host "                        "
    Write-Host "(1) Pre-Prep"
    Write-Host "(2) Workstation Prep"
    Write-Host "(3) Windows Updates"
    Write-Host "(4) Adjust power settings"
    Write-Host "(5) Remove MS Apps"
    Write-Host "Press Q to Quit."
    Write-Host "                        "
<#End of Options#>}
# Menu Responses
Do { Show-Menu
    $selection = Read-Host "Please make a selection"
    Switch ($selection)
{'1' 
{'Pre-Prep selected' <# Create ITAdmin, remove Audit mode, and install Chocolatey #>
    Write-Host "Prepping system, will require reboot and then select option #2 to complete."
    # Create onsys directory and hide it from muggles
        Write-Host "Creating directories..." -ForegroundColor Yellow
        New-Item -Path "C:\onsys" -ItemType Directory
        New-Item -Path "C:\onsys\Prep" -ItemType Directory
        New-Item -Path "C:\onsys\Prep\Choco\" -ItemType Directory
    # Create XML files for various settings
        New-Item -Path C:\onsys\Prep\startlayout.xml -ItemType File
        Add-Content -Path C:\onsys\Prep\startlayout.xml $global:StartMenuXML
        New-Item -Path C:\onsys\Prep\DefaultAssociations.xml -ItemType File
        Add-Content -Path C:\onsys\Prep\DefaultAssocations.xml $global:DefaultAppsXML
        New-Item -Path C:\onsys\Prep\remove.xml -ItemType File
        Add-Content -Path C:\onsys\Prep\remove.xml $global:removeXML
        New-Item -Path C:\onsys\Prep\setup.xml -ItemType File
        Add-Content -Path C:\onsys\Prep\setup.xml $global:setupXML
        attrib +s +h "C:\onsys"

    # Remove OOBE prompts, and create ITAdmin
        Set-ItemProperty -Path 'HKLM:\SYSTEM\Setup' -Name 'CmdLine' -Value ''
        Set-ItemProperty -Path 'HKLM:\SYSTEM\Setup' -Name 'RespecializeCmdLine' -Value ''
        Set-ItemProperty -Path 'HKLM:\SYSTEM\Setup' -Name 'OOBEInProgress' -Value '0'
        Set-ItemProperty -Path 'HKLM:\SYSTEM\Setup' -Name 'SetupPhase' -Value '0'
        Set-ItemProperty -Path 'HKLM:\SYSTEM\Setup' -Name 'SetupType' -Value '0'
        Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name 'EnableCursorSuppression' -Value '0'
        Set-ItemProperty -Path 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System' -Name 'ConsentPromptBehaviorAdmin' -Value '0'
    # Disable UAC
        Set-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System -Name ConsentPromptBehaviorAdmin -Type DWord -Value 0
        Set-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System -Name EnableLUA -Type DWord -Value 0
    # Install NuGet
        Install-PackageProvider -Name NuGet -Force
        Import-PackageProvider -Name NuGet -Force
    # Apparently PSWindowsUpdate module comes from the PSGallery and needs to be trusted
        Set-PSRepository -Name PSGallery -InstallationPolicy Trusted
        Install-Module PSWindowsUpdate -Force
        Import-Module PSWindowsUpdate -Force
    # Install Windows Updates
        Write-Verbose "Checking for, and downloading and installing Windows Updates (No Auto Reboot)" -Verbose
        Get-WindowsUpdate -install -acceptall -IgnoreReboot -IgnoreRebootRequired
        Write-Host "Installing Windows Updates Complete!" -ForegroundColor Green
    # Enable updates for other microsoft products
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        $ServiceManager = New-Object -ComObject "Microsoft.Update.ServiceManager"
        $ServiceManager.ClientApplicationID = "My App"
        $ServiceManager.AddService2( "7971f918-a847-4430-9279-4a52d1efe18d",7,"")
        Write-Verbose "Installing Windows Update Powershell Module" -Verbose
    # Install Chocolatey
        Write-Host "Installing Chocolatey"
        [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072; Invoke-Expression ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))
        Start-Sleep -Seconds 2
    # Create ITAdmin w/password 
        $NewPassword = ConvertTo-SecureString "Cyberdog#1" -AsPlainText -Force
        New-LocalUser -Name "ITAdmin" -Description "Consys Group Admin account"
        Set-LocalUser -Name "ITAdmin" -Password $NewPassword
        Add-LocalGroupMember -Group "Administrators" -Member "ITAdmin"
        Write-Host "Windows Bloat removed, Audit mode disabled, ITAdmin created. System Rebooting" -ForegroundColor Green
        Read-Host -Prompt "Done?"
        Restart-Computer
<#End of Pre-Prep #>}
'2' { 'System Prep starting...'
    <# System Prep tasks required for workstations at Consys #>
    Start-Transcript C:\onsys\PrepStart.txt
    If (-NOT ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator))
        {Start-Process powershell.exe "-File",('"{0}"' -f $MyInvocation.MyCommand.Path) -Verb RunAs
        Exit}
# Prompt for setup type
    $global:PrepCheck = Read-Host -Prompt "Prep or Takeover? (1 or 2)"
# Boolean to proceed with prep or takeover
        If($global:PrepCheck -eq '1'){
            $global:ScriptIntelligence = "Prep"
            Write-Host "Loading prep functions"
            Write-Host "Prepping system for CG_Prep"
            Start-Sleep -Seconds 1}
        ElseIf ($global:PrepCheck -like '2'){
            $global:ScriptIntelligence = "Takeover"
            Write-Host "Loading takeover functions" -ForegroundColor Yellow
            Write-Host "Prepping system for CG_Takeover" -ForegroundColor Yellow
            Start-Sleep -Seconds 1}
# Variables
    $global:ConsysDir = Test-Path -Path "C:\onsys"
    $global:ManufacturerCheck = Get-CimInstance -Class Win32_Computersystem | Select-Object -ExpandProperty Manufacturer
    $global:Temp = Test-Path -Path "C:\Windows\Temp"
    $global:Prefetch = Test-Path -Path "C:\Windows\Prefetch"
    $global:SystemLogs = Test-Path -Path @('C:\Windows\Logs\CBS', 'C:\Windows\Performance\WinSAT','C:\ProgramData\Microsoft\Windows\WER\ReportArchive\AppCrash')
    #Apps for removal:
    $global:BingWeather = Get-AppXPackage -Name *Microsoft.BingWeather*
    $global:GetHelp = Get-AppXPackage -Name *Microsoft.GetHelp*
    $global:Getstarted = Get-AppXPackage -Name *Microsoft.Getstarte*
    $global:Maps = Get-AppXPackage -Name *Microsoft.WindowsMaps*
    $global:MixedReality = Get-AppXPackage -Name *Microsoft.MixedReality.Portal*
    $global:OfficeHub = Get-AppXPackage -Name *Microsoft.MicrosoftOfficeHu*
    $global:OneConnect = Get-AppXPackage -Name *Microsoft.OneConnect*
    $global:OneNote = Get-AppXPackage -Name *Microsoft.Office.OneNote*
    $global:People = Get-AppXPackage -Name *Microsoft.People*
    $global:SolitaireCollection = Get-AppXPackage -Name *Microsoft.MicrosoftSolitaireCollection*
    $global:Wallet = Get-AppXPackage -Name *Microsoft.Wallet*
    $global:WindowsCommunications = Get-AppXPackage -Name *microsoft.windowscommunicationsapp*
    $global:WindowsFeedback = Get-AppXPackage -Name *Microsoft.WindowsFeedbackHu*
    $global:Xbox.TCUI = Get-AppXPackage -Name *Microsoft.Xbox.T*
    $global:XboxApp = Get-AppXPackage -Name *Microsoft.XboxApp*
    $global:XboxGameOverlay = Get-AppXPackage -Name *Microsoft.XboxGameOverla*
    $global:XboxGamingOverlay = Get-AppXPackage -Name *Microsoft.XboxGamingOverlay*
    $global:XboxIdentityProvider = Get-AppXPackage -Name *Microsoft.XboxIdentityProvider*
    $global:XboxSpeechToTextOverlay = Get-AppXPackage -Name *Microsoft.XboxSpeechToTextOverlay*
    $global:YourPhone = Get-AppXPackage -Name *Microsoft.YourPhone*
    $global:ZuneMusic = Get-AppXPackage -Name *Microsoft.ZuneMusi*
    $global:ZuneVideo = Get-AppXPackage -Name *Microsoft.ZuneVideo*

# Create onsys directory and hide it from muggles
    If($global:ConsysDir -eq $false){
        Write-Host "Creating directories..." -ForegroundColor Yellow
        New-Item -Path "C:\onsys" -ItemType Directory
        New-Item -Path "C:\onsys\Prep" -ItemType Directory
        New-Item -Path "C:\onsys\Prep\Choco\" -ItemType Directory
        $env:ChocolateyInstall = 'C:\onsys\Prep\Choco\'
        attrib +s +h "C:\onsys"
    <#C:\onsys#>}
# Installs Agent as an Admin
    <# $AgentRequired = Test-Path -Path "C:\onsys\Prep"
    If($AgentRequired -eq "$true"){Start-Process "C:\onsys\AGENT_*" -Verb RunAs
    Write-Host "Agent Installing..." -ForegroundColor Red}
    ElseIf ($AgentRequired -eq "$false"){Write-Host "Agent not detected in Consys Dir, please manually download" -ForegroundColor Red}
    # Else If Agent already installed 
    #>

    <##>
# FUNCTIONS
function CG_Power(){
    # Hibernate off
        powercfg -h off
    # SpecIfies the new value, in minutes.
        powercfg /CHANGE monitor-timeout-ac 240
        powercfg /CHANGE monitor-timeout-dc 10
        powercfg /CHANGE disk-timeout-ac 0
        powercfg /CHANGE disk-timeout-dc 0
        powercfg /Change standby-timeout-ac 0
        powercfg /Change standby-timeout-dc 20
    # To disable selective suspend on plugged in laptops/desktops (0=Do nothing - 1=Sleep - 2=Hibernate - 3=Shut down - 4=Turn off the display):
        Powercfg -setacvalueindex 8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c 2a737441-1930-4402-8d77-b2bebba308a3 48e6b7a6-50f5-4782-a5d4-53bb8f07e226 0
        Powercfg -setdcvalueindex 8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c 2a737441-1930-4402-8d77-b2bebba308a3 48e6b7a6-50f5-4782-a5d4-53bb8f07e226 0
    # To set power button action on laptops/desktops (0=Do nothing - 1=Sleep - 2=Hibernate - 3=Shut down - 4=Turn off the display):
        powercfg -setacvalueindex 8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c 4f971e89-eebd-4455-a8de-9e59040e7347 7648efa3-dd9c-4e3e-b566-50f929386280 2
        powercfg -setdcvalueindex 8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c 4f971e89-eebd-4455-a8de-9e59040e7347 7648efa3-dd9c-4e3e-b566-50f929386280 2
    # To set lid close action on laptops (0=Do nothing - 1=Sleep - 2=Hibernate - 3=Shut down):
        powercfg -setacvalueindex 8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c 4f971e89-eebd-4455-a8de-9e59040e7347 5ca83367-6e45-459f-a27b-476b1d01c936 0
        powercfg -setdcvalueindex 8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c 4f971e89-eebd-4455-a8de-9e59040e7347 5ca83367-6e45-459f-a27b-476b1d01c936 0
    <# Power configurations #>}
function CG_NetworkUpdates(){
    # Disable Firewall
        Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled False
    # Enable PSRemoting
        Enable-PSRemoting
    # Enable RDP
        Enable-NetFirewallRule -DisplayGroup "Remote Desktop"
        Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Terminal Server" -name "fDenyTSConnections" -Value 0
    # Disable IPv6 - on all adapters
    Disable-NetAdapterBinding –InterfaceAlias '*' –ComponentID 'ms_tcpip6'
        Write-Host "Network settings completed" -ForegroundColor Green
    <# Networking updates #>}
function CG_UIAdjustments(){
    $ErrorActionPreference -eq 'silentlycontinue'
    # TimeZone
        Set-TimeZone -Name "Eastern Standard Time"
    # Language Preferences
        Set-Culture -CultureInfo en-CA
    # Change Explorer home screen back to "This PC"
        Set-ItemProperty -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced -Name LaunchTo -Type DWord -Value 1
    # Domain Users added to Local Admin
    # Add-LocalGroupMember -Group Administrators -Member "$env:USERDNSDOMAIN\Domain Users"
    # .Net Framework
        Write-Verbose "Install .NET Framework" -Verbose
        Add-WindowsCapability -Online -Name NetFx3~~~~
        Write-Verbose ".NET Framework Install Complete" -Verbose
        Disable-MMAgent -ApplicationPreLaunch
    # Disable (Edge) Prelaunch
        reg add "HKLM\SOFTWARE\Policies\Microsoft\MicrosoftEdge\Main" /v AllowPrelaunch /t REG_DWORD /d "0" /f
    # Remove Desktop shortcuts
        Remove-Item -path $env:USERPROFILE\desktop\*.lnk -exclude *Chrome*
        Remove-Item -path c:\users\public\desktop\*.lnk -exclude *Chrome*
    # Default File associations
        dism /online /Import-DefaultAppAssociations:"$global:Default_Apps"
    # Dark mode
        Write-Host "Enabling Dark Mode"
        Set-ItemProperty -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize -Name AppsUseLightTheme -Value 0
    # Disabling OneDrive...
        If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive")) {New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive" | Out-Null}
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive" -Name "DisableFileSyncNGSC" -Type DWord -Value 1
    # Apply default Apps
        dism /online /Import-DefaultAppAssociations:"C:\onsys\Prep\DefaultAssociations.xml"
    <# UI Updates #>}
function CG_WinUpdates(){
    # Install Windows Updates
        Write-Verbose "Checking for, and downloading and installing Windows Updates (No Auto Reboot)" -Verbose
        Get-WindowsUpdate -install -acceptall -IgnoreReboot -IgnoreRebootRequired
        Write-Host "Installing Windows Updates Complete!" -ForegroundColor Green
    <# Windows updates #>}
function CG_Menus(){
    # Clear Start-Menu Pins
    $layoutFile="C:\Windows\StartMenuLayout.xml"
    # Delete layout file If it already exists
    If(Test-Path $layoutFile)
    {Remove-Item $layoutFile}
    # Creates the blank layout file
    $global:StartMenuXML | Out-File $layoutFile -Encoding ASCII
    $regAliases = @("HKLM", "HKCU")
    # Assign the start layout and force it to apply with "LockedStartLayout" at both the machine and user level
    foreach ($regAlias in $regAliases){
    $basePath = $regAlias + ":\SOFTWARE\Policies\Microsoft\Windows"
    $keyPath = $basePath + "\Explorer" 
    If(!(Test-Path -Path $keyPath)) {New-Item -Path $basePath -Name "Explorer"}
    Set-ItemProperty -Path $keyPath -Name "LockedStartLayout" -Value 1
    Set-ItemProperty -Path $keyPath -Name "StartLayoutFile" -Value $layoutFile}
    # Restart Explorer, open the start menu (necessary to load the new layout), and give it a few seconds to process
    Stop-Process -name explorer
    Start-Sleep -s 2
    $wshell = New-Object -ComObject wscript.shell; $wshell.SendKeys('^{ESCAPE}')
    Start-Sleep -s 2
    # Enable the ability to pin items again by disabling "LockedStartLayout"
    foreach ($regAlias in $regAliases){
    $basePath = $regAlias + ":\SOFTWARE\Policies\Microsoft\Windows"
    $keyPath = $basePath + "\Explorer" 
    Set-ItemProperty -Path $keyPath -Name "LockedStartLayout" -Value 0}
    # Restart Explorer and delete the layout file
    Stop-Process -name explorer
    # Uncomment the next line to make clean start menu default for all new users
    Import-StartLayout -LayoutPath $layoutFile -MountPath $env:SystemDrive\
    Remove-Item $layoutFile

    # Hide Cortana Search
    Set-ItemProperty -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Search -Name SearchboxTaskbarMode -Type DWord -Value 0
    # Hide Cortana button
    Set-Itemproperty -Path Registry::HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced -Name ShowCortanaButton -Value 0
    # Start Menu: Disable Bing Search Results
    Set-ItemProperty -Path Registry::HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Search -Name BingSearchEnabled -Type DWord -Value 0
    # Hide TaskView Button
    Set-ItemProperty -Path Registry::HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced -Name ShowTaskViewButton -Type DWord -Value 0
    # Remove Suggestions from Start Menu
    Set-ItemProperty -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager -Name SystemPaneSuggestionsEnabled -Type DWord -Value 0
    # Remove MeetNow Button
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "HideSCAMeetNow" -Value 1
<# Remove and customize Start Menu & Taskbar #>}
function CG_Apps (){
    # Apps to install
    choco install -y -r microsoft-windows-terminal
    choco install -y -r adobereader
    choco install -y -r googlechrome
    choco install -y -r zoom
    choco install -y -r zoom-outlook
    <# Office install disabled while script not in production#>
    choco install -y -r office365business
    # Check If Dell is manufacturer, If true then install Command Updates, and then install all updates
    If($global:ManufacturerCheck -eq "Dell Inc."){Write-Host "Installing Dell Command Update" -ForegroundColor Green
        choco install -y -r dellcommandupdate
        Start-Process "C:\Program Files\Dell\CommandUpdate\dcu-cli.exe" "/scan" -Wait
        Start-Process "C:\Program Files\Dell\CommandUpdate\dcu-cli.exe" "/applyUpdates" -Wait
        Write-Verbose "Dell Command Update installed."}
    Else{Write-Host "Dell is not the manufacturer, Dell Command Update will not be installed" -ForegroundColor Red}
<# Apps to install during Prep#>}
function CG_Debloat (){
    $ErrorActionPreference -eq 'silentlycontinue'
    # Remove MSBloat
        Remove-AppXPackage -Package $global:BingWeather
        Remove-AppXPackage -Package $global:GetHelp
        Remove-AppXPackage -Package $global:Getstarted
        Remove-AppXPackage -Package $global:Maps
        Remove-AppXPackage -Package $global:MixedReality
        Remove-AppXPackage -Package $global:OfficeHub
        #Remove-AppXPackage -Package $global:OneConnect
        Remove-AppXPackage -Package $global:OneNote
        Remove-AppXPackage -Package $global:People
        Remove-AppXPackage -Package $global:SolitaireCollection
        Remove-AppXPackage -Package $global:Wallet
        Remove-AppXPackage -Package $global:WindowsCommunications
        Remove-AppXPackage -Package $global:WindowsFeedback
        #Remove-AppXPackage -Package $global:Xbox.TCUI
        #Remove-AppXPackage -Package $global:Xbox.App
        #Remove-AppXPackage -Package $global:XboxGameOverlay
        Remove-AppXPackage -Package $global:XboxGamingOverlay
        Remove-AppXPackage -Package $global:XboxIdentityProvider
        Remove-AppXPackage -Package $global:XboxSpeechToTextOverlay
        Remove-AppXPackage -Package $global:YourPhone
        Remove-AppXPackage -Package $global:ZuneMusic
        Remove-AppXPackage -Package $global:ZuneVideo 
    # Delete system level temp files
    If($global:Temp -eq $true){
    Write-Host "Removing System level Temp files..." -ForegroundColor Yellow
    Remove-Item -Path C:\Windows\Temp\* -Force -Recurse}
    If($global:Prefetch -eq $true){
    Write-Host "Removing System level Prefetch Data..." -ForegroundColor Yellow
    Remove-Item -Path C:\Windows\Prefetch\*.pf -Force -Recurse
    <# Pre Fetch#>}
    If($global:SystemLogs -eq $true){
        Write-Host "Removing System level log files..." -ForegroundColor Yellow
        Remove-Item -Path "C:\Windows\Performance\WinSAT\*.log" -Force -Recurse
        Remove-Item -Path "C:\ProgramData\Microsoft\Windows\WER\ReportArchive\AppCrash*" -Force -Recurse
    <#System Level Logs#>}
    # SSD lIfe improvement
        fsutil behavior set DisableLastAccess 1
        fsutil behavior set EncryptPagingFile 0
    # Disable Defrag
        schtasks /Change /DISABLE /TN "\Microsoft\Windows\Defrag\ScheduledDefrag"
    # Disable automatic setup of network devices
    If(!(Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\NcdAutoSetup\Private")){
        New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\NcdAutoSetup\Private" -Force | Out-Null}
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\NcdAutoSetup\Private" -Name "AutoSetup" -Type DWord -Value 0
    # Remove pre-loaded O365
        Write-Verbose "Removing existing Office365 Installs" -Verbose
        Start-Process ".\setup.exe" "/configure .\remove.xml" -Wait
    # Remove TEAMS system wide installer
        Start-Process MsiExec.exe -ArgumentList '/X{39AF0813-FA7B-4860-ADBE-93B9B214B914} /qn' -Wait
        Start-Process MsiExec.exe -ArgumentList '/X{731F6BAA-A986-45A4-8936-7C3AAAAA760B} /qn' -Wait
    # Disable Silent Install Store Apps
        Write-Output "> Disabling silent install Store Apps..."
        Set-ItemProperty -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager -Name SilentInstalledAppsEnabled -Type DWord -Value 0
    # Disable Subscribed Content Apps
        Write-Output "> Disabling Subscribed Content Apps..."
        Set-ItemProperty -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager -Name SubscribedContent-338388Enabled -Type DWord -Value 0
    # Disable Action Center
        Write-Output "> Disabling Action Center..."
        If (!(Test-Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\Explorer")){
        New-Item -Path HKCU:\SOFTWARE\Policies\Microsoft\Windows\Explorer | Out-Null}
        Set-ItemProperty -Path HKCU:\SOFTWARE\Policies\Microsoft\Windows\Explorer -Name DisableNotIficationCenter -Type DWord -Value 1
        Set-ItemProperty -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\PushNotIfications -Name ToastEnabled -Type DWord -Value 0
    # Hiding OneDrive from FileExplorer
        Write-Output "> Hiding the onedrive folder in windows explorer..."
        regedit /s $PSScriptRoot\Regfiles\Hide_Onedrive_Folder.reg
    # Disable Tips & Tricks
        Write-Output "> Disabling tips, tricks and suggestions in the startmenu and settings..."
        regedit /s $PSScriptRoot\Regfiles\Disable_Windows_Suggestions.reg
    # Disable context menus
        Write-Output "> Disabling contextmenu entries for: Share, Include in library & Give access..."
        regedit /s $PSScriptRoot\Regfiles\Disable_Share_from_context_menu.reg
        regedit /s $PSScriptRoot\Regfiles\Disable_Include_in_library_from_context_menu.reg
        regedit /s $PSScriptRoot\Regfiles\Disable_Give_access_to_context_menu.reg
    # Disable Bing search from Start Menu
        Write-Output "> Disabling bing in Windows search..."
        regedit /s $PSScriptRoot\Regfiles\Disable_Bing_Searches.reg
    # Clean DNS
        Write-Host "Flushing DNS..." -ForegroundColor Yellow
        Clear-DnsClientCache
<# Debloat #>}
function CG_Prep (){
    CG_Power
    CG_NetworkUpdates
    CG_UIAdjustments
    CG_WinUpdates
    CG_Debloat
    CG_Menus
    CG_Apps
<#Prep Functions#>}
function CG_Takeover(){
    CG_Power
    CG_NetworkUpdates
    CG_UIAdjustments
    CG_WinUpdates
    CG_Debloat
    CG_Menus
<# Remove bloat from previous MSP #>}
If($global:ScriptIntelligence -eq "Prep"){
    Write-Host "Powershell Version: $global:PSVersion detected" -ForegroundColor Yellow
    Write-Host "Adjusting syntax...please wait"
    CG_Prep}
ElseIf($global:ScriptIntelligence -eq "Takeover"){
    Write-Host "Takeover option was selected"
    Write-Host "Adjusting syntax"
    CG_Takeover}
$PrepComplete = Read-Host -Prompt "Reset Execution Policy?(Y/N)"
If($PrepComplete -eq 'Y'){Write-Host "Execution Policy has been reset"
    Set-ExecutionPolicy -ExecutionPolicy Restricted -Scope LocalMachine}
    Else{Write-Host "Policy not reset"}
Stop-Transcript
<# End of System Prep#>} 
'3' {'Server Prep starting...'
    Write-Host "This will have basic prompts"
    Write-host "Ones asking about DC, FS, ADDS, DNS, DHCP"
    Write-Host "At this time I have no baseline for a server config"
    
    # Setup Additional Drives
        # Change CDROM to E:
        # Rename 60GB Drive as "OS"
        # Create simple volume w/ remaining unallocated partition
        # Assign letters (D)ata,(H)yperV data,(F)ServerBackup,(G)WkstnBackup - Where Applicable
    
    # Setup New Users
        # U: ITAdmin P: Cyberdog#1
        # U: Speedvault P: Cyberdog#1
        # U: Intronis-wkstn P: Cyberdog#1
    
    # Global Function Prep 
        # Disable UAC
        # Install Chrome
        # Install Adobe
        # Change Quick Access to My Computer
        # Change Server-Name (Read Prompt to global variable)
        # Disable Windows Firewall
        # Enable RDP
        # Adjust Windows updates to Manual only
        # Disable IE Enhanced security
        # Set Time Zone
        # Activate Windows Server OS

    # Features to install
        # Install Hyper-V 
        # Install .Net 3.5 Framework
        # Install ASP.NET 4.6
        # Install SNMP
        # Reboot Server

    # Config SNMP
        # Set Community rights to "READ ONLY"
        # Set Community name type to Public
        # Set "Accept SNMP Packets from any host"
    
    # Dell Open Manage
        # Start-Process OMSA_x64.exe (-RunAs)

    # NIC Teaming
        # New Team
        # Name: "Host-Team1"
        # Can take several minutes
        # Show team status - Prompt to move on
        # Repeat steps if second team required
        # Reboot Server 
        # Select NIC Host-Team1
        # Disable IPv6
        # Set IP X.X.X.50 (Host is always .50)
        

    
    



    # Server Type
        # 1. Stand Alone
        # 2. Host, DC-VM, Data-VM
        # 3. Host, DC-VM, Data-VM, Archive-VM
        # 4. Terminal Server


    <# End of Server Prep#>}
'4' {'Adjusting (Power Settings)'
    # Hibernate off
    powercfg -h off
    # SpecIfies the new value, in minutes.
        powercfg /CHANGE monitor-timeout-ac 240
        powercfg /CHANGE monitor-timeout-dc 10
        powercfg /CHANGE disk-timeout-ac 0
        powercfg /CHANGE disk-timeout-dc 0
        powercfg /Change standby-timeout-ac 0
        powercfg /Change standby-timeout-dc 20
    # To disable selective suspend on plugged in laptops/desktops (0=Do nothing - 1=Sleep - 2=Hibernate - 3=Shut down - 4=Turn off the display):
        Powercfg -setacvalueindex 8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c 2a737441-1930-4402-8d77-b2bebba308a3 48e6b7a6-50f5-4782-a5d4-53bb8f07e226 0
        Powercfg -setdcvalueindex 8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c 2a737441-1930-4402-8d77-b2bebba308a3 48e6b7a6-50f5-4782-a5d4-53bb8f07e226 0
    # To set power button action on laptops/desktops (0=Do nothing - 1=Sleep - 2=Hibernate - 3=Shut down - 4=Turn off the display):
        powercfg -setacvalueindex 8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c 4f971e89-eebd-4455-a8de-9e59040e7347 7648efa3-dd9c-4e3e-b566-50f929386280 2
        powercfg -setdcvalueindex 8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c 4f971e89-eebd-4455-a8de-9e59040e7347 7648efa3-dd9c-4e3e-b566-50f929386280 2
    # To set lid close action on laptops (0=Do nothing - 1=Sleep - 2=Hibernate - 3=Shut down):
        powercfg -setacvalueindex 8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c 4f971e89-eebd-4455-a8de-9e59040e7347 5ca83367-6e45-459f-a27b-476b1d01c936 0
        powercfg -setdcvalueindex 8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c 4f971e89-eebd-4455-a8de-9e59040e7347 5ca83367-6e45-459f-a27b-476b1d01c936 0
    Write-Host "Completed."
<# Power configurations #>}
'5' {'You chose (Reset MS Apps)'}
'6' {'You chose ()'}
} pause }
Until ($selection -eq 'Q')
#
Stop-Transcript
