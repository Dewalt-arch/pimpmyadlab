#Requires -RunAsAdministrator
 
# TCM-ACADEMY Practical Ethical Hacker Course - Active Directory Lab build script 
# DomainController (Hydra-DC) and Both Workstation (Punisher & Spiderman) 
# https://academy.tcm-sec.com/p/practical-ethical-hacking-the-complete-course
#
# Scripted By: Dewalt         
# Revision 2.0.3 - see readme.md for revision notes   
#    
# Special Thanks to :
#  ToddAtLarge (PNPT Certified) for the NukeDefender script 
#  Yaseen (PNPT Certified) for Alpha/Beta Testing!
#  
# 
#  -- Autoconfigured IP Addresses --
#  DC will always have ip x.x.x.250
#  Punsiher will always have ip x.x.x.220 
#  Spirderman will always have ip x.x.x.221
#  DNS On the DC is set to 127.0.0.1
#  DNS On Workstations is set to DC's ip of x.x.x.250
#

function check_ipaddress {
  $CheckIPAddress=Get-NetIPAddress -AddressFamily IPv4 -InterfaceIndex $(Get-NetConnectionProfile | Select-Object -ExpandProperty InterfaceIndex) | Select-Object -ExpandProperty IPAddress
  # split the ip address up based on the . 
  $CheckIPByte = $CheckIPAddress.Split(".")
  
  # first 2 octets of ip address only 
  if ($CheckIPByte[0] -eq "169" -And $CheckIPByte[1] -eq "254") 
   { write-host("`n [ ERROR ] - $CheckIPaddress is a LinkLocal Adress, Check your Hypervisor configuration `n`n")
     exit } 
  # else 
  # { write-host("Network IP is not a Link local ip address range.. Continuing")} 
  }

# -- being set_mppref function
function set_mppref {
  # moved to its own function so it is only called once at the begining of each machine build
  Set-MpPreference -DisableRealtimeMonitoring $true | Out-Null
  Set-MpPreference -DisableRemovableDriveScanning $true | Out-Null
  Set-MpPreference -DisableArchiveScanning  $true | Out-Null
  Set-MpPreference -DisableAutoExclusions  $true | Out-Null
  Set-MpPreference -DisableBehaviorMonitoring  $true | Out-Null
  Set-MpPreference -DisableBlockAtFirstSeen $true | Out-Null
  Set-MpPreference -DisableCatchupFullScan  $true | Out-Null
  Set-MpPreference -DisableCatchupQuickScan $true | Out-Null
  Set-MpPreference -DisableEmailScanning $true | Out-Null
  Set-MpPreference -DisableIntrusionPreventionSystem  $true | Out-Null
  Set-MpPreference -DisableIOAVProtection  $true | Out-Null
  Set-MpPreference -DisablePrivacyMode  $true | Out-Null
  Set-MpPreference -DisableRealtimeMonitoring  $true | Out-Null
  Set-MpPreference -DisableRemovableDriveScanning  $true | Out-Null
  Set-MpPreference -DisableRestorePoint  $true | Out-Null
  Set-MpPreference -DisableScanningMappedNetworkDrivesForFullScan  $true | Out-Null
  Set-MpPreference -DisableScanningNetworkFiles  $true | Out-Null
  Set-MpPreference -DisableScriptScanning $true | Out-Null
  }
  # -- being set_mppref function

# ---- begin nuke defender function
function nukedefender { 
  $ErrorActionPreference = "SilentlyContinue"

  # disable uac, firewall, defender
  write-host("`n  [++] Nuking Defender")

  reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /f /v EnableLUA /t REG_DWORD /d 0 > $null
  reg add "HKLM\System\CurrentControlSet\Services\SecurityHealthService" /v "Start" /t REG_DWORD /d "4" /f > $null

  # remove defender reg hive if it exists
  # reg delete "HKLM\Software\Policies\Microsoft\Windows Defender" /f > $null
  
  # defender av go bye bye! 
  reg add "HKLM\Software\Policies\Microsoft\Windows Defender" /v "DisableAntiSpyware" /t REG_DWORD /d "1" /f > $null
  reg add "HKLM\Software\Policies\Microsoft\Windows Defender" /v "DisableAntiVirus" /t REG_DWORD /d "1" /f > $null
  reg add "HKLM\Software\Policies\Microsoft\Windows Defender\MpEngine" /v "MpEnablePus" /t REG_DWORD /d "0" /f > $null
  reg add "HKLM\Software\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "DisableBehaviorMonitoring" /t REG_DWORD /d "1" /f > $null
  reg add "HKLM\Software\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "DisableIOAVProtection" /t REG_DWORD /d "1" /f > $null
  reg add "HKLM\Software\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "DisableOnAccessProtection" /t REG_DWORD /d "1" /f > $null
  reg add "HKLM\Software\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "DisableRealtimeMonitoring" /t REG_DWORD /d "1" /f > $null
  reg add "HKLM\Software\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "DisableScanOnRealtimeEnable" /t REG_DWORD /d "1" /f > $null
  reg add "HKLM\Software\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "DisableScriptScanning" /t REG_DWORD /d "1" /f > $null 
  reg add "HKLM\Software\Policies\Microsoft\Windows Defender\Reporting" /v "DisableEnhancedNotifications" /t REG_DWORD /d "1" /f > $null
  reg add "HKLM\Software\Policies\Microsoft\Windows Defender\SpyNet" /v "DisableBlockAtFirstSeen" /t REG_DWORD /d "1" /f > $null
  reg add "HKLM\Software\Policies\Microsoft\Windows Defender\SpyNet" /v "SpynetReporting" /t REG_DWORD /d "0" /f > $null
  reg add "HKLM\Software\Policies\Microsoft\Windows Defender\SpyNet" /v "SubmitSamplesConsent" /t REG_DWORD /d "2" /f > $null
  reg add "HKLM\System\CurrentControlSet\Control\WMI\Autologger\DefenderApiLogger" /v "Start" /t REG_DWORD /d "0" /f > $null
  reg add "HKLM\System\CurrentControlSet\Control\WMI\Autologger\DefenderAuditLogger" /v "Start" /t REG_DWORD /d "0" /f > $null
    
  # disable services 
  write-host("`n  [++] Nuking Defender Related Services")
  schtasks /Change /TN "Microsoft\Windows\ExploitGuard\ExploitGuard MDM policy Refresh" /Disable > $null
  schtasks /Change /TN "Microsoft\Windows\Windows Defender\Windows Defender Cache Maintenance" /Disable > $null
  schtasks /Change /TN "Microsoft\Windows\Windows Defender\Windows Defender Cleanup" /Disable > $null
  schtasks /Change /TN "Microsoft\Windows\Windows Defender\Windows Defender Scheduled Scan" /Disable > $null
  schtasks /Change /TN "Microsoft\Windows\Windows Defender\Windows Defender Verification" /Disable > $null

  # disable windows update/automatic update
  write-host("`n  [++] Nuking Windows Update")
  reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" /v "NoAutoUpdate" /t REG_DWORD /d "1" /f > $null

  # disable remote uac ( should solved the rcp_s_access_denied issue with Impacket may need to include w/ workstations )
  write-host("`n  [++] Nuking UAC and REMOTE UAC")
  reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v "LocalAccountTokenFilterPolicy" /t REG_DWORD /d "1" /f > $null

  # enable icmp-echo on ipv4 and ipv6 (should not be required firewall is off)
  write-host("`n  [++] Enabling ICMP ECHO on IPv4 and IPv6")
  netsh advfirewall firewall add rule name="ICMP Allow incoming V4 echo request" protocol=icmpv4:8,any dir=in action=allow > $null
  netsh advfirewall firewall add rule name="ICMP Allow incoming V6 echo request" protocol=icmpv6:8,any dir=in action=allow > $null

  # enable Network Discovery
  write-host("`n  [++] Enabling Network Discovery")
  Get-NetFirewallRule -Group '@FirewallAPI.dll,-32752' |Set-NetFirewallRule -Profile 'Private, Domain' `
  -Enabled true -PassThru|select Name,DisplayName,Enabled,Profile|ft -a | Out-Null

  # disable all firewalling (public, private, domain) - Server and Workstations
  write-host("`n  [++] Disabling Windows Defender Firewalls : Public, Private, Domain")
  Set-NetFirewallProfile -Profile Domain, Public, Private -Enabled False | Out-Null
  
  # DARK MODE! 
  write-host("`n  [++] Quality of life improvement - Dark Theme")
  # Set-ItemProperty -Path "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize" -Name "AppsUseLightTheme" -Value 0 
  reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize" /v "AppsUseLightTheme" /t REG_DWORD /d "0" /f > $null
  reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize" /v "SystemUsesLightTheme" /t REG_DWORD /d "0" /f > $null

  # Disable screen locker, timeout
  write-host("`n  [++] Quality of life improvement - Disable ScreenSaver, ScreenLock and Timeout")
  reg add  "HKEY_CURRENT_USER\Software\Policies\Microsoft\Windows\Control Panel\Desktop" /v "ScreenSaveTimeOut" /t REG_DWORD /d "0" /f > $null 
  reg add  "HKEY_CURRENT_USER\Software\Policies\Microsoft\Windows\Control Panel\Desktop" /v "ScreenSaveActive" /t REG_DWORD /d "0" /f > $null
  reg add  "HKEY_CURRENT_USER\Software\Policies\Microsoft\Windows\Control Panel\Desktop" /v "ScreenSaverIsSecure" /t REG_DWORD /d "0" /f > $null
  }
  # ---- end nukedefender

# ---- begin remove_all_updates  
function remove_all_updates {
  Get-WmiObject -query "Select HotFixID  from Win32_QuickFixengineering" | sort-object -Descending -Property HotFixID|%{
    $sUpdate=$_.HotFixID.Replace("KB","")
    write-host ("Uninstalling update "+$sUpdate);
    & wusa.exe /uninstall /KB:$sUpdate /quiet /norestart;
    Wait-Process wusa 
    Start-Sleep -s 1 }
  }
  # ---- end remove_all_updates 

# ---- begin fix_setspn function 
function fix_setspn {
  $FullDomainName=((gwmi Win32_ComputerSystem).Domain)
  $ShortDomainName=((gwmi Win32_ComputerSystem).Domain).Split(".")[0]
  $machine=$env:COMPUTERNAME
  write-host("`n  [++] Deleting Existing SPNs")
  #setspn -D SQLService/MARVEL.local HYDRA-DC > $null
  #setspn -D SQLService/Marvel.local MARVEL\SQLService > $null
  #setspn -D HYDRA-DC/SQLService.MARVEL.local:60111 MARVEL\SQLService > $null
  #setspn -D MARVEL/SQLService.Marvel.local:60111 MARVEL\SQLService > $null
  #setspn -D DomainController/SQLService.MARVEL.Local:60111 MARVEL\SQLService > $null
 
#--- new code 
  setspn -D SQLService/$FullDomainName $machine > $null
  setspn -D SQLService/$FullDomainName $ShortDomainName\SQLService > $null
  setspn -D $machine/SQLService`.$FullDomainName`:60111 $ShortDomainName\SQLService > $null
  setspn -D $ShortDomainName/SQLService.$FullDomainName:60111 $ShortDomainName\SQLService > $null
  setspn -D DomainController/SQLService.$FullDomainName:60111 $ShortDomainName\SQLService > $null

  # add the new spn
  write-host("`n  [++] Adding SPNs")
  # setspn -A HYDRA-DC/SQLService.MARVEL.local:60111 MARVEL\SQLService > $null
  # setspn -A SQLService/MARVEL.local  MARVEL\SQLService > $null
  # setspn -A DomainController/SQLService.MARVEL.local:60111 MARVEL\SQLService > $null
 
 # -- new code 
 setspn -A $machine/SQLService.$FullDomainName`:60111 $ShortDomainName\SQLService > $null
 setspn -A SQLService/$FullDomainName $ShortDomainName\SQLService > $null
 setspn -A DomainController/SQLService.$FullDomainName`:60111 $ShortDomainName\SQLService > $null

  # check both local and domain spns (add additional if statements here)
  write-host("`n  [++] Checking Local Hydra-DC SPN")
  #setspn -L HYDRA-DC
  # -- new code 
  setspn -L $machine 
  write-host("`n  [++] Checking MARVEL\SQLService SPN")
  #setspn -L MARVEL\SQLService
  # -- new code 
  setspn -L $ShortDomainName\SQLService
  }
  # ---- end fix_setspn function 

# ---- begin fix_adcsca function 
function fix_adcsca {
  write-host ("`n  [++] Removing ADCSCertificateAuthority")
  # Install-WindowsFeature ADCS-Cert-Authority -IncludeManagementTools
  Install-AdcsCertificationAuthority -Force | Out-Null
  write-host ("`n  [++] Installing new ADCSCertificateAuthority `n")
  Install-AdcsCertificationAuthority -CAType EnterpriseRootCa -CryptoProviderName "RSA#Microsoft Software Key Storage Provider" `
  -KeyLength 2048 -HashAlgorithmName SHA256 -ValidityPeriod Years -ValidityPeriodUnits 99 -WarningAction SilentlyContinue -Force | Out-Null 
  #hold on this part may not be needed
  #Read-Host -Prompt "`n Press ENTER to continue..."
  #restart-computer 
  }
  # ---- end fix_adcsca function  

# ---- begin build_lab function 
function build_lab {
  $ErrorActionPreference = "SilentlyContinue"
  write-host("`n  When prompted you are being logged out simply click the Close button")
  remove_all_updates 

  # disable server manager from launch at startup
  write-host("`n  [++] Disabling Server Manager from launching on startup ")
  Get-ScheduledTask -TaskName ServerManager | Disable-ScheduledTask | Out-Null

  # download and install latest version of git from github
  setup_git

  # fix registry key fdrespub / network discovery in network exploerer
  # write-host("`n  [++] Setting Registry key: FDResPub")
  # reg add "HKLM\SYSTEM\CurrentControlSet\Services\FDResPub" /f /v DependOnService /t REG_MULTI_SZ /d "RpcSs\0http\0fpdhost\0LanmanWorkstation"
  # red add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /f /v sc_fdrespub /t REG_EXPAND_SZ /d "sc config fdrespub depend= RpcSs/http/fdphost/LanmanWorkstation"
  
  # install ad-domain-services
  write-host("`n  [++] Installing Module Active Directory Domain Services (ADDS)")
  Install-windowsfeature -name AD-Domain-Services -IncludeManagementTools -WarningAction SilentlyContinue | Out-Null

  # import activedirectory module
  write-host("`n  [++] Importing Module ActiveDirectory")
  Import-Module ActiveDirectory -WarningAction SilentlyContinue | Out-Null

  # install adds 
  write-host("`n  [++] Installing ADDS Domain : Marvel.local ")
  Install-ADDSDomain -SkipPreChecks -ParentDomainName MARVEL -NewDomainName local -NewDomainNetbiosName MARVEL `
  -InstallDns -SafeModeAdministratorPassword (Convertto-SecureString -AsPlainText "P@$$w0rd!" -Force) -Force -WarningAction SilentlyContinue | Out-Null

  # create adds forest marvel.local
  write-host("`n  [++] Deploying Active Directory Domain Forest in MARVEL.local")
  Install-ADDSForest -SkipPreChecks -CreateDnsDelegation:$false -DatabasePath "C:\Windows\NTDS" `
  -DomainMode "WinThreshold" -DomainName "MARVEL.local" -DomainNetbiosName "MARVEL" `
  -ForestMode "WinThreshold" -InstallDns:$true -LogPath "C:\Windows\NTDS" -NoRebootOnCompletion:$false `
  -SysvolPath "C:\Windows\SYSVOL" -Force:$true `
  -SafeModeAdministratorPassword (Convertto-SecureString -AsPlainText "P@$$w0rd!" -Force) -WarningAction SilentlyContinue | Out-Null

  write-host("`n  Note: Do NOT REBOOT MANUALLY - Let me reboot on my own! I am A BIG COMPUTER NOW!! I GOT THIS!! `n")
  }
  # ---- end build_adlab function

# ---- begin smb_signing function
function smb_signing {
  # smb signing is enabled but not required
  write-host("`n  [++] Setting Registry Keys SMB Signing Enabled but not Required")
  reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" /v "RequireSecuritySignature" /t REG_DWORD /d "0" /f > $null
  reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" /v "RequireSecuritySignature" /t REG_DWORD /d "0" /f > $null
  }
  # ---- end smb_signing function 

function get_sharphound {
  $source_url = "https://github.com/BloodHoundAD/SharpHound/releases/download/v1.1.1/SharpHound-v1.1.1.zip"
  mkdir C:\TCM-Academy\Sharphound
  $destination_path = "C:\TCM-Academy\Sharphound"
  Start-BitsTransfer -Source $source_url -Destination $destination_path 
  Expand-Archive -Path $destination_path\SharpHound-v1.1.1.zip -DestinationPath $destination_path -Force
  write-host("`n  [++] Installed Sharphound.exe to $destination_path ")
  }  

# ---- begin create_labcontent function
function create_labcontent {
  $ErrorActionPreference = "SilentlyContinue"
  
  # install ad-certificate services
  write-host("`n  [++] Installing Active Directory Certificate Services")
  Add-WindowsFeature -Name AD-Certificate -IncludeManagementTools -WarningAction SilentlyContinue | Out-Null
  
  # install ad-certificate authority
  write-host("`n  [++] Installing Active Directory Certificate Authority")
  Add-WindowsFeature -Name Adcs-Cert-Authority -IncludeManagementTools -WarningAction SilentlyContinue | Out-Null

  # configure ad-certificate authority
  write-host("`n  [++] Configuring Active Directory Certificate Authority")
  # fix_adcsca
  Install-AdcsCertificationAuthority -CAType EnterpriseRootCa -CryptoProviderName "RSA#Microsoft Software Key Storage Provider" `
  -KeyLength 2048 -HashAlgorithmName SHA1 -ValidityPeriod Years -ValidityPeriodUnits 99 -WarningAction SilentlyContinue -Force | Out-Null

  # install remote system administration tools
  write-host("`n  [++] Installing Remote System Administration Tools (RSAT)")
  Add-WindowsCapability -Online -Name Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0 -WarningAction SilentlyContinue | Out-Null

  # install rsat-adcs and rsat-adcs-management 
  write-host("`n  [++] Installing RSAT-ADCS and RSAT-ADCS-Management")
  Add-WindowsFeature RSAT-ADCS,RSAT-ADCS-mgmt -WarningAction SilentlyContinue | Out-Null

  # create C:\share\hackme me and smbshare
  write-host("`n  [++] Creating Share C:\Share\hackme - Permissions Everyone FullAccess")
  mkdir C:\Share\hackme > $null
  New-SmbShare -Name "hackme" -Path "C:\Share\hackme" -ChangeAccess "Users" -FullAccess "Everyone" -WarningAction SilentlyContinue | Out-Null

  # moved smb sigining to a function 
  smb_signing

  # printer-nightmare registry keys (breakout into individual fix function)
  write-host("`n  [++] Setting Registry Keys for PrinterNightmare")
  reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint" /v "NoWarningNoElevationOnInstall" /t REG_DWORD /d "1" /f > $null
  reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint" /v "RestrictDriverInstallationToAdministrators" /t REG_DWORD /d "0" /f > $null

  # set localaccounttokenfilterpolicy (breakout into individual fix function)
  write-host("`n  [++] Setting Registry Key for LocalAccountTokenFilterPolicy")
  reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\system" /v "LocalAccountTokenFilterPolicy" /t REG_DWORD /d "1" /f > $null

  # set alwaysinstallelevated (breakout into individual fix function)
  write-host("`n  [++] Setting Registry Key for AlwaysInstallElevated")
  red add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Installer" -v "AlwaysInstallElevated" /t REG_DWORD /d "1" /f > $null 

  # LAPS
  # wget https://download.microsoft.com/download/C/7/A/C7AAD914-A8A6-4904-88A1-29E657445D03/LAPS.x64.msi
  # .\Laps.x64.msi
  # Import-module AdmPwd.PS
  # Update-AdmPwdADSchema
  
  # set dns config of ethernet card on dc to 127.0.0.1
  
  # HERE IS THE IPV6 PROBLEM!!! Something to do with setting the dns on the nic borks the ipv6 
  #$adapter=Get-CimInstance -Class Win32_NetworkAdapter -Property NetConnectionID,NetConnectionStatus | Where-Object { $_.NetConnectionStatus -eq 2 } | Select-Object -Property NetConnectionID -ExpandProperty NetConnectionID
  #write-host("`n  [++] Setting DNS Server to 127.0.0.1 on interface $adapter")
  #Set-DNSClientServerAddress "$adapter" -ServerAddresses ("127.0.0.1") | Out-Null

  # create user pparker
  New-ADUser -Name "Peter Parker" -GivenName "Peter" -Surname "Parker" -SamAccountName "pparker" `
  -UserPrincipalName "pparker@$Global:Domain -Path DC=marvel,DC=local" `
  -AccountPassword (ConvertTo-SecureString "Password2" -AsPlainText -Force) `
  -PasswordNeverExpires $true -PassThru | Enable-ADAccount  | Out-Null
  Write-Host "`n  [++] User: Peter Parker added, Logon: pparker Password: Password2"
  Write-Host "        Adding Peter Parker to Marvel.local Groups: Domain Users"

  # create user fcastle
  New-ADUser -Name "Frank Castle" -GivenName "Frank" -Surname "Castle" -SamAccountName "fcastle" `
  -UserPrincipalName "fcastle@$Global:Domain -Path DC=marvel,DC=local" `
  -AccountPassword (ConvertTo-SecureString "Password1" -AsPlainText -Force) `
  -PasswordNeverExpires $true -PassThru | Enable-ADAccount  | Out-Null

  # if the rps_s_access_denited is fixed by the reg key, fcastle no longer needs to be a domain admin
  Add-ADGroupMember -Identity "Domain Admins" -Members fcastle  | Out-Null
  Write-Host "`n  [++] User: Frank Castle added, Logon: fcastle Password: Password1"
  Write-Host "        Adding Frank Castle to Marvel.local Groups: Domain Users, Domain Admins"

  # create user tstark 
  New-ADUser -Name "Tony Stark" -GivenName "Tony" -Surname "Stark" -SamAccountName "tstark" `
  -UserPrincipalName "tstark@$Global:Domain -Path DC=marvel,DC=local" `
  -AccountPassword (ConvertTo-SecureString "Password2019!@#" -AsPlainText -Force) `
  -PasswordNeverExpires $true -PassThru | Enable-ADAccount | Out-Null

  Add-ADGroupMember -Identity "Administrators" -Members tstark
  Add-ADGroupMember -Identity "Domain Admins" -Members tstark
  Write-Host "`n  [++] User: Tony Stark added, Logon: tstark Password: Password2019!@#"
  Write-Host "        Adding Tony Stark to Marvel.local Groups: Administrators, Domain Admins"

  # create user sqlservice 
  New-ADUser -Name "SQL Service" -GivenName "SQL" -Surname "Service" -SamAccountName "sqlservice" `
  -UserPrincipalName "sqlservice@$Global:Domain -Path DC=marvel,DC=local" `
  -AccountPassword (ConvertTo-SecureString "MYpassword123#" -AsPlainText -Force) `
  -PasswordNeverExpires $true -Description "Password is MYpassword123#" -PassThru | Enable-ADAccount | Out-Null

  Add-ADGroupMember -Identity "Administrators" -Members sqlservice | Out-Null
  Add-ADGroupMember -Identity "Domain Admins" -Members sqlservice | Out-Null
  Add-ADGroupMember -Identity "Enterprise Admins" -Members sqlservice | Out-Null
  Add-ADGroupMember -Identity "Group Policy Creator Owners" -Members sqlservice | Out-Null
  Add-ADGroupMember -Identity "Schema Admins" -Members sqlservice | Out-Null
  Write-Host "`n  [++] User: SQL Service added, Logon Name: sqlservice Password: MYpassword123#" 
  Write-Host "        Adding SQLService to Marvel.local Groups: Administrators, Domain Admins, Enterprise Admins, Group Policy Creator Owners, Schema Admins"

  # setspn for sqlservice user
  # this section of the script was moved to its own function to serve 2 purposes 
  # 1 for the adlab build intitally and 2 as a support tool 
  fix_setspn

  # create ou=groups, move all existing groups into ou=groups,dc=marvel,dc=local
  New-ADOrganizationalUnit -Name "Groups" -Path "DC=MARVEL,DC=LOCAL" -Description "Groups" | Out-Null
  get-adgroup "Schema Admins" | move-adobject -targetpath "OU=Groups,DC=MARVEL,DC=LOCAL" | Out-Null
  get-adgroup "Allowed RODC Password Replication Group" | move-adobject -targetpath "OU=Groups,DC=MARVEL,DC=LOCAL" | Out-Null
  get-adgroup "Cert Publishers" | move-adobject -targetpath "OU=Groups,DC=MARVEL,DC=LOCAL" | Out-Null
  get-adgroup "Cloneable Domain Controllers" | move-adobject -targetpath "OU=Groups,DC=MARVEL,DC=LOCAL" | Out-Null
  get-adgroup "Denied RODC Password Replication Group" | move-adobject -targetpath "OU=Groups,DC=MARVEL,DC=LOCAL" | Out-Null
  get-adgroup "DnsAdmins" | move-adobject -targetpath "OU=Groups,DC=MARVEL,DC=LOCAL" | Out-Null
  get-adgroup "DnsUpdateProxy" | move-adobject -targetpath "OU=Groups,DC=MARVEL,DC=LOCAL" | Out-Null
  get-adgroup "Domain Computers" | move-adobject -targetpath "OU=Groups,DC=MARVEL,DC=LOCAL" | Out-Null
  get-adgroup "Domain Controllers" | move-adobject -targetpath "OU=Groups,DC=MARVEL,DC=LOCAL" | Out-Null
  get-adgroup "Domain Guests" | move-adobject -targetpath "OU=Groups,DC=MARVEL,DC=LOCAL" | Out-Null
  get-adgroup "Domain Users" | move-adobject -targetpath "OU=Groups,DC=MARVEL,DC=LOCAL" | Out-Null
  get-adgroup "Domain Admins" | move-adobject -targetpath "OU=Groups,DC=MARVEL,DC=LOCAL" | Out-Null
  get-adgroup "Enterprise Admins" | move-adobject -targetpath "OU=Groups,DC=MARVEL,DC=LOCAL" | Out-Null
  get-adgroup "Enterprise Key Admins" | move-adobject -targetpath "OU=Groups,DC=MARVEL,DC=LOCAL" | Out-Null
  get-adgroup "Enterprise Read-only Domain Controllers" | move-adobject -targetpath "OU=Groups,DC=MARVEL,DC=LOCAL" | Out-Null
  get-adgroup "Group Policy Creator Owners" | move-adobject -targetpath "OU=Groups,DC=MARVEL,DC=LOCAL" | Out-Null
  get-adgroup "Key Admins" | move-adobject -targetpath "OU=Groups,DC=MARVEL,DC=LOCAL" | Out-Null
  get-adgroup "Protected Users" | move-adobject -targetpath "OU=Groups,DC=MARVEL,DC=LOCAL" | Out-Null
  get-adgroup "RAS and IAS Servers" | move-adobject -targetpath "OU=Groups,DC=MARVEL,DC=LOCAL" | Out-Null
  get-adgroup "Read-only Domain Controllers" | move-adobject -targetpath "OU=Groups,DC=MARVEL,DC=LOCAL" | Out-Null
  }
  # ---- end create_labcontent function


  # ---- begin create_marvel_gpo
function create_marvel_gpo {
  $CurrentDomain=((gwmi Win32_ComputerSystem).Domain).Split(".")[0]
  write-host("`n  [++] Removing Disable Defender Policy and Unlinking from Domain")
  Get-GPO -Name "Disable Defender" | Remove-GPLink -target "DC=$CurrentDomain,DC=local" | Remove-GPO -Name "Disable Defender" > $null 
 
  write-host("`n  [++] Creating new Disable Defender Group Policy Object")
  New-GPO -Name "Disable Defender"

  #reg add "HKLM\SYSTEM\CurrentControlSet\Services\FDResPub" /f /v DependOnService /t REG_MULTI_SZ /d "RpcSs\0http\0fpdhost\0LanmanWorkstation"
  write-host("`n  [++] Setting GPO Registry key: FDResPub")
  Set-GPRegistryValue -Name "Disable Defender" -Key "HKLM\SYSTEM\CurrentControlSet\Services\FDResPub" -ValueName "DependOnService" -Type MultiString -Value "RpcSs\0http\0fpdhost\0LanmanWorkstation"
  Set-GPRegistryValue -Name "Disable Defender" -Key "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -ValueName "sc_fdredpub" -Type MultiString -Value "sc config fdrespub depend= RpcSs/http/fdphost/LanmanWorkstation"
  reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /f /v sc_fdrespub /t REG_EXPAND_SZ /d "sc config fdrespub depend= RpcSs/http/fdphost/LanmanWorkstation"
  
  # enable rdp 
  # Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -name "fDenyTSConnections" -value 0
  write-host("`n  [++] Enable RDP")
  Set-GPRegistryValue -Name "Disable Defender" -Key "HKLM\System\CurrentControlSet\Control\Terminal Server" -ValueName "fDenyTSConnections" -Value 0 -Type Dword | Out-Null 

  #reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /f /v EnableLUA /t REG_DWORD /d 0 > $null
  write-host("`n  [++] Setting GPO Registry key: EnableLUA")
  Set-GPRegistryValue -Name "Disable Defender" -Key "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -ValueName "EnableLUA" -Value 0 -Type Dword | Out-Null

  #Set-GPRegistryValue -Name "LAPS_IT" -Key "HKLM\Software\Policies\Microsoft Services\AdmPwd" -ValueName 'AdmPwdEnabled' -Value 1 -Type Dword
  #reg add "HKLM\System\CurrentControlSet\Services\SecurityHealthService" /v "Start" /t REG_DWORD /d "4" /f > $null
  write-host("`n  [++] Setting GPO Registry key: SecurityHealthService")
  Set-GPRegistryValue -Name "Disable Defender" -Key "HKLM\System\CurrentControlSet\Services\SecurityHealthService" -ValueName "Start" -Value 4 -Type Dword | Out-Null
  # remove defender reg hive if it exists
  # reg delete "HKLM\Software\Policies\Microsoft\Windows Defender" /f > $null
  
  # defender av go bye bye domain group policy! 
  # reg add "HKLM\Software\Policies\Microsoft\Windows Defender" /v "DisableAntiSpyware" /t REG_DWORD /d "1" /f > $null
  write-host("`n  [++] Setting GPO Registry key: DisableAntiSpyware")
  Set-GPRegistryValue -Name "Disable Defender" -Key "HKLM\Software\Policies\Microsoft\Windows Defender" -ValueName "DisableAntiSpyware" -Value 1 -Type Dword | Out-Null

  #reg add "HKLM\Software\Policies\Microsoft\Windows Defender" /v "DisableAntiVirus" /t REG_DWORD /d "1" /f > $null
  write-host("`n  [++] Setting GPO Registry key: DisableAntiVirus")
  Set-GPRegistryValue -Name "Disable Defender" -Key "HKLM\Software\Policies\Microsoft\Windows Defender" -ValueName "DisableAntiVirus" -Value 1 -Type Dword | Out-Null

  #reg add "HKLM\Software\Policies\Microsoft\Windows Defender\MpEngine" /v "MpEnablePus" /t REG_DWORD /d "0" /f > $null
  write-host("`n  [++] Setting GPO Registry key: MpEnablePus")
  Set-GPRegistryValue -Name "Disable Defender" -Key "HKLM\Software\Policies\Microsoft\Windows Defender\MpEngine" -ValueName "MpEnablePus" -Value 0 -Type Dword | Out-Null

  write-host("`n  [++] Setting GPO Registry key: RTP DisableBehaviorMonitoring")
  #reg add "HKLM\Software\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "DisableBehaviorMonitoring" /t REG_DWORD /d "1" /f > $null
  Set-GPRegistryValue -Name "Disable Defender" -Key "HKLM\Software\Policies\Microsoft\Windows Defender\Real-Time Protection" -ValueName "DisableBehaviorMonitoring" -Value 1 -Type Dword | Out-Null

  write-host("`n  [++] Setting GPO Registry key: RTP DisableIOAVProtection")
  #reg add "HKLM\Software\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "DisableIOAVProtection" /t REG_DWORD /d "1" /f > $null
  Set-GPRegistryValue -Name "Disable Defender" -Key "HKLM\Software\Policies\Microsoft\Windows Defender\Real-Time Protection" -ValueName "DisableIOAVProtection" -Value 1 -Type Dword | Out-Null
  
  write-host("`n  [++] Setting GPO Registry key: RTP DisableOnAccessProtection")
  #reg add "HKLM\Software\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "DisableOnAccessProtection" /t REG_DWORD /d "1" /f > $null
  Set-GPRegistryValue -Name "Disable Defender" -Key "HKLM\Software\Policies\Microsoft\Windows Defender\Real-Time Protection" -ValueName "DisableOnAccessProtection" -Value 1 -Type Dword | Out-Null

  write-host("`n  [++] Setting GPO Registry key: RTP DisableRealtimeMonitoring")
  #reg add "HKLM\Software\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "DisableRealtimeMonitoring" /t REG_DWORD /d "1" /f > $null
  Set-GPRegistryValue -Name "Disable Defender" -Key "HKLM\Software\Policies\Microsoft\Windows Defender\Real-Time Protection" -ValueName "DisableRealtimeMonitoring" -Value 1 -Type Dword | Out-Null
 
  write-host("`n  [++] Setting GPO Registry key: RTP DisableScanOnRealtimeEnable")
  #reg add "HKLM\Software\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "DisableScanOnRealtimeEnable" /t REG_DWORD /d "1" /f > $null
  Set-GPRegistryValue -Name "Disable Defender" -Key "HKLM\Software\Policies\Microsoft\Windows Defender\Real-Time Protection" -ValueName "DisableScanOnRealtimeEnable" -Value 1 -Type Dword | Out-Null

  write-host("`n  [++] Setting GPO Registry key: RTP DisableScriptScanning")
  #Set-MpPreference -DisableScriptScanning $true 
  Set-GPRegistryValue -Name "Disable Defender" -Key "HKLM\Software\Policies\Microsoft\Windows Defender\Real-Time Protection" -ValueName "DisableScriptScanning" -Value 1 -Type Dword | Out-Null

  write-host("`n  [++] Setting GPO Registry key: Defender Reporting DisableEnhancedNotifications")
  #reg add "HKLM\Software\Policies\Microsoft\Windows Defender\Reporting" /v "DisableEnhancedNotifications" /t REG_DWORD /d "1" /f > $null
  Set-GPRegistryValue -Name "Disable Defender" -Key "HKLM\Software\Policies\Microsoft\Windows Defender\Reporting" -ValueName "DisableEnhancedNotifications" -Value 1 -Type Dword | Out-Null

  write-host("`n  [++] Setting GPO Registry key: Defender SpyNet DisableBlockAtFirstSeen")
  #reg add "HKLM\Software\Policies\Microsoft\Windows Defender\SpyNet" /v "DisableBlockAtFirstSeen" /t REG_DWORD /d "1" /f > $null
  Set-GPRegistryValue -Name "Disable Defender" -Key "HKLM\Software\Policies\Microsoft\Windows Defender\SpyNet" -ValueName "DisableBlockAtFirstSeen" -Value 1 -Type Dword | Out-Null
 
  write-host("`n  [++] Setting GPO Registry key: Defender SpyNet SpynetReporting")
  #reg add "HKLM\Software\Policies\Microsoft\Windows Defender\SpyNet" /v "SpynetReporting" /t REG_DWORD /d "0" /f > $null
  Set-GPRegistryValue -Name "Disable Defender" -Key "HKLM\Software\Policies\Microsoft\Windows Defender\SpyNet" -ValueName "SpynetReporting" -Value 0 -Type Dword | Out-Null
  
  write-host("`n  [++] Setting GPO Registry key: Defender SpyNet SubmitSamplesConsent")
  #reg add "HKLM\Software\Policies\Microsoft\Windows Defender\SpyNet" /v "SubmitSamplesConsent" /t REG_DWORD /d "2" /f > $null
  Set-GPRegistryValue -Name "Disable Defender" -Key "HKLM\Software\Policies\Microsoft\Windows Defender\SpyNet" -ValueName "SubmitSamplesConsent" -Value 2 -Type Dword | Out-Null
  
  write-host("`n  [++] Setting GPO Registry key: Defender ApiLogger")
  #reg add "HKLM\System\CurrentControlSet\Control\WMI\Autologger\DefenderApiLogger" /v "Start" /t REG_DWORD /d "0" /f > $null
  Set-GPRegistryValue -Name "Disable Defender" -Key "HKLM\System\CurrentControlSet\Control\WMI\Autologger\DefenderApiLogger" -ValueName "Start" -Value 0 -Type Dword | Out-Null 

  write-host("`n  [++] Setting GPO Registry key: Defender DefenderAuditLogger")
  #reg add "HKLM\System\CurrentControlSet\Control\WMI\Autologger\DefenderAuditLogger" /v "Start" /t REG_DWORD /d "0" /f > $null
  Set-GPRegistryValue -Name "Disable Defender" -Key "HKLM\System\CurrentControlSet\Control\WMI\Autologger\DefenderAuditLogger" -ValueName "Start" -Value 0 -Type Dword | Out-Null 
 
  # smb1 enabled 
  #Set-GPRegistryValue -Name "Disable Defender" -Key "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -ValueName "SMB1" -Value 1 -Type Dword | Out-Null 
  #  
  # move the enable-windowsoptionalfeature to both the DC and Workstation builds 
  # set smb1 = enabled in both DC and Workstations Registries ( locally )
  # set smb1 = enabled via GPO for the domain 
  # Enable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart 
  # Set-SmbServerConfiguration -EnableSMB1Protocol $true -RequireSecuritySignature $False -EnableSecuritySignature $True -Confirm:$false
  # Set-GPRegistryValue -Name "Disable Defender" -Key "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -ValueName "SMB1" -Value 1 -Type Dword | Out-Null 
  # Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" SMB1 -Type DWORD -Value 1 -Force


  # smb2 signing is enabled but not required (breakout into individual fix function)
  write-host("`n  [++] Setting GPO Registry key: Defender SMB2 Client RequireSecuritySignature")
  #reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" /v "RequireSecuritySignature" /t REG_DWORD /d "0" /f > $null
  Set-GPRegistryValue -Name "Disable Defender" -Key "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" -ValueName "RequireSecuritySignature" -Value 0 -Type Dword | Out-Null

  write-host("`n  [++] Setting GPO Registry key: Defender SMB2 Server RequireSecuritySignature")
  # reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" /v "requiresecuritysignature" /t REG_DWORD /d "0" /f > $null
  Set-GPRegistryValue -Name "Disable Defender" -Key "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -ValueName "requiresecuritysignature" -Value 0 -Type Dword | Out-Null
 
  # printer-nightmare registry keys (breakout into individual fix function)
  write-host("`n  [++] Setting GPO Registry key: PrinterNightmare")
  #reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint" /v "NoWarningNoElevationOnInstall" /t REG_DWORD /d "1" /f > $null
  Set-GPRegistryValue -Name "Disable Defender" -Key "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint" -ValueName "NoWarningNoElevationOnInstall" -Value 1 -Type Dword | Out-Null

  #reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint" /v "RestrictDriverInstallationToAdministrators" /t REG_DWORD /d "0" /f > $null
  Set-GPRegistryValue -Name "Disable Defender" -Key "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint" -ValueName "RestrictDriverInstallationToAdministrators" -Value 0 -Type Dword | Out-Null

  # set localaccounttokenfilterpolicy
  write-host("`n  [++] Setting GPO Registry key: LocalAccountTokenFilterPolicy")
  # reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\system" /v "LocalAccountTokenFilterPolicy" /t REG_DWORD /d "1" /f
  Set-GPRegistryValue -Name "Disable Defender" -Key "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\system" -ValueName "LocalAccountTokenFilterPolicy" -Value 1 -Type Dword | Out-Null

  # set alwaysinstallelevated 
  write-host("`n  [++] Setting GPO Registry key: AlwaysInstallElevated")
  # reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Installer" -v "AlwaysInstallElevated" /t REG_DWORD /d "1" /f > $null 
  Set-GPRegistryValue -Name "Disable Defender" -Key "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Installer" -ValueName "AlwaysInstallElevated" -Value 0 -Type Dword | Out-Null

  write-host("`n  [++] Setting GPO Registry key: WindowsUpdate")
  # reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" /v "NoAutoUpdate" /t REG_DWORD /d "1" /f > $null
  Set-GPRegistryValue -Name "Disable Defender" -Key "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -ValueName "NoAutoUpdate" -Value 1 -Type Dword | Out-Null

  #winrm registry key 
  # Set-GPRegistryValue -Name "WinRM" -Key "HKLM\Policies\Microsoft\Windows\WinRM\Service" -ValueName "AllowAutoConfig" -Value 1 -Type Dword | Out-Null
  
  #winrs registry key
  # Set-GPRegistryValue -Name "WinRS" -key "HKLM\Policies\Microsoft\Windows\WinRM\Service\WinRS" -ValueName "AllowRemoteShellAccess" -Value 1 -Type Dword | Out-Null

  # quality of life improvements gpo-policy pushed 
    # Dark Mode GPO 
    write-host("`n  [++] Setting GPO Registry key: Dark Theme")
    Set-GPRegistryValue -Name "Disable Defender" -Key "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize" -ValueName "AppsUseLightTheme" -Value 0 -Type Dword | Out-Null
    Set-GPRegistryValue -Name "Disable Defender" -Key "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize" -ValueName "SystemUsesLightTheme" -Value 0 -Type Dword | Out-Null
    
    # Disable screen time out and screen locker (its a lab!)
    write-host("`n  [++] Setting GPO Registry key: Disable Screenlock, timer")
    Set-GPRegistryValue -Name "Disable Defender" -Key "HKEY_CURRENT_USER\Software\Policies\Microsoft\Windows\Control Panel\Desktop\" -ValueName "ScreenSaveTimeOut" -Value 0 -Type Dword
    Set-GPRegistryValue -Name "Disable Defender" -Key "HKEY_CURRENT_USER\Software\Policies\Microsoft\Windows\Control Panel\Desktop\" -ValueName "ScreenSaveActive" -Value 0 -Type Dword
    Set-GPRegistryValue -Name "Disable Defender" -Key "HKEY_CURRENT_USER\Software\Policies\Microsoft\Windows\Control Panel\Desktop\" -ValueName "ScreenSaverIsSecure" -Value 0 -Type Dword | Out-Null

    # set ipv4 prefrence over ipv6 
    Set-GPRegistryValue -Name "Disabled Components" -Key "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters\" -ValueName "DisabledComponents" -Value 0x20 -Type Dword 
    # New-ItemProperty “HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters\” -Name “DisabledComponents” -Value 0x20 -PropertyType “DWord”
    # Set-ItemProperty “HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters\” -Name “DisabledComponents” -Value 0x20
    
  # thats all folks!
  write-host("`n  [++] New Disable Defender GPO Created, Linked and Enforced `n")
  Get-GPO -Name "Disable Defender" | New-GPLink -target "DC=MARVEL,DC=local" -LinkEnabled Yes -Enforced Yes

  write-host("`n  [++] Removing and unlinking Default Domain Policy")
  Remove-GPLink -Name "Default Domain Policy" -target "DC=$CurrentDomain,DC=local" | Out-Null 
  }
  # ---- end create_marvel_gpo

# ---- begin set_dcstaticip function  
function set_dcstaticip { 
  # get the ip address
  $IPAddress=Get-NetIPAddress -AddressFamily IPv4 -InterfaceIndex $(Get-NetConnectionProfile | Select-Object -ExpandProperty InterfaceIndex) | Select-Object -ExpandProperty IPAddress
  
  # get the adapter name
  $adapter=Get-CimInstance -Class Win32_NetworkAdapter -Property NetConnectionID,NetConnectionStatus | Where-Object { $_.NetConnectionStatus -eq 2 } | Select-Object -Property NetConnectionID -ExpandProperty NetConnectionID
  
  # split the ip address up based on the . 
  $IPByte = $IPAddress.Split(".")
  
  # first 3 octets not intrested in, only the last octet set to .250 (ip address)
  $StaticIP = ($IPByte[0]+"."+$IPByte[1]+"."+$IPByte[2]+".250") 

  # first 3 octets not intrested in, onlly the last octet set to .1 (default gateway)
  $StaticGateway = ($IPByte[0]+"."+$IPByte[1]+"."+$IPByte[2]+".1") 

  # static mask of 24 bits or 255.255.255.0
  $StaticMask = "255.255.255.0"

  write-host "$adapter $StaticIP $StaticMask $StaticGateway"
 
  netsh interface ipv4 set address name="$adapter" static $StaticIP $StaticMask $StaticGateway
  netsh interface ipv4 set dnsservers name="$adapter" static 8.8.8.8
  }
  # ---- end set_dcstaticip function  

# ---- begin set_punisher_staticip function  
function set_punisher_staticip { 
  # get the ip address
  $IPAddress=Get-NetIPAddress -AddressFamily IPv4 -InterfaceIndex $(Get-NetConnectionProfile | Select-Object -ExpandProperty InterfaceIndex) | Select-Object -ExpandProperty IPAddress
  
  # get the adapetr name
  $adapter=Get-CimInstance -Class Win32_NetworkAdapter -Property NetConnectionID,NetConnectionStatus | Where-Object { $_.NetConnectionStatus -eq 2 } | Select-Object -Property NetConnectionID -ExpandProperty NetConnectionID
   
  # split the ip address up based on the . 
  $IPByte = $IPAddress.Split(".")
   
  # first 3 octets not intrested in, only the last octet set to .250 (ip address)
  $StaticIP = ($IPByte[0]+"."+$IPByte[1]+"."+$IPByte[2]+".220") 
 
  # first 3 octets not intrested in, onlly the last octet set to .1 (default gateway)
  $StaticGateway = ($IPByte[0]+"."+$IPByte[1]+"."+$IPByte[2]+".1") 
 
  # static mask of 24 bits or 255.255.255.0
  $StaticMask = "255.255.255.0"

  write-host "$adapter $StaticIP $StaticMask $StaticGateway"
 
  netsh interface ipv4 set address name="$adapter" static $StaticIP $StaticMask $StaticGateway
  netsh interface ipv4 set dnsservers name="$adapter" static 8.8.8.8
  }
  # ---- end set_punisher_staticip function  

# ---- begin set_spiderman_staticip function  
function set_spiderman_staticip { 
  # get the ip address
  $IPAddress=Get-NetIPAddress -AddressFamily IPv4 -InterfaceIndex $(Get-NetConnectionProfile | Select-Object -ExpandProperty InterfaceIndex) | Select-Object -ExpandProperty IPAddress
  
  # get the adapetr name
  $adapter=Get-CimInstance -Class Win32_NetworkAdapter -Property NetConnectionID,NetConnectionStatus | Where-Object { $_.NetConnectionStatus -eq 2 } | Select-Object -Property NetConnectionID -ExpandProperty NetConnectionID
  
  # split the ip address up based on the . 
  $IPByte = $IPAddress.Split(".")
  
  # first 3 octets not intrested in, only the last octet set to .250 (ip address)
  $StaticIP = ($IPByte[0]+"."+$IPByte[1]+"."+$IPByte[2]+".221") 

  # first 3 octets not intrested in, onlly the last octet set to .1 (default gateway)
  $StaticGateway = ($IPByte[0]+"."+$IPByte[1]+"."+$IPByte[2]+".1") 

  # static mask of 24 bits or 255.255.255.0
  $StaticMask = "255.255.255.0"

  write-host "`n  [++] Setting $adapter to IP: $StaticIP  Subnet: $StaticMask  Gateway: $StaticGateway"
  netsh interface ipv4 set address name="$adapter" static $StaticIP $StaticMask $StaticGateway

  write-host "`n  [++]  Setting $adapter to DNS: 8.8.8.8"
  netsh interface ipv4 set dnsservers name="$adapter" static 8.8.8.8
  }  
  # ---- end set_spiderman_staticip function

function fix_dcdns {
  $IPAddress=Get-NetIPAddress -AddressFamily IPv4 -InterfaceIndex $(Get-NetConnectionProfile | Select-Object -ExpandProperty InterfaceIndex) | Select-Object -ExpandProperty IPAddress
  
  # get the adapter name
  $adapter=Get-CimInstance -Class Win32_NetworkAdapter -Property NetConnectionID,NetConnectionStatus | Where-Object { $_.NetConnectionStatus -eq 2 } | Select-Object -Property NetConnectionID -ExpandProperty NetConnectionID
  
  # split the ip address up based on the . 
  $IPByte = $IPAddress.Split(".")
  
  # first 3 octets not intrested in, only the last octet set to .250 (ip address)
  $StaticIP = ($IPByte[0]+"."+$IPByte[1]+"."+$IPByte[2]+".250") 

  # first 3 octets not intrested in, onlly the last octet set to .1 (default gateway)
  $StaticGateway = ($IPByte[0]+"."+$IPByte[1]+"."+$IPByte[2]+".1") 

  # static mask of 24 bits or 255.255.255.0
  $StaticMask = "255.255.255.0"
   
  netsh interface ipv4 set address name="$adapter" static $StaticIP $StaticMask $StaticGateway

  write-host "`n  [++] Disabling $adapter Power Management"
  Disable-NetAdapterPowerManagement -Name "$adapter"
  
  write-host "`n  [++] Setting $adapter DNS to 127.0.0.1"
  netsh interface ipv4 set dnsservers name="$adapter" static 127.0.0.1 
  
  write-host "`n  [++] Setting Ipv6 DNS to DHCP"
  netsh interface ipv6 set dnsservers "$adapter" dhcp
}

function fix_workstationdns {
  $DCDNS=(Test-Connection -comp HYDRA-DC -Count 1).ipv4address.ipaddressToString
  
  write-host("`n  [++] Found HYDRA-DC At $DCDNS")
  $adapter=Get-CimInstance -Class Win32_NetworkAdapter -Property NetConnectionID,NetConnectionStatus | Where-Object { $_.NetConnectionStatus -eq 2 } | Select-Object -Property NetConnectionID -ExpandProperty NetConnectionID
  
  write-host "`n  [++] Disabling $adapter Power Management"
  Disable-NetAdapterPowerManagement -Name "$adapter"
  
  write-host "`n  [++] Setting $adapter DNS to $DCDNS"
  netsh interface ipv4 set dnsservers name="$adapter" static $DCDNS
  
  write-host "`n  [++] Setting Ipv6 DNS to : DHCP"
  netsh interface ipv6 set dnsservers "$adapter" dhcp
  }

# ---- begin server_build function
function server_build {
  Get-ScheduledTask -TaskName ServerManager | Disable-ScheduledTask | Out-Null
  write-host("`n`n   Computer Name : $machine")
  write-host("     Domain Name : $domain")
  write-host("      OS Version : $osversion")

  if($currentname -ne "HYDRA-DC") {
      write-host("`n  Computer Name is Incorrect Setting HYDRA-DC")
      write-host("`n  - Script Run 1 of 3 - Setting the computer name to HYDRA-DC and rebooting")
      write-host("`n  AFTER The reboot run the script again! to setup the domain controller!")
      Read-Host -Prompt "`n Press ENTER to continue..."
      set_mppref  # one time run of this function on the dc build 
      set_dcstaticip
      Rename-Computer -NewName "HYDRA-DC" -Restart
      }
      elseif ($domain -ne "MARVEL.LOCAL") {
        write-host("`n  Computer name is CORRECT... Executing BuildLab Function")
        write-host("`n  Script Run 2 of 3 - AFTER The Domain Controller has been setup and configured, the system will auto-reboot")
        write-host("`n  NOTE: This Reboot will take SEVERAL MINUTES, Dont Panic! We are working hard to build your Course Domain-Controller!")
        write-host("`n  AFTER THE REBOOT run this script 1 more time and select menu option D")
        Read-Host -Prompt "`n`n Press ENTER to continue..."
        build_lab
        }
      elseif ($domain -eq "MARVEL.LOCAL" -And $machine -eq "HYDRA-DC") {
        write-host("`n Computer name and Domain are correct : Executing CreateContent Function ")
        create_labcontent
        create_marvel_gpo
        get_sharphound
        fix_dcdns 
        write-host("`n Script Run 3 of 3 - We are all done! Rebooting one last time! o7 Happy Hacking! ")
        $dcip=Get-NetIPAddress -AddressFamily IPv4 -InterfaceIndex $(Get-NetConnectionProfile | Select-Object -ExpandProperty InterfaceIndex) | Select-Object -ExpandProperty IPAddress
        write-host("`n`n Write this down! We need this in the Workstation Configruation... Domain Controller IP Address: $dcip `n`n")
        Read-Host -Prompt "`n`n Press ENTER to continue..."
        restart-computer
        }
      else { 
        write-host("Giving UP! There is nothing to do!") 
        }
      }
      # ---- end server_build function

# ---- begin git_powersploit function      
#function git_powersploit {
#  write-host("`n  [++] Git Cloning PowerSploit to $Env:windir\System32\WindowsPowerShell\v1.0\Modules\PowerSploit")
#  git clone https://github.com/PowerShellMafia/PowerSploit $Env:windir\System32\WindowsPowerShell\v1.0\Modules\PowerSploit > $null 
#  }
   # ---- end git_powersploit function

# ---- begin setup_git function
function setup_git {
  [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
  $architecture = '64-bit'
  $assetName = "Git-*-$architecture.exe"
  
  $gitHubApi = 'https://api.github.com/repos/git-for-windows/git/releases/latest'
  $response = Invoke-WebRequest -Uri $gitHubApi -UseBasicParsing
  $json = $response.Content | ConvertFrom-Json
  $release = $json.assets | Where-Object Name -like $assetName
  
  # download 
  write-host("`n  [++] Downloading $($release.name)")
  Start-BitsTransfer -Source $release.browser_download_url -Destination ".\$($release.name)" | Out-Null
  
  # install  
  write-host("`n  [++] Installing $($release.name)")
  Unblock-File -Path ".\$($release.name)"
  Start-Process .\$($release.name) -argumentlist "/silent /supressmsgboxes" -Wait  | Out-Null 
  rm .\$($release.name)  
  
  # reload environment variables 
  $env:Path = [System.Environment]::GetEnvironmentVariable("Path","Machine") + ";" + [System.Environment]::GetEnvironmentVariable("Path","User")  
  }
  # ---- end setup_git function

# ---- begin get_recon function 
function git_recon() { 
  # Put Recon in the right place (could be used on DC or Workstations) 
  write-host("`n  [++] Downloading Powershell Mafia v1.9 to C:\TCM-Academy")
  mkdir $HOME\Documents\WindowsPowerShell\Modules\Recon
  git clone https://github.com/PowerShellMafia/PowerSploit C:\tcm-academy\PowerShellMafia
  write-host("`n  [++] Copying Recon to C:\$HOME\Documents\WindowsPowerShell\Modules\Recon")
  echo D | xcopy /e /y C:\tcm-academy\PowerShellMafia\Recon $HOME\Documents\WindowsPowerShell\Modules\Recon
  }
  # ---- end git_recon function


# ---- begin workstations_common function
function workstations_common { 

  # remove all updates 
  remove_all_updates

  # download and install Git for Windows 
  setup_git 
  
  # write-host("`n  [++] Setting Registry key: FDResPub")
  # reg add "HKLM\SYSTEM\CurrentControlSet\Services\FDResPub" /f /v DependOnService /t REG_MULTI_SZ /d "RpcSs\0http\0fpdhost\0LanmanWorkstation"
  
  # install remote system administration tools
  write-host("`n  [++] Installing Remote System Administration Tools (RSAT)") 
  Add-WindowsCapability -Online -Name Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0 | Out-Null

  # install dotnet v2 - needed for powerview fix : powershell -version 2 -ep bypass 
  write-host("`n  [++] Installing .Net 2.0")
  Add-WindowsCapability -Online -Name NetFx2~~~~ | Out-Null
    
  # install dotnet v3 
  write-host("`n  [++] Installing .Net 3.0")
  Add-WindowsCapability -Online -Name NetFx3~~~~ | Out-Null 

  # download old version of Powerview so it works with course material 
  # requires .net v2 and the powershell -version 2 -ep bypass for this 
  # (course material update for this one)
  mkdir C:\TCM-ACADEMY > $null 
  write-host("`n  [++] Downloading Powerview v1.9 to C:\TCM-Academy")
  Invoke-WebRequest  https://raw.githubusercontent.com/PowerShellEmpire/PowerTools/version_1.9/PowerView/powerview.ps1 -o C:\TCM-Academy\Powerview.ps1 | Out-Null
  
  #Git PowershellMafia's Recon and drop it in $HOME\Documents\WindowsPowerShell\Modules\Recon
  # Will work for the DC wont work for the Workstation as its not logged into the domain yet... 
  # git_recon 

  # download an unzip Sharphound.zipi to C:\TCM-Academy\Sharphound
  get_sharphound 

  # download and unzip pstools.zip to c:\pstools 
  write-host("`n  [++] Downloading PSTools to C:\TCM-Academy")
  Invoke-WebRequest  https://download.sysinternals.com/files/PSTools.zip -o C:\TCM-Academy\PStools.zip | Out-Null
  Start-BitsTransfer -Source "https://download.sysinternals.com/files/PSTools.zip" -Destination "C:\TCM-Aacademy\PSTools.zip" | Out-Null
  write-host("`n  [++] Extracting PSTools to C:\PSTools")
  Expand-Archive -Force C:\TCM-Academy\PSTools.zip C:\PSTools | Out-Null 
  
  # create c:\share and smbshare
  mkdir C:\Share > $null 
  New-SmbShare -Name "Share" -Path "C:\Share" -ChangeAccess "Users" -FullAccess "Everyone" -WarningAction SilentlyContinue | Out-Null

  fix_workstationdns

  # automatically join domain using tstark
  write-host("`n Joining machine to domain Marvel.local")
  # add-computer -domainname "MARVEL.LOCAL" -username administrator -restart | Out-Null
  $domain = "MARVEL"
  $password = "Password2019!@#" | ConvertTo-SecureString -asPlainText -Force
  $username = "$domain\tstark" 
  $credential = New-Object System.Management.Automation.PSCredential($username,$password)
  Add-Computer -DomainName $domain -Credential $credential  | Out-Null 
  }
  # ---- end workstations_common function      

# ---- begin workstation_punisher function 
function workstation_punisher { 
  write-host("`n`n   Computer Name : $machine")
  write-host("     Domain Name : $domain")
  write-host("      OS Version : $osversion")

  if ($machine -ne "PUNISHER") { 
    write-host ("`n Setting the name of this machine to PUNISHER and rebooting automatically...")
    write-host (" Run this script 1 more time and select 'P' in the menu to join the domain")
    Read-Host -Prompt "`n Press ENTER to continue..."
    # set_mppref
    set_punisher_staticip 
    Rename-Computer -NewName "PUNISHER" -Restart
    }
    elseif ($machine -eq "PUNISHER") {
      workstations_common
      # Enable the administrator account locally and set password 
      Get-LocalUser -Name "Administrator" | Enable-LocalUser
      $UserAccount = Get-LocalUser -Name "Administrator"
      $UserAccountPassword = "Password1" | ConvertTo-SecureString -asPlainText -Force
      $UserAccount | Set-LocalUser -Password $UserAccountPassword

      Read-Host -Prompt "`n All done! $machine is all setup! `n Press Enter to reboot and Login as MARVEL\fcastle and Password1 "
      restart-computer 
    }
    else { write-host("Nothing to do here") }
    } 
    # ---- end workstation_punisher function 
    
# ---- begin workstation_spiderman function
function workstation_spiderman { 
  write-host("`n`n   Computer Name : $machine")
  write-host("     Domain Name : $domain")
  write-host("      OS Version : $osversion")
  
  if ($machine -ne "SPIDERMAN") {
    write-host ("`n Setting the name of this machine to SPIDERMAN and rebooting automatically...")
    write-host (" Run this script 1 more time and select 'S' in the menu to join the domain")
    Read-Host -Prompt "`n Press ENTER to continue..."
    set_mppref
    set_spiderman_staticip
    Rename-Computer -NewName "SPIDERMAN" -Restart
    }
    elseif ($machine -eq "SPIDERMAN") {
      workstations_common 
      Get-LocalUser -Name "Administrator" | Enable-LocalUser
      $UserAccount = Get-LocalUser -Name "Administrator"
      $UserAccountPassword = "Password1" | ConvertTo-SecureString -asPlainText -Force
      $UserAccount | Set-LocalUser -Password $UserAccountPassword
      #add fcastle as a local administrator on the spiderman machine 
      Add-LocalGroupMember -Group Administrators -Member Fcastle -Verbose
      Read-Host -Prompt "`n All done! $machine is all setup! `n Press Enter to reboot and Login as MARVEL\pparker and Password2 "
      restart-computer 
      }
    else { write-host("Nothing to do here") }
    } 
    # ---- end workstation_spiderman function

# ---- begin menu function
function menu {
  do {
    Write-Host "`n`n`tTCM-Academy PEH Course AD-Lab Build Menu - Select an option`n"
    Write-Host "`tPress 'D' to setup Hydra-DC Domain Controller"
    Write-host "`t(must be run 3 times)`n"
    Write-Host "`tPress 'P' to setup Punisher Workstation and join the domain Marvel.local"
    Write-host "`t(must be run 2 times)`n"
    Write-Host "`tPress 'S' to setup Spiderman Workstation and join the domain Marvel.local" 
    Write-host "`t(must be run 2 times)`n"
    Write-host "`n`t --- Independant Standalone Functions ---"
    Write-host "`n`tPress 'N' to only run the NukeDefender Function"
    Write-host "`n`tPress 'F' to Fix Disable Defender GPO Policy"
    Write-Host "`n`tPress 'K' to only run the SetSPN Function"
    Write-Host "`n`tPress 'A' to only run the ADCSCertificateAuthority Function"
    Write-Host "`n`tPress 'H' to only download sharphound.zip and extract to C:\TCM-Academy\Sharphound"
    Write-Host "`n`tPress 'X' to Exit"
    $choice = Read-Host "`n`tEnter Choice" } 
    until (($choice -eq 'P') -or ($choice -eq 'D') -or ($choice -eq 'S') -or ($choice -eq 'N') -or ($choice -eq 'F') -or ($choice -eq 'X') -or ($choice -eq 'K') -or ($choice -eq 'A') -or ($choice -eq 'H'))
    
  switch ($choice) {
    'D'{  Write-Host "`n Running... Hydra-DC domain controller"
          nukedefender 
          server_build }
    'P'{  Write-Host "`n Running... Punisher Workstation"
          nukedefender 
          workstation_punisher }
    'S'{  Write-Host "`n Running... Spiderman Workstation"
          nukedefender 
          workstation_spiderman }
    'F'{  Write-Host "`n ONLY Running... Fix My Disable Defender GPO function and exit" 
          create_marvel_gpo }          
    'N'{  Write-Host "`n ONLY Running... the NukeDefender function and exit"
          nukedefender }
    'K'{  Write-Host "`n ONLY running... Fix SetSPN Function and exit"
          fix_setspn }
    'A'{  Write-Host "`n ONLY running... Fix ADCSCertificateAuthority Function and exit"
          fix_adcsca }    
    'H'{  Write-Host "`n ONLY running... Download Sharphound.zip and extract to c:\tcm-academy"
          get_sharphound }                           
    'X'{Return}
    }
  } 

  # ---- begin menu function  

# ---- begin main
  $ErrorActionPreference = "SilentlyContinue"
  clear 
  $currentname=$env:COMPUTERNAME 
  $machine=$env:COMPUTERNAME
  $domain=$env:USERDNSDOMAIN
  $osversion=((Get-WmiObject -class Win32_OperatingSystem).Caption)

  write-host("`n`n   Computer Name : $machine")
  write-host("     Domain Name : $domain")
  write-host("      OS Version : $osversion")

  # execute function check_ipaddress test if ip address is 169.254.0.0/16 if it is.. fail and exit 
  check_ipaddress
  menu 

  #if ("$osversion" -eq "Microsoft Windows Server 2019 Standard Evaluation") 
  #  { menu }
  #  # elseif ("$osversion" -eq "Microsoft Windows Server 2022 Standard Evaluation") 
  #  # { menu }  
  #  elseif ("$osversion" -eq "Microsoft Windows Server 2019 Standard") 
  #  { menu }  
  #  elseif ("$osversion" -eq "Microsoft Windows Server 2016 Standard") 
  #  { menu }
  #  elseif ("$osversion" -eq "Microsoft Windows 10 Enterprise Evaluation") 
  #  { menu }
  #  elseif ("$osversion" -eq "Microsoft Windows 10 Enterprise 2016 LTSB")
  #  { menu }
  #  elseif ("$osversion" -eq "Microsoft Windows 10 Pro")
  #  { menu }
  #  elseif ("$osversion" -like "Home") {      
  #    write-host("`n [!!] Windows Home is unable to join a domain, please use the correct version of windows")
  #    exit 
  #    }
  #  elseif ("$osversion" -like "Education") {
  #    write-host("`n [!!] Windows Educational versions cannot be used with this lab")
  #    }
  #  elseif ("$osversion" -like "Windows 11") {
  #    write-host("`n [!!] Windows 11 cannot be used with this lab")
  #    exit 
  #    }
  #  elseif ("$osversion" -like "Windows Server 2022") {
  #    write-host("`n [!!] Windows Server 2022 cannot be used with this lab")
  #    exit 
  #    }
  #    else { write-host("Unable to find a suitable OS Version for this lab - Exiting") 
  #    }
      # ---- end main
    
