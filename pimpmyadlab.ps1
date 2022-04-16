#Requires -RunAsAdministrator
 
# TCM-ACADEMY Practical Ethical Hacker Course - Active Directory Lab build script 
# DomainController (Hydra-DC) and Both Workstation (Punisher & Spiderman)
# https://academy.tcm-sec.com/p/practical-ethical-hacking-the-complete-course
#
# Scripted By: Dewalt  
# Special Thanks to :
#  ToddAtLarge (PNPT Certified) for the NukeDefender script 
#  Yaseen (PNPT Certified) for Alpha/Beta Testing!
#  uCald4aMarine Release Candidate Testing
# 
# Note: Script is being provided as a curtosy and is by no means intended to replace 
# or remove direct course provided instruction. All aspects of this script have been 
# carefully planned out to replicate the lab instructed setup per peh course material
# and provide a scripted installation, with a number of fixes to common issues. 
# 
# INSTALLATION AND USAGE : 
# 
# On each machine Domain Contoller, Workstation1 and Workstation2 : 
#  start / run / cmd (as administrator)
#  powershell -ep bypass 
#  cd \to\where\you\saved\the\script
#  .\pimpmy-tcmpeh-adlab.ps1
#
# Lab build is 3 vms :
# 1. Hydra-DC  (Windows 2019 Server) 
# 2. Punisher  (Windows 10 Enterprise Client)
# 3. Spiderman (Windows 10 Enterprise Client)
#
# Menu Option D - Domain Controller only (Windows 2019 Server)
# Script must be run 3 times in order to fully complete Domain Contoller Install/Configure
# Run 1 - Sets the name of the computer to Hydra-DC, reboots automatically when done
# Run 2 - Installs Domain Controller, Forest, etc, reboots automatically when done
# Run 3 - Installs the contents for the Cert-Auth, Domain, Users, SetSPN, etc and various other things
#
# Menu Option P - Punisher Workstation only (Windows 10 Enterprise Client Workstation)
# Script must be run 2 times in order to fully complete Punisher Workstation Install/Configure
# HYDRA-DC Domain Controller must already be completed and running to setup this workstation
# Run 1 - Sets the name of the computer to Punisher, reboots 
# Run 2 - Set the ip address of the domain controller for workstation dns, join domain Marvel.local, reboots
#
# Menu Option S - Spiderman Workstation only (Windows 10 Enterprise Client Workstation)
# Script must be run 2 times in order to fully complete Domain Contoller Install/Configure
# HYDRA-DC Domain Controller must already be completed and running to setup this workstation
# Run 1 - Sets the name of the computer to Spiderman, reboots
# Run 2 - Set the ip address of the domain controller for workstation dns, join domain Marvel.local, reboots
#
# Menu Option X - Exits the menu 
#

# ---- BEGIN NUKE DEFENDER FUNCTION
function nukedefender {
  $ErrorActionPreference = "SilentlyContinue"

  # DISABLE UAC, FIREWALL, DEFENDER
  write-host("`n  [++] Nuking Defender")
  reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /f /v EnableLUA /t REG_DWORD /d 0 > $null
  reg add "HKLM\System\CurrentControlSet\Services\SecurityHealthService" /v "Start" /t REG_DWORD /d "4" /f > $null

  # DISABLE DEFENDER RTP, TAMPER PROTECTIONS
  # reg delete "HKLM\Software\Policies\Microsoft\Windows Defender" /f > $null
  
  # DEFENDER AV GO BYE BYE!
  reg add "HKLM\Software\Policies\Microsoft\Windows Defender" /v "DisableAntiSpyware" /t REG_DWORD /d "1" /f > $null
  reg add "HKLM\Software\Policies\Microsoft\Windows Defender" /v "DisableAntiVirus" /t REG_DWORD /d "1" /f > $null
  reg add "HKLM\Software\Policies\Microsoft\Windows Defender\MpEngine" /v "MpEnablePus" /t REG_DWORD /d "0" /f > $null
  reg add "HKLM\Software\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "DisableBehaviorMonitoring" /t REG_DWORD /d "1" /f > $null
  reg add "HKLM\Software\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "DisableIOAVProtection" /t REG_DWORD /d "1" /f > $null
  reg add "HKLM\Software\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "DisableOnAccessProtection" /t REG_DWORD /d "1" /f > $null
  reg add "HKLM\Software\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "DisableRealtimeMonitoring" /t REG_DWORD /d "1" /f > $null
  reg add "HKLM\Software\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "DisableScanOnRealtimeEnable" /t REG_DWORD /d "1" /f > $null
  reg add "HKLM\Software\Policies\Microsoft\Windows Defender\Reporting" /v "DisableEnhancedNotifications" /t REG_DWORD /d "1" /f > $null
  reg add "HKLM\Software\Policies\Microsoft\Windows Defender\SpyNet" /v "DisableBlockAtFirstSeen" /t REG_DWORD /d "1" /f > $null
  reg add "HKLM\Software\Policies\Microsoft\Windows Defender\SpyNet" /v "SpynetReporting" /t REG_DWORD /d "0" /f > $null
  reg add "HKLM\Software\Policies\Microsoft\Windows Defender\SpyNet" /v "SubmitSamplesConsent" /t REG_DWORD /d "2" /f > $null
  reg add "HKLM\System\CurrentControlSet\Control\WMI\Autologger\DefenderApiLogger" /v "Start" /t REG_DWORD /d "0" /f > $null
  reg add "HKLM\System\CurrentControlSet\Control\WMI\Autologger\DefenderAuditLogger" /v "Start" /t REG_DWORD /d "0" /f > $null

  # DISABLE SERVICES
  write-host("`n  [++] Nuking Defender Related Services")
  schtasks /Change /TN "Microsoft\Windows\ExploitGuard\ExploitGuard MDM policy Refresh" /Disable > $null
  schtasks /Change /TN "Microsoft\Windows\Windows Defender\Windows Defender Cache Maintenance" /Disable > $null
  schtasks /Change /TN "Microsoft\Windows\Windows Defender\Windows Defender Cleanup" /Disable > $null
  schtasks /Change /TN "Microsoft\Windows\Windows Defender\Windows Defender Scheduled Scan" /Disable > $null
  schtasks /Change /TN "Microsoft\Windows\Windows Defender\Windows Defender Verification" /Disable > $null

  # DISABLE WINDOWS AUTOMATIC UPDATE
  write-host("`n  [++] Nuking Windows Update")
  reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" /v "NoAutoUpdate" /t REG_DWORD /d "1" /f > $null

  # DISABLE REMOTE-UAC ( should solved the rcp_s_access_denied issue with Impacket may need to include w/ workstations )
  write-host("`n  [++] Nuking UAC")
  reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v "LocalAccountTokenFilterPolicy" /t REG_DWORD /d "1" /f > $null

  # ENABLE ICMP ECHO IPV4 AND IPV6 (Shouldnt be needed firewall is off)
  write-host("`n  [++] Enabling ICMP ECHO on IPv4 and IPv6")
  netsh advfirewall firewall add rule name="ICMP Allow incoming V4 echo request" protocol=icmpv4:8,any dir=in action=allow > $null
  netsh advfirewall firewall add rule name="ICMP Allow incoming V6 echo request" protocol=icmpv6:8,any dir=in action=allow > $null

  # Enable Network Discovery - covers video #109 - lab update (run on both server and workstations)
  write-host("`n  [++] Enabling Network Discovery")
  Get-NetFirewallRule -DisplayGroup 'Network Discovery'|Set-NetFirewallRule -Profile 'Private, Domain' `
  -Enabled true -PassThru|select Name,DisplayName,Enabled,Profile|ft -a | Out-Null

  # Disable all firewalling - Server and Workstations
  write-host("`n  [++] Disabling Windows Defender Firewalls : Public, Private, Domain")
  Set-NetFirewallProfile -Profile Domain, Public, Private -Enabled False | Out-Null
  }
  # ---- END NUKEDEFENDER

# ---- BEGIN BUILD_LAB
function build_lab {
  $ErrorActionPreference = "SilentlyContinue"

  # INSTALL AD-DOMAIN-SERVICES
  write-host("`n  When prompted you are being logged out simply click the Close button")
  write-host("`n  [++] Installing Module Active Directory Domain Services (ADDS)")
  Install-windowsfeature -name AD-Domain-Services -IncludeManagementTools -WarningAction SilentlyContinue | Out-Null

  # IMPORT ACTIVEDIRECTORY MODULE
  write-host("`n  [++] Importing Module ActiveDirectory")
  Import-Module ActiveDirectory -WarningAction SilentlyContinue | Out-Null

  # INSTALL ADDS
  write-host("`n  [++] Installing ADDS Domain : Marvel.local ")
  Install-ADDSDomain -SkipPreChecks -ParentDomainName MARVEL -NewDomainName local -NewDomainNetbiosName MARVEL `
  -InstallDns -SafeModeAdministratorPassword (Convertto-SecureString -AsPlainText "P@$$w0rd!" -Force) -Force -WarningAction SilentlyContinue | Out-Null

  # CREATE ADDS FOREST
  write-host("`n  [++] Deploying Active Directory Domain Forest in MARVEL.local")
  Install-ADDSForest -SkipPreChecks -CreateDnsDelegation:$false -DatabasePath "C:\Windows\NTDS" `
  -DomainMode "WinThreshold" -DomainName "MARVEL.local" -DomainNetbiosName "MARVEL" `
  -ForestMode "WinThreshold" -InstallDns:$true -LogPath "C:\Windows\NTDS" -NoRebootOnCompletion:$false `
  -SysvolPath "C:\Windows\SYSVOL" -Force:$true `
  -SafeModeAdministratorPassword (Convertto-SecureString -AsPlainText "P@$$w0rd!" -Force) -WarningAction SilentlyContinue | Out-Null

  write-host("`n  Note: Do NOT REBOOT MANUALLY - Let me reboot on my own! I am A BIG COMPUTER NOW!! I GOT THIS!! `n")
  }
  # ---- END BUILD_LAB

# ---- BEGIN CREATE_LABCONTENT 
function create_labcontent {
  $ErrorActionPreference = "SilentlyContinue"
  
  # INSTALL AD-CERTIFICATE SERVICES
  write-host("`n  [++] Installing Active Directory Certificate Services")
  Add-WindowsFeature -Name AD-Certificate -IncludeManagementTools -WarningAction SilentlyContinue | Out-Null
  
  # INSTALL AD-CERTIFICATE AUTHORITY
  write-host("`n  [++] Installing Active Directory Certificate Authority")
  Add-WindowsFeature -Name Adcs-Cert-Authority -IncludeManagementTools -WarningAction SilentlyContinue | Out-Null

  # CONFIGURE AD-CERTIFICATE AUTHORITY
  write-host("`n  [++] Configuring Active Directory Certificate Authority")
  Install-AdcsCertificationAuthority -CAType EnterpriseRootCa -CryptoProviderName "RSA#Microsoft Software Key Storage Provider" `
  -KeyLength 2048 -HashAlgorithmName SHA1 -ValidityPeriod Years -ValidityPeriodUnits 99 -WarningAction SilentlyContinue -Force | Out-Null

  # SETUP REMOTE MANAGEMENT FEATURE
  write-host("`n  [++] Installing Remote System Administration Tools (RSAT)")
  Add-WindowsCapability -Online -Name Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0 -WarningAction SilentlyContinue | Out-Null

  # INSTALL RSAT-ADCS AND RSAT-ADCS-MANAGEMENT
  write-host("`n  [++] Installing RSAT-ADCS and RSAT-ADCS-Management")
  Add-WindowsFeature RSAT-ADCS,RSAT-ADCS-mgmt -WarningAction SilentlyContinue | Out-Null

  # SHARED FOLDER SERVER AND WORKSTATION BOTH
  write-host("`n  [++] Creating Share C:\Share\hackme - Permissions Everyone FullAccess")
  mkdir C:\Share\hackme > $null
  New-SmbShare -Name "hackme" -Path "C:\Share\hackme" -ChangeAccess "Users" -FullAccess "Everyone" -WarningAction SilentlyContinue | Out-Null

  # SET SMB SIGNING ENABLED BUT NOT REQUIRED
  write-host("`n  [++] Setting Registry Keys SMB Signing Enabled but not Required")
  reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" /v "RequireSecuritySignature" /t REG_DWORD /d "0" /f > $null
  reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" /v "requiresecuritysignature" /t REG_DWORD /d "0" /f > $null

  # SET PRINTER NIGHTMARE REGISTRY KEYS FOR CVE-2021-1675
  write-host("`n  [++] Setting Registry Keys for PrinterNightmare")
  reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint" /v "NoWarningNoElevationOnInstall" /t REG_DWORD /d "1" /f > $null
  reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint" /v "RestrictDriverInstallationToAdministrators" /t REG_DWORD /d "0" /f > $null

  #Get-DNSClientServerAddress
  $adapter=Get-CimInstance -Class Win32_NetworkAdapter -Property NetConnectionID,NetConnectionStatus | Where-Object { $_.NetConnectionStatus -eq 2 } | Select-Object -Property NetConnectionID -ExpandProperty NetConnectionID
  write-host("`n  [++] Setting DNS Server to 127.0.0.1 on interface $adapter")
  Set-DNSClientServerAddress "$adapter" -ServerAddresses ("127.0.0.1") | Out-Null

  # NEED TO DO:
  # ADMINISTRATOR : PASSWORD IS P@$$w0rd! PER COURSE INSTRUCTION... CHANGE IT?
  # MAY CREATE TOO MUCH CONFUSION AS THE USER IS GOING TO INSTALL THE OS AND SET THE
  # PASSWORD FOR ADMINISTRATOR HOLD ON THIS IDEA

  # CREATE USER PETER PARKER (PPARKER) AND ASSIGN GROUPS
  New-ADUser -Name "Peter Parker" -GivenName "Peter" -Surname "Parker" -SamAccountName "pparker" `
  -UserPrincipalName "pparker@$Global:Domain -Path DC=marvel,DC=local" `
  -AccountPassword (ConvertTo-SecureString Password2 -AsPlainText -Force) `
  -PasswordNeverExpires $true -PassThru | Enable-ADAccount  | Out-Null
  Write-Host "`n  [++] User: Peter Parker added, Logon: pparker Password: Password2"
  Write-Host "        Adding Peter Parker to Marvel.local Groups: Domain Users"

  # CREATE USER FRANK CASTLE (FCASTLE) AND ASSIGN GROUPS
  New-ADUser -Name "Frank Castle" -GivenName "Frank" -Surname "Castle" -SamAccountName "fcastle" `
  -UserPrincipalName "fcastle@$Global:Domain -Path DC=marvel,DC=local" `
  -AccountPassword (ConvertTo-SecureString Password1 -AsPlainText -Force) `
  -PasswordNeverExpires $true -PassThru | Enable-ADAccount  | Out-Null

  # IF THE RPC_S_ACCESS_DENIED IS FIXED BY THE REG KEY FCASTLE NO LONGER NEEDS TO BE A DOMAIN ADMIN
  Add-ADGroupMember -Identity "Domain Admins" -Members fcastle  | Out-Null
  Write-Host "`n  [++] User: Frank Castle added, Logon: fcastle Password: Password1"
  Write-Host "        Adding Frank Castle to Marvel.local Groups: Domain Users, Domain Admins"

  # CREATE USER TONY STARK
  New-ADUser -Name "`n  [++] User: Tony Stark" -GivenName "Tony" -Surname "Stark" -SamAccountName "tstark" `
  -UserPrincipalName "tstark@$Global:Domain -Path DC=marvel,DC=local" `
  -AccountPassword (ConvertTo-SecureString Password2019!@# -AsPlainText -Force) `
  -PasswordNeverExpires $true -PassThru | Enable-ADAccount | Out-Null

  Add-ADGroupMember -Identity "Administrators" -Members tstark
  Add-ADGroupMember -Identity "Domain Admins" -Members tstark
  Write-Host "`n  [++] User: Tony Stark added, Logon: tstark Password: Password2019!@#"
  Write-Host "        Adding Tony Stark to Marvel.local Groups: Administrators, Domain Admins"

  # CREATE USER SQL SERVICE (SQLSERVICE) AND ASSIGN GROUPS (SQLSERVICE)
  New-ADUser -Name "SQL Service" -GivenName "SQL" -Surname "Service" -SamAccountName "sqlservice" `
  -UserPrincipalName "sqlservice@$Global:Domain -Path DC=marvel,DC=local" `
  -AccountPassword (ConvertTo-SecureString MYpassword123$ -AsPlainText -Force) `
  -PasswordNeverExpires $true -Description "Password is MYpassword123#" -PassThru | Enable-ADAccount | Out-Null

  Add-ADGroupMember -Identity "Administrators" -Members sqlservice | Out-Null
  Add-ADGroupMember -Identity "Domain Admins" -Members sqlservice | Out-Null
  Add-ADGroupMember -Identity "Enterprise Admins" -Members sqlservice | Out-Null
  Add-ADGroupMember -Identity "Group Policy Creator Owners" -Members sqlservice | Out-Null
  Add-ADGroupMember -Identity "Schema Admins" -Members sqlservice | Out-Null
  Write-Host "`n  [++] User: SQL Service added, Logon Name: sqlservice Password: MYpassword123#" 
  Write-Host "        Adding SQLService to Marvel.local Groups: Administrators, Domain Admins, Enterprise Admins, Group Policy Creator Owners, Schema Admins"

  # SETSPN FOR USER SQLSERVICE
  # DELETE EXISTING SPN
  write-host("`n  [++] Deleting Existing SPNs")
  setspn -D SQLService/MARVEL.local HYDRA-DC > $null
  setspn -D SQLService/Marvel.local MARVEL\SQLService > $null
  setspn -D HYDRA-DC/SQLService.MARVEL.local:60111 MARVEL\SQLService > $null
  setspn -D MARVEL/SQLService.Marvel.local:60111 MARVEL\SQLService > $null
  setspn -D DomainController/SQLService.MARVEL.Local:60111 MARVEL\SQLService > $null

  # ADD THE NEW SPN
  write-host("`n  [++] Adding SPNs")
  setspn -A HYDRA-DC/SQLService.MARVEL.local:60111 MARVEL\SQLService > $null
  setspn -A SQLService/MARVEL.local  MARVEL\SQLService > $null
  setspn -A DomainController/SQLService.MARVEL.local:60111 MARVEL\SQLService > $null

  # CHECK BOTH MACHINE AND DOMAIN
  write-host("`n  [++] Checking Local Hydra-DC SPN")
  setspn -L HYDRA-DC
  write-host("`n  [++] Checking MARVEL\SQLService SPN")
  setspn -L MARVEL\SQLService

  # CREATE OU=GROUPS MOVE ALL EXISTING GROUPS INTO OU=GROUPS,DC=MARVEL,DC=LOCAL
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
  # ---- END CREATE_LABCONTENT

# ---- BEGIN SERVER_BUILD
function server_build {
  $currentname="$env:COMPUTERNAME"
  $machine="$env:COMPUTERNAME"
  $domain="$env:USERDNSDOMAIN"

  write-host("`n`n  Computer Name is : $machine")
  write-host("    Domain Name is : $domain")

  if($currentname -ne "HYDRA-DC") {
      write-host("`n  Computer Name is Incorrect Setting HYDRA-DC")
      write-host("`n  - Script Run 1 of 3 - Setting the computer name to HYDRA-DC and rebooting")
      write-host("`n  AFTER The reboot run the script again! to setup the domain controller!")
      Read-Host -Prompt "`n Press ENTER to continue..."
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
          write-host("`n Script Run 3 of 3 - We are all done! Rebooting one last time! o7 Happy Hacking! ")
          $dcip=Get-NetIPAddress -AddressFamily IPv4 -InterfaceIndex $(Get-NetConnectionProfile | Select-Object -ExpandProperty InterfaceIndex) | Select-Object -ExpandProperty IPAddress
          write-host("`n`n Write this down! We need this in the Workstation Configruation... Domain Controller IP Address: $dcip `n`n")
          Read-Host -Prompt "`n`n Press ENTER to continue..."
          Restart-Computer
          }
        else {
        write-host("Giving UP! There is nothing to do!") }
      }
      # ---- END SERVER_BUILD

# ---- BEGIN WORKSTATION_PUNISHER
  function workstation_punisher { 
  $currentname="$env:COMPUTERNAME"
  $machine="$env:COMPUTERNAME"
  $domain="$env:USERDNSDOMAIN"

  write-host("Computer Name is : $machine")
  write-host("  Domain Name is : $domain")

  if ($machine -ne "PUNISHER") {
    write-host ("`n Setting the name of this machine to PUNISHER and rebooting automatically...")
    write-host (" Run this script 1 more time and select 'P' in the menu to join the domain")
    Read-Host -Prompt "`n Press ENTER to continue..."
    Rename-Computer -NewName "PUNISHER" -Restart
  }
  elseif ($machine -eq "PUNISHER") {
    mkdir C:\Share
    New-SmbShare -Name "Share" -Path "C:\Share" -ChangeAccess "Users" -FullAccess "Everyone" -WarningAction SilentlyContinue | Out-Null
    $DCDNS=Read-Host "`n Enter the IP Address of the HYDRA-DC Domain Controller here and press enter "
    $adapter=Get-CimInstance -Class Win32_NetworkAdapter -Property NetConnectionID,NetConnectionStatus | Where-Object { $_.NetConnectionStatus -eq 2 } | Select-Object -Property NetConnectionID -ExpandProperty NetConnectionID
    write-host(" Setting DNS Server to $DCDNS on adapter $adapter")
    Set-DNSClientServerAddress "$adapter" -ServerAddresses ("$DCDNS")
    add-computer -domainname "MARVEL.LOCAL" -restart | Out-Null
  }
  else { write-host("Nothing to do here") }
  } 
  # ---- END WORKSTATION_PUNISHER
    
# ---- BEGIN WORKSTATION_SPIDERMAN
   function workstation_spiderman { 
    $currentname="$env:COMPUTERNAME"
    $machine="$env:COMPUTERNAME"
    $domain="$env:USERDNSDOMAIN"
  
    write-host("Computer Name is : $machine")
    write-host("  Domain Name is : $domain")
  
    if ($machine -ne "SPIDERMAN") {
      write-host ("`n Setting the name of this machine to SPIDERMAN and rebooting automatically...")
      write-host (" Run this script 1 more time and select 'S' in the menu to join the domain")
      Read-Host -Prompt "`n Press ENTER to continue..."
      Rename-Computer -NewName "SPIDERMAN" -Restart
    }
    elseif ($machine -eq "SPIDERMAN") {
      mkdir C:\Share
      New-SmbShare -Name "Share" -Path "C:\Share" -ChangeAccess "Users" -FullAccess "Everyone" -WarningAction SilentlyContinue | Out-Null
      $DCDNS=Read-Host "`n Enter the IP Address of the HYDRA-DC Domain Controller here and press enter "
      write-host("$DCDNS")
      $adapter=Get-CimInstance -Class Win32_NetworkAdapter -Property NetConnectionID,NetConnectionStatus | Where-Object { $_.NetConnectionStatus -eq 2 } | Select-Object -Property NetConnectionID -ExpandProperty NetConnectionID
      write-host(" Setting DNS Server to $DCDNS on adapter $adapter")
      Set-DNSClientServerAddress "$adapter" -ServerAddresses ("$DCDNS")
      add-computer -domainname "MARVEL.LOCAL" -restart | Out-Null
    }
    else { write-host("Nothing to do here") }
    } 
    # ---- END WORKSTATION_SPIDERMAN

  # ---- BEGIN MAIN
    $ErrorActionPreference = "SilentlyContinue"
    do {
    clear
    Write-Host "`n`n`tTCM-Academy PEH Course AD-Lab Build Menu - Select an option`n"
    Write-Host "`tPress 'D' to setup Hydra-DC Domain Controller"
    Write-host "`t(must be run 3 times)`n"
    Write-Host "`tPress 'P' to setup Punisher Workstation and join the domain Marvel.local"
    Write-host "`t(must be run 2 times)`n"
    Write-Host "`tPress 'S' to setup Spiderman Workstation and join the domain Marvel.local" 
    Write-host "`t(must be run 2 times)`n"
    Write-Host "`tPress 'X' to Exit"
    $choice = Read-Host "`n`tEnter Choice" } until (($choice -eq 'P') -or ($choice -eq 'D') -or ($choice -eq 'S') -or ($choice -eq 'X'))

    switch ($choice) {
      'D'{  Write-Host "`nYou have selected Hydra-DC domain controller"
            nukedefender 
            server_build }
      'P'{  Write-Host "`nYou have selected Punisher Workstation"
            nukedefender 
            workstation_punisher }
      'S'{  Write-Host "`nYou have selected Spiderman Workstation"
            nukedefender 
            workstation_spiderman }
      'X'{Return}
    }
    # ---- END MAIN 
