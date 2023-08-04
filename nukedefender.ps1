#Requires -RunAsAdministrator
 
# NukeDefender.ps1 
# Function from PimpmyADLab.ps1 exported to a single script for those that 
# dont need to rebuild the entire lab and only need the fixes provides by 
# the nukedefender function itself.  
#
# Scripted By: Dewalt
#    
# Special Thanks to :
#  ToddAtLarge (PNPT Certified) for the NukeDefender script 
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
  
    # Enable Network Discovery 
    write-host("`n  [++] Enabling Network Discovery")
    Get-NetFirewallRule -Group '@FirewallAPI.dll,-32752' |Set-NetFirewallRule -Profile 'Private, Domain' `
    -Enabled true -PassThru|select Name,DisplayName,Enabled,Profile|ft -a | Out-Null
  
    # Disable all firewalling 
    write-host("`n  [++] Disabling Windows Defender Firewalls : Public, Private, Domain")
    Set-NetFirewallProfile -Profile Domain, Public, Private -Enabled False | Out-Null

    # SET SMB SIGNING ENABLED BUT NOT REQUIRED
    write-host("`n  [++] Setting Registry Keys SMB Signing Enabled but not Required")
    reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" /v "RequireSecuritySignature" /t REG_DWORD /d "0" /f > $null
    reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" /v "requiresecuritysignature" /t REG_DWORD /d "0" /f > $null

    # SET PRINTER NIGHTMARE REGISTRY KEYS FOR CVE-2021-1675
    write-host("`n  [++] Setting Registry Keys for PrinterNightmare")
    reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint" /v "NoWarningNoElevationOnInstall" /t REG_DWORD /d "1" /f > $null
    reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint" /v "RestrictDriverInstallationToAdministrators" /t REG_DWORD /d "0" /f > $null

    }
    # ---- END NUKEDEFENDER

    # ---- BEGIN MAIN
    nukedefender 
