# PimpmyADLab.ps1
  (note: name and repo may change it is still under debate)

TCM-Academy Practical Ethical Hacker Course - Active Directory Lab build script
- Course Link : https://academy.tcm-sec.com/p/practical-ethical-hacking-the-complete-course
 
Requirements : 
- DomainController (Hydra-DC) 
    - Windows 2019 Server (Standard Evaluation - Desktop Experience) required
 
- Workstations 
    - Windows 10 Enterprise Client (Standard Evaluation - Desktop Experience) required

# Note: 
 Disclaimer: Author assumes zero liability for any damages in any form. 

 This script is provided as a courtesy in addition to, and is by no means intended 
 to replace or remove any direct course provided instruction. All aspects of this 
 script have been carefully planned, to replicate the lab instructed setup per 
 TCM Academy/PEH course material and provide a scripted installation.  
 
 The function NukeDefender.ps1 has also been provided as a separate script
 and menu functionality added to PimpmyADLab.ps1 for those that just need to 
 NukeDefender only and not rebuild the entire lab.  

# Special Thanks to :
  - ToddAtLarge (PNPT Certified) for the NukeDefender script 
  - Yaseen (PNPT Certified) for Alpha/Beta Testing!

# Code Contributors
  - jmeliendrez  https://github.com/jmeliendrez
  - wodensec     https://github.com/WodenSec

# Installation and usage : 
 On each machine Domain Contoller, Workstation1 and Workstation2 : 
 - Install the Operating System
 - Install the Hypervisor GuestOS-Additions/Tools
 - Reboot the vm
  
Each run will require the following :
- start / run / cmd (as administrator)
- powershell -ep bypass 
 - Copy pimpmyadlab.ps1 to the vm or wget the file directly to that machine:
 
   wget https://raw.githubusercontent.com/Dewalt-arch/pimpmyadlab/main/pimpmyadlab.ps1 -O pimpmyadlab.ps1

   Once the script has been copied or downloaded to the vm this step is now not required

- cd \to\where\you\saved\the\script 
- .\pimpmyadlab.ps1

- You will be presented with a menu

 Lab build is 3 vms :
 1. Hydra-DC  (Windows 2019 Server) 
 2. Punisher  (Windows 10 Enterprise Client)
 3. Spiderman (Windows 10 Enterprise Client)

 # Menu 
  - **D**  to install for Hydra-DC  Domain Controller, run 1 2 and 3 
  - **P**  to install for Punisher  Workstation #1 run 1 and 2 
  - **S**  to install for Spiderman Workstation #2 run 1 and 2 
  - **N**  to ***only*** run the Nukedefender function and exit
  - **H**  to only Download and extract sharphound.zip and extract sharphound.exe
  - **X**  to exit the menu 

# Updated June 10, 2023
 - added function get_sharphound to dc and workstation setup
 - added standalone Menu option H 

# Domain Controller Instructions: 
 HYDRA-DC Domain Controller 
 (Windows 2019 Server, Standard Eval Desktop Experience)

- Domain Controller only (Windows 2019 Server)
  - Install the OS in the vm 
  - Install the Hypervisor GuestOS Additions/Tools, Reboot
    - Instructions on how to wget the script directly to the vm are located above
  
  - Select Menu Option **D** 
  - Script must be run ***3 times*** in order to fully complete Domain Controller installation and configuration
   
  - ***Run 1*** - Sets the name of the computer to Hydra-DC, reboots automatically when done
    - After the reboot, Run script again, Select Menu Option D for Run #2 
   
  - ***Run 2*** - Installs Domain Controller, Forest, etc, reboots automatically when done
    - After the reboot, Run script again, Select Menu Option D for Run #3 
   
  - ***Run 3*** - Installs the contents for the Cert-Auth, Domain, Users, SetSPN, etc and various other things
    - Final reboot of the system, domain controller is complete and ready for use! 

# Workstation #1 Instructions: 
 Punisher Workstation only (Windows 10 Enterprise Client Workstation)

  - HYDRA-DC Domain Controller must already be completed and running to setup this workstation

  - Install the OS in the vm 
  - Install the Hypervisor GuestOS Additions/Tools, Reboot
  - Copy script to the vm
    - Instructions on how to wget the script directly to the are is located above

  - Select Menu Option **P** 
    - Script must be run ***2 times*** to fully complete Workstation installation and configuation
      
  - ***Run 1*** - Sets the name of the computer to Punisher, reboots 
    - After the reboot, Run script again, Select Menu Option P for Run #2 

  - ***Run 2*** 
    - Automatically acquires the ip address of HYDRA-DC and assigns that ip to the DNS Configuration
    - Automatically joins the Marvel domain
    - Reboots automatically
     
  - If the workstation vm rebooted automatically
    - Setup is complete! 
     
  - If the machine did not reboot automatically :
    - Is the HYDRA-DC Domain Controller running and logged into as Administrator?
    - Are all vms on NAT(vmware) or NatNetwork(virtualbox) Per course instruction?
    - Double check your network setup in the hypervisor and re-run the script if it fails

    
# Workstation #2 Instructions:
 Spiderman Workstation only (Windows 10 Enterprise Client Workstation)

  - HYDRA-DC Domain Controller must already be completed and running to setup this workstation

  - Install the OS in the vm 
  - Install the Hypervisor GuestOS Additions/Tools, Reboot
  - Copy script to the vm
    - Instructions on how to wget the script directly to the vm are located above

  - Select Menu Option **S**
    - Script must be run 2 times to fully complete Workstation installation and configuation
      
  - ***Run 1*** 
    - Sets the name of the computer to Spiderman, reboots
    - After the reboot, Run script again, Select Menu Option S for Run #2 
  
  - ***Run 2*** 
    - Automatically acquires the ip address of HYDRA-DC and assigns that ip to the DNS Configuration
    - Automatically joins the Marvel domain
    - Reboots automatically
      
  - If the workstation vm rebooted automatically 
    - Setup is complete! 
      
  - If the machine did not reboot automatically :
    - Is the HYDRA-DC Domain Controller running and logged into as Administrator?
    - Are all vms on NAT(vmware) or NatNetwork(virtualbox) Per course instruction?
    - Double check your network setup in the hypervisor and re-run the script if it fails 


# Revision history 

# Revision 2.0.3 
  - local administrator on both spiderman and punisher activated and password set to Password1 

# Revision 2.0.2 
  - local administrator account enabled on the punisher machine and password set to Password1

# Revision 2.0.1 
  - added regsitry key to enable rdp in the gpo policy

# Revision 2.0.0
  - changes to setting the network ip, gateway, subnet, dns no longer using a powershell array
  - added registry keys AppsUseLightTheme and SystemUsesLightTheme = 0 
  - reworked dc, punisher, and spiderman setups
  - disable network card power management on all machines

# Revision 1.0.8 
  - fix_setspn function enhancement (updated)
  - function now dynamically acquires the machine name and domain-name
    instead of set to static values of "hydra-dc" and "marvel" and will now 
    work with any machine name and domain name now  
  - added check_ip function and fails if ip is 169.254
  - revision history moved to the bottom of the readme.md 

# Revision 1.0.7
  - create_marvel_gpo function updated to add more support for the fix gpo menu option F
   - no longer statically sets "marvel" as the domain name
   - will now work with any domain name that is currently running

# Revision 1.0.6 
  - Correction to GPO Policy, was linked but not enforced 
  - GPO Policy Disable Defender is now Enforced  

# Revision 1.0.5 
  - SetSPN has been broken out into its own function and added as a 
    menu item "Q" to only run this function and exit 
  - ADCSCertificateAuthority has been broken out into its own function
    and added as menu option A to only run this function and exit

# Revision 1.0.4 
  - Disable Defender Group Policy Object is now created with all options 
    from NukeDefender and all options from the build_lab function 
    - removes any existing "Disable Defender" Policy linked to the Marvel.local domain
    - creates a new "Disable Defender" Policy
    - sets all settings
    - Links GPO Policy to Marvel.local domain and Enforces policy 
      
# Revision 1.0.3 
  - Any and all Windows Updates will be removed automatically on 
    - Domain controller Hydra-DC
    - Workstations : Punisher & Spiderman

  Domain Controller Updates :   
  - Added autoconfiguration of DC to static ip instead of dhcp
    - ip will always be x.x.x.250
    - Default gateway automatically set to x.x.x.1 for the same network ip range  
    - Subnet set to 24 masked bits 255.255.255.0
    - temporary dns of 8.8.8.8 set for installation until after ADCS is installed
    - after adcs is installed dns is set to 127.0.0.1

  Workstations Updates (Punisher & Spiderman)
  - Added autoconfiguration of Punisher to static ip instead of dhcp 
    - Punisher  IP address will always be x.x.x.220
    - Spiderman IP address will always be x.x.x.221 
    - Default Gateway automatically set to x.x.x.1 for the same network ip range 
    - Subnet set to 24 masked bits 255.255.255.0
    - temporary dns of 8.8.8.8 set for installation until final configuration (run 2)
    - after run 2 of the script dns is set to HYDRA-DC's Ip address 

# Revision 1.0.2 
  - Moved items common to both workstations to a common function workstations_common 
  
  - Added .Net 2.0 for Powershell -v 2 -ep bypass for Powerview.Ps1 
  
  - Downloads Powerview.ps1 v1.9 (older version) to \TCM-Academy\Powerview.ps1 
    - Loading powerview will be : 
    - cmd (as administrator)
    - powerview -version 2 -ep bypass 
    - . c:\tcm-academy\Powerview.ps1
      - Get-Net* Functions should now work normally per course instruction
  
  - Added PSTools download (quality of life improvement)
    - PSTools unzipped to C:\PSTools 
    
  - Added Function to download and install latest version of git from github
    - function is currently disabled
    
  - Added autodetection of domain controller ip address 
    - automatically sets dns configuration on the workstation
    - eliminates prompting the student for the ip address of the domain controller
    - removed prompt to enter ip address of the domain controller 

  - Added auto join of the domain marvel.local 
    - Removed prompt to join the domain, will be done automatically now

  - Added Git Clone of PowershellMafia Powersploit 
    - cloned to $Env:windir\System32\WindowsPowerShell\v1.0\Modules\PowerSploit
    - powershell -version 2 -ep bypass 
    - Import-module $Env:windir\System32\WindowsPowerShell\v1.0\Modules\PowerSploit\Recon
    - Get-Net* commands should now work
    
  - Minor code cleanup
  
# Revision 1.0.1a
  - Added OS Version to on-screen display above the menu 
  - Added OS Detection, script will fail if it finds any of the following
    - "Windows 11", "Home", "Education" or "Server 2022"    

 
