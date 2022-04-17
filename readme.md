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
 This script is being provided as a courtesy and is by no means intended to replace 
 or remove any direct course provided instruction. All aspects of this script have 
 been carefully planned, to replicate the lab instructed setup per PEH course material
 and provide a scripted installation.

 Disclaimer: Author assumes no liability
 
# Special Thanks to :
  - ToddAtLarge (PNPT Certified) for the NukeDefender script 
  - Yaseen (PNPT Certified) for Alpha/Beta Testing!
  - uCald4aMarine Release Candidate Testing

# Installation and usage : 
 On each machine Domain Contoller, Workstation1 and Workstation2 : 
 - Install the Operating System
 - Install the Hypervisor GuestOS-Additions/Tools
 - Reboot the vm
 - Copy pimpmyadlab.ps1 to the vm
  
Each run will require the following :
- start / run / cmd (as administrator)
- powershell -ep bypass 
- cd \to\where\you\saved\the\script
- .\pimpmyadlab.ps1
- You will be presented with a menu

 Lab build is 3 vms :
 1. Hydra-DC  (Windows 2019 Server) 
 2. Punisher  (Windows 10 Enterprise Client)
 3. Spiderman (Windows 10 Enterprise Client)


- Domain Controller only (Windows 2019 Server)
  - Install the OS in the vm 
  - Install the Hypervisor GuestOS Additions/Tools, Reboot
  - Copy script to the vm (see instructions above on how to run the script in the vm)
    - start / run / cmd (as administrator)
    - powershell -ep bypass
    - cd \to\where\you\saved\the\script
    - .\pimpmyadlab.ps1
    - You will be presented with a menu
   - Select Menu Option D 
   - Script must be run 3 times in order to fully complete Domain Contoller installation and configuration
    - Run 1 - Sets the name of the computer to Hydra-DC, reboots automatically when done
      - After the reboot, Run script again, Select Menu Option D again for Run #2 
    - Run 2 - Installs Domain Controller, Forest, etc, reboots automatically when done
      - After the reboot, Run script again, Select Menu Option D again for Run #3 
    - Run 3 - Installs the contents for the Cert-Auth, Domain, Users, SetSPN, etc and various other things
      - Final reboot of the system, domin controller is done and ready for use! 

- Punisher Workstation only (Windows 10 Enterprise Client Workstation)
  - Install the OS in the vm 
  - Install the Hypervisor GuestOS Additions/Tools, Reboot
  - Copy script to the vm (see instructions above on how to run the script in the vm)
    - start / run / cmd (as administrator)
    - powershell -ep bypass
    - cd \to\where\you\saved\the\script
    - .\pimpmyadlab.ps1
    - You will be presented with a menu
  - Select Menu Option P 
    - Script must be run 2 times to fully complete Punisher Workstation Install/Configure
    - HYDRA-DC Domain Controller must already be completed and running to setup this workstation
  - Run 1 - Sets the name of the computer to Punisher, reboots 
    - After the reboot, Run script again, Select Menu Option P again for Run #2 
  - Run 2 - Enter the ip address of the domain controller when prompted, join domain Marvel.local, reboots
    - If the machine rebooted after being prompted for the Administrator Username and Password to join the domain 
      
- Spiderman Workstation only (Windows 10 Enterprise Client Workstation)
  - Install the OS in the vm 
  - Install the Hypervisor GuestOS Additions/Tools, Reboot
  - Copy script to the vm (see instructions above on how to run the script in the vm)
    - start / run / cmd (as administrator)
    - powershell -ep bypass
    - cd \to\where\you\saved\the\script
    - .\pimpmyadlab.ps1
    - You will be presented with a menu
  - Select Menu Option S
    - Script must be run 2 times to fully complete Domain Contoller Install/Configure
    - HYDRA-DC Domain Controller must already be completed and running to setup this workstation
  - Run 1 - Sets the name of the computer to Spiderman, reboots
    - After the reboot, Run script again, Select Menu Option S again for Run #2 
  - Run 2 - Enter the ip address of the domain controller when prompted, join domain Marvel.local, reboots
    - If the machine rebooted after being prompted for the Administrator Username and Password to join the domain 

 Menu Option X  
 - Exits the menu 
