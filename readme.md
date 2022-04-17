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

 # Menu 
  - D  to install for Hydra-DC  Domain Controller , run 1 2 and 3 
  - P  to install for Punisher  Workstation #1 run 1 and 2 
  - S  to install for Spiderman Workstation #2 run 1 and 2 
  - X  to exit the menu 

# Domain Controller Instructions: 

- Domain Controller only (Windows 2019 Server)
  - Install the OS in the vm 
  - Install the Hypervisor GuestOS Additions/Tools, Reboot
  - Copy script to the vm (see instructions above on how to run the script in the vm)
  
  - Execute the instructions below in the vm 
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
      - Final reboot of the system, domin controller is complete and ready for use! 

# Workstation #1 Instructions: 

- Punisher Workstation only (Windows 10 Enterprise Client Workstation)
  - Install the OS in the vm 
  - Install the Hypervisor GuestOS Additions/Tools, Reboot
  - Copy script to the vm (see instructions above on how to run the script in the vm)
  
  - Execute the instructions below in the vm 
    - start / run / cmd (as administrator)
    - powershell -ep bypass
    - cd \to\where\you\saved\the\script
    - .\pimpmyadlab.ps1
    - You will be presented with a menu
  
  - Select Menu Option P 
    - Script must be run 2 times to fully complete Workstation installation and configuation
    - HYDRA-DC Domain Controller must already be completed and running to setup this workstation
 
  - Run 1 - Sets the name of the computer to Punisher, reboots 
    - After the reboot, Run script again, Select Menu Option P again for Run #2 
 
  - Run 2 
    - Enter the ip address of the domain controller when prompted
    - Enter the Administrator username and password for the HYDRA-DC Login when prompted to join domain Marvel.local
    - Reboots automatically
     
     - If the machine rebooted after being prompted for the Administrator Username and Password to join the domain 
       - Setup is complete! 
     
     - If the machine did not reboot automatically :
       - Is the HYDRA-DC Domain Controller running and logged into as Administrator?
       - Are all vms on NAT(vmware) or NatNetwork(virtualbox) Per course instruction?
       - Double check that you are using the correct username and password for Administrator on Hydra-DC to join the domain
       - Try again with correct logon credentials

# Workstation #2 Instructions: 

- Spiderman Workstation only (Windows 10 Enterprise Client Workstation)
  - Install the OS in the vm 
  - Install the Hypervisor GuestOS Additions/Tools, Reboot
  - Copy script to the vm (see instructions above on how to run the script in the vm)
  
  - Execute the instructions below in the vm 
    - start / run / cmd (as administrator)
    - powershell -ep bypass
    - cd \to\where\you\saved\the\script
    - .\pimpmyadlab.ps1
    - You will be presented with a menu
  
  - Select Menu Option S
    - Script must be run 2 times to fully complete Workstation installation and configuation
    - HYDRA-DC Domain Controller must already be completed and running to setup this workstation
  
  - Run 1 
    - Sets the name of the computer to Spiderman, reboots
    - After the reboot, Run script again, Select Menu Option S again for Run #2 
  
  - Run 2 
    - Enter the ip address of the domain controller when prompted
    - Enter the Adminstrator username and password to join domain Marvel.local when prompted
    - Reboots automatically
      
      - If the machine rebooted after being prompted for the Administrator Username and Password to join the domain 
        - Setup is complete! 
      
      - If the machine did not reboot automatically :
        - Is the HYDRA-DC Domain Controller running and logged into as Administrator?
        - Are all vms on NAT(vmware) or NatNetwork(virtualbox) Per course instruction?
        - Double check that you are using the correct username and password for Administrator on Hydra-DC to join the domain
        - Try again with correct logon credentials 

 Menu Option X  
 - Exits the menu 
