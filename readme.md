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

Menu Option D 
- Domain Controller only (Windows 2019 Server)
  - Install the OS in the vm 
  - Install the Hypervisor GuestOS Additions/Tools, Reboot
  - Copy script to the vm (see instructions above on how to run the script in the vm)
- Script must be run 3 times in order to fully complete Domain Contoller installation and configuration
  - Run 1 - Sets the name of the computer to Hydra-DC, reboots automatically when done
  - Run 2 - Installs Domain Controller, Forest, etc, reboots automatically when done
  - Run 3 - Installs the contents for the Cert-Auth, Domain, Users, SetSPN, etc and various other things

Menu Option P 
- Punisher Workstation only (Windows 10 Enterprise Client Workstation)
  - Install the OS in the vm 
  - Install the Hypervisor GuestOS Additions/Tools, Reboot
  - Copy script to the vm (see instructions above on how to run the script in the vm)
- Script must be run 2 times in order to fully complete Punisher Workstation Install/Configure
  - HYDRA-DC Domain Controller must already be completed and running to setup this workstation
  - Run 1 - Sets the name of the computer to Punisher, reboots 
  - Run 2 - Set the ip address of the domain controller for workstation dns, join domain Marvel.local, reboots

Menu Option S 
- Spiderman Workstation only (Windows 10 Enterprise Client Workstation)
  - Install the OS in the vm 
  - Install the Hypervisor GuestOS Additions/Tools, Reboot
  - Copy script to the vm (see instructions above on how to run the script in the vm)
- Script must be run 2 times in order to fully complete Domain Contoller Install/Configure
  - HYDRA-DC Domain Controller must already be completed and running to setup this workstation
  - Run 1 - Sets the name of the computer to Spiderman, reboots
  - Run 2 - Set the ip address of the domain controller for workstation dns, join domain Marvel.local, reboots

 Menu Option X  
 - Exits the menu 
