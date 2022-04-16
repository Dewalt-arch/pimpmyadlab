# pimpmyadlab.ps1 (name and repo may change its still under debate)

TCM-ACADEMY Practical Ethical Hacker Course - Active Directory Lab build script
 - DomainController (Hydra-DC) and both Workstations
   - Windows 2019 Server (Standard Evaluation - Desktop Experience) required
   - Windows 10 Enterprise Client (Standard Evaluation - Desktop Experience) required

Course Link : 
https://academy.tcm-sec.com/p/practical-ethical-hacking-the-complete-course

# Note: 
  This script is being provided as a curtosy and is by no means intended to replace 
 or remove direct course provided instruction. All aspects of this script have been 
 carefully planned out to replicate the lab instructed setup per peh course material
 and provide a scripted installation, with a number of fixes to common issues. 
 
# INSTALLATION AND USAGE : 
 
 On each machine Domain Contoller, Workstation1 and Workstation2 : 
 Install the Operating System, Insall the Hypervisor GuestOS-Additions/Tools, reboot
 Copy the script to the vm
  
  Each run will reuire : 
  start / run / cmd (as administrator)
  powershell -ep bypass 
  cd \to\where\you\saved\the\script
  .\pimpmy-tcmpeh-adlab.ps1

 Lab build is 3 vms :
 1. Hydra-DC  (Windows 2019 Server) 
 2. Punisher  (Windows 10 Enterprise Client)
 3. Spiderman (Windows 10 Enterprise Client)

 # Menu Option D 
   Domain Controller only (Windows 2019 Server)
   Script must be run 3 times in order to fully complete Domain Contoller Install/Configure
   Run 1 - Sets the name of the computer to Hydra-DC, reboots automatically when done
   Run 2 - Installs Domain Controller, Forest, etc, reboots automatically when done
   Run 3 - Installs the contents for the Cert-Auth, Domain, Users, SetSPN, etc and various other things

 # Menu Option P 
   Punisher Workstation only (Windows 10 Enterprise Client Workstation)
   Script must be run 2 times in order to fully complete Punisher Workstation Install/Configure
   HYDRA-DC Domain Controller must already be completed and running to setup this workstation
   Run 1 - Sets the name of the computer to Punisher, reboots 
   Run 2 - Set the ip address of the domain controller for workstation dns, join domain Marvel.local, reboots

 # Menu Option S 
   Spiderman Workstation only (Windows 10 Enterprise Client Workstation)
   Script must be run 2 times in order to fully complete Domain Contoller Install/Configure
   HYDRA-DC Domain Controller must already be completed and running to setup this workstation
   Run 1 - Sets the name of the computer to Spiderman, reboots
   Run 2 - Set the ip address of the domain controller for workstation dns, join domain Marvel.local, reboots

 # Menu Option X  Exists the menu 