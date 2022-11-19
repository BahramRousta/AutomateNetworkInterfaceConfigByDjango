# NetworkManagment
This application is based on ubuntu version 22.04 and use ssh-key for connect to devices and executing scripts. In first step install openssh-server and modify sshd_config. Set "PermitRootLogin" to "yes" and restart sshd service. Set passwd and mkdir ".ssh" for "root" user to access copy ssh public key from admin device. At the end install nmap. 
