# Assignment-SetB

As per assignment, the single bash script has been segemnted into following major functions:
- **runAsRoot** : The function is responsible for making sure that script must be executed by a privileged user (root/in sudoers group), otherwise exit with message for the same.

- **initialize** : The function is responsible for initializing global variables here.

- **menuDisplay** : The function is responsible for displaying an operations menu, for the user to select from. The operations included here are:
    - **addUser** : This operation takes as input the **username, user's pre-generated public key and the user role i.e. dev or devops**. Based on the above inputs, a new linux user is added to the server with a default password (to be changed by user later on) and ssh is enabled using the provided public key (password based login has been disabled in serverHardening process)
 
    - **quit** : This option is used to quit the menu.

- **serverHardening** : This function has been segmeted in to below parts:
    - check and disable root user remote login
    - check and disable password based remote login. Only RSA key-pair based remote login will be allowed.
    - Ignore ICMP packets to prevent server recon (ping), other packet flooding attacks.
    - check and disable all IPv6 communication (Assuming it will not be used)
    - Limiting ssh idle connection timeout to 5 minutes
    - check and add iptable rules to allow only HTTPS(443), SSH(22) and DNS(53) traffic for both ingress and egress
    - check and add a custom ssh banner with a waring for unauthorized access.
    - check and disable default MOTD to restrict any server internal information leak
    - Allow only users present in **dev or devops group** for remote login to server

- **checkAndAddDirectoryAccess** : This function is resonsible for providing appropriate ownership and access to users in dev group to "/opt/sayurbox/sample-web-app" and "/var/log/" directories

- **logRotation** : This function is resonsible for checking and adding logrotate configuration for log files with 14 days retention, rotated daily using cron, compressing the logs with default date format

- **optimizeServer** : This function has been segmeted in to below parts:
   - check and set the server run-level to 3 (multi-user.target), to disable GUI for reducing resource consumption and attack surface
   - check and increase the soft and hard limit for max number of open files, so as not to limit connections
   - check and increase server socket accept queue buffer size
   - check and increase server TCP receive queue buffer size

**Note1** - The script could be executed in debug mode using "-d" flag. Use "-h" for help.<br /> 
**Note2** - Default password for devops role : S@yurb0x@devops<br /> 
            &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;Default password for dev role : S@yurb0x@dev

Operations Menu<br />
<img width="387" alt="Screenshot 2022-02-17 at 4 36 46 PM" src="https://user-images.githubusercontent.com/17096303/154475623-cd17452d-7320-4046-8939-6cac8186df81.png"><br />

Adding one "devops" and one "dev" role user<br />
<img width="901" alt="Screenshot 2022-02-17 at 4 41 35 PM" src="https://user-images.githubusercontent.com/17096303/154475641-909e455b-02f5-4ebe-9220-6ebaa30eed4c.png"><br />

Logs from rest of the script after user add<br />
<img width="700" alt="Screenshot 2022-02-17 at 4 43 19 PM" src="https://user-images.githubusercontent.com/17096303/154475654-e53e10f8-5f97-4c6a-8d39-20b7c01d4ee4.png"><br />
<br />Login from devops role user (Also in sudoers)<br />
<img width="500" alt="Screenshot 2022-02-17 at 4 58 23 PM" src="https://user-images.githubusercontent.com/17096303/154477665-dc5ee44d-9be2-42ac-a389-e9fcc8b8f01b.png"><br />
<br />Login from dev role user (not in sudoers)<br />
<img width="510" alt="Screenshot 2022-02-17 at 5 34 00 PM" src="https://user-images.githubusercontent.com/17096303/154478649-009dd385-f799-47fb-b8a2-aef8d2be8b56.png"><br />
<br />Directory Access for dev role <br />
<img width="477" alt="Screenshot 2022-02-17 at 5 06 55 PM" src="https://user-images.githubusercontent.com/17096303/154476022-8cac6e2a-26e4-49ed-800f-579219ab0f27.png"><br />
<br /> IPtable Rules<br />
<img width="902" alt="Screenshot 2022-02-17 at 4 59 52 PM" src="https://user-images.githubusercontent.com/17096303/154476006-27d318bc-af70-4502-a4c8-d57083561765.png">
