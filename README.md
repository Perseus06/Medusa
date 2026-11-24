Medusa:
----------

Medusa is a worm targeting endpoints with Windows OS, using the SMB protocol for propagating itself across the LAN. Each time executed, Medusa will propagate to one computer only in the LAN, which (as i like to believe) gives the worm additional effect of mystery and making it quieter. The malware is written in pure C and using the Windows API and the winsock library (ws2_32.dll).

For making itself look as a legitimate executable, Medusa disguises itself as an update for Microsoft edge browser (msedge).


### Medusa's attack flow:

Firstly the worm has to arrive to a computer in the LAN. This is prior to the attack of Medusa itself, and can be done via email, DOK, phishing, etc. From the moment Medusa is installed and executed on one computer in the LAN, it is independent and requires no intervention of the attacker. Those are the six phases of Medusa's attack flow:


#### 1. Little privilege escalation:

The first step is trying to achieve the SeDebug privilege. This privilege allows the malware to access the memory of all the running processes in the OS, including secured sensitive processes (like winlogon.exe). This is the only step which is not necessary but a bonus. If the achieving of the SeDebug fails, the worm will continue to run regularly. Achieving SeDebug depends on being executed with local administrator privileges, which will not happen always and that's fine.


#### 2. Message to victim:

print to the terminal a message that tells the victim the updating process is starting.


#### 3. Network scanning using ICMP:

Medusa uses ICMP to scan the whole LAN (x.x.x.0/24). The worm sends each possible IP an echo request, in hope for receiving an echo response. If echo response had arrived, Medusa checks the TTL of the packet to determine if it came from a windows computer or not (TTL should be 65-128). When detected echo response with good TTL value, the scanning is stopped and this IP address will be the next victim Medusa will propagate to. If no more windows computers were found, Medusa gives up over propagation and moves straight to the payload (phase 5 in this explanation).

The network scanning is pretty low level - Medusa uses a raw socket (only IP layer is configured), and builds and analyzes by itself the ICMP header of the packets (the header is represented as a struct in the code of Medusa). That's definitely wasn't a simple mission :)


#### 4. Propagation using SMB brute force:

This step is the one making the worm propagate to remote computers in the LAN. After finding IP of windows computer in the LAN, Medusa will try to connect to the c$ share of this computer using the SMB protocol. The c$ is a default share exists on every windows computer, that allows to remotely connect to the C: drive. The connection to c$ relies on username and password for local account on the remote computer. Therefore, Medusa starts a brute force over SMB, guessing usernames and passwords as well. When credentials to existing user are found, Medusa uses the connection to the c$ for transferring itself to the remote computer. Medusa will place its executable in the desktop so the victim will easily see it and as a result click it (the desktop is available from the c$ because the desktop is in the C: drive). Of course medusa has to copy also the usernames and passwords files to the public documents folder of the victim, using the opened c$ share.

If the SMB connection had failed - due to network error or lack of credentials (brute force failure) - the worm gives up over that specific victim and returns to phase 3 in order to find another victim. If another windows computer is found in the new scanning, the worm will execute phase 4 on it as well.


#### 5. Remote and local persistency:

In addition to copying the worm to the remote desktop of the victim, the worm also make sure to copy itself to the remote system startup folder of the victim (deep under programdata). That way the worm ensures it will be executed on the computer of the victim, even if the victim won't click on the file itself - it will be executed from the startup folder. The copying is done using the same c$ share opened at phase 4. After this, the c$ share is closed.

At this point the propagation had ended because the malware is on the desktop of the next victim, or because the propagation process had failed. Therefore, from now on all the actions are gonna occur on the current victim (the one who executed the worm). In this phase, Medusa will create a copy of itself in the system startup folder of the computer to create a persistency. This way, each time the computer is turned on Medusa will automatically be executed, and the persistency over the host (and the whole network) will keep on.

So, the worm creates persistency on the current computer and the remote computer, by copying itself to the system startup folder of both computers. It's important to mention that this phase might fail due to lack of privileges, because creating a file in the system startup requires admin privileges. If Medusa would not be executed as admin, it won't be able to copy itself to the local startup. If Medusa would connect to the remote c$ using non admin user, it won't be able to copy itself to the remote startup. Do not worry if the phase fails, the payload is still executed!


#### 6. Payload:

At last, the worm can execute its payload on the victim. The payload is termination of every process of msedge.exe, so the victim will not be able to use Microsoft edge at all (i truly hate that browser). The payload is executed as infinite loop, which in it the malware iterates over the Active process links and searches for any msedge.exe processes. Each msedge.exe process found is terminated by the malware.

Additionally, while the payload is being executed there is a signal handler on the SIGINT signal, which is triggered by calling ctrl+c. Every time the victim tries to stop the worm from running using ctrl+c, the worm won't be terminates and instead only a message will be printed to the victim.

You can change the process Medusa will terminate if you wish to. Modify the PROCESS_NAME macro in worm.c to the case sensitive name of the process you would like to terminate (use task manager to see the name of the process), and compile the code to a new executable (compilation commands are saved in the description of worm.c). Just keep in mind that terminating important process in the system (like lsass.exe) will cause the OS to collapse, so be caution about it. It wont harm your computer, but it can be little sucks.


Meanwhile our first victim is suffering from lack of microsoft edge, the next victim finds on its desktop the worm that had propagated from the first victim. The new victim will execute the worm, and all this happens over and over again.



### Usage in .txt files:

As part of the brute force, the worm needs a list for usernames and a list for passwords. For supporting very long usernames/passwords list, the worm uses two .txt files for the brute force:

- data1_for_msedge_update.txt for usernames list.
- data2_for_msedge_update.txt for passwords list.

In those files, each username/password is saved in its own line. In the propagation process, the worm makes sure to transfer the two .txt file along with the worm itself. The .txt files are saved in the public documents directory of the host. For the first victim in the network, you must find a way to install those .txt files in the public documents library, otherwise Medusa shall fail.

You can edit those files as you wish, of course. Just make sure to put them in the right path and to not change their names, and everything should be fine.


### Adding version info file:

This is a cute addition for hiding the process of the worm, and making it look more realistic. Every formal executable distributed by a company has a resource file called version info, which indicates what is the executable, who made it, etc. For making Medusa look like a Microsoft Edge update, i took the version info of the real msedge.exe and in it changed msedge to msedge_update and "Microsoft Edge" to "Microsoft Edge Update". Now, when you execute the file, you can open process explorer and see "Microsoft Edge Update" as the description of the process executable, although it's malware!

If you would like to work with resources, i highly recommend using Resource Hacker app for this. The file version_info.rc is the edited version info for msedge_update.exe, enjoy it :)