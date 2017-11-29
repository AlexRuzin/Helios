#include "main.h"

HANDLE		debug_event_handle		= INVALID_HANDLE_VALUE;
HANDLE		debug_map_object		= INVALID_HANDLE_VALUE;
HANDLE		debug_event_lock		= INVALID_HANDLE_VALUE;
LPVOID		debug_buffer			= NULL;

#ifdef DEBUG_OUT
VOID initialize_debug_channel(VOID)
{
	ERROR_CODE	status;

	HANDLE		log_file = INVALID_HANDLE_VALUE;

	INT			i;

#ifdef REROUTE_TO_DBGPRINT
	return;
#endif

#ifdef DEBUG_FILE_LOGGER
	// Zero the log
	while (DeleteFileA(LOG_FILE) == FALSE) {
		Sleep(10 * generate_random_byte_range(10));
	}
	while (log_file == INVALID_HANDLE_VALUE) {
		log_file = CreateFileA(		LOG_FILE,
									GENERIC_READ,
									FILE_SHARE_READ,
									NULL,
									CREATE_ALWAYS,
									FILE_ATTRIBUTE_NORMAL,
									NULL);
		Sleep(10 * generate_random_byte_range(10));
	}

	CloseHandle(log_file);
	return;

#endif

	//DebugBreak();

	debug_event_lock = OpenEventA(READ_CONTROL | EVENT_MODIFY_STATE, FALSE, DEBUG_EVENT_LOCK);
	if (debug_event_lock == NULL) {
		BREAK;
	}

	status = SetEvent(debug_event_lock);
	if (!status) {
		BREAK;
	}

	debug_event_handle = OpenEventA(READ_CONTROL | EVENT_MODIFY_STATE, FALSE, DEBUG_EVENT_NAME);
	if (debug_event_handle == NULL) {
		BREAK;
	}

	debug_map_object = OpenFileMappingA(FILE_MAP_READ | FILE_MAP_WRITE,
										FALSE,
										DEBUG_MAP_NAME);
	if (debug_map_object == NULL) {
		BREAK;
	}


	debug_buffer = MapViewOfFile(			debug_map_object,
											FILE_MAP_READ | FILE_MAP_WRITE,
											0,
											0,
											DEBUG_BUFFER_SIZE);
	if (debug_buffer == NULL) {
		BREAK;
	}

	return;
}
#elif defined NICE_DEBUG
VOID initialize_debug_channel(VOID)
{
	ERROR_CODE	status;

	HANDLE		log_file = INVALID_HANDLE_VALUE;

	INT			i;

#ifdef REROUTE_TO_DBGPRINT
	return;
#endif

#ifdef DEBUG_FILE_LOGGER
	// Zero the log
	while (DeleteFileA(LOG_FILE) == FALSE) {
		Sleep(10 * generate_random_byte_range(10));
	}
	while (log_file == INVALID_HANDLE_VALUE) {
		log_file = CreateFileA(		LOG_FILE,
									GENERIC_READ,
									FILE_SHARE_READ,
									NULL,
									CREATE_ALWAYS,
									FILE_ATTRIBUTE_NORMAL,
									NULL);
		Sleep(10 * generate_random_byte_range(10));
	}

	CloseHandle(log_file);
	return;

#endif

	//DebugBreak();

	debug_event_lock = OpenEventA(READ_CONTROL | EVENT_MODIFY_STATE, FALSE, DEBUG_EVENT_LOCK);
	if (debug_event_lock == NULL) {
		BREAK;
	}

	status = SetEvent(debug_event_lock);
	if (!status) {
		BREAK;
	}

	debug_event_handle = OpenEventA(READ_CONTROL | EVENT_MODIFY_STATE, FALSE, DEBUG_EVENT_NAME);
	if (debug_event_handle == NULL) {
		BREAK;
	}

	debug_map_object = OpenFileMappingA(FILE_MAP_READ | FILE_MAP_WRITE,
										FALSE,
										DEBUG_MAP_NAME);
	if (debug_map_object == NULL) {
		BREAK;
	}


	debug_buffer = MapViewOfFile(			debug_map_object,
											FILE_MAP_READ | FILE_MAP_WRITE,
											0,
											0,
											DEBUG_BUFFER_SIZE);
	if (debug_buffer == NULL) {
		BREAK;
	}

	return;
}
#endif

#ifdef DEBUG_OUT
VOID send_debug_channel(char *FormatString, ...)
{
	SYSTEMTIME	systemtime					= {0};

	CHAR		buffer[1024]				= {0};
	CHAR		out_buffer[1024]			= {0};
	va_list		valist						= {0};

	//BREAK;

#ifdef DEBUG_FILE_LOGGER
	debug_logger(FormatString);
#endif

#ifndef REROUTE_TO_DBGPRINT
	GetSystemTime(&systemtime);

	Sleep(150);

	WaitForSingleObject(debug_event_lock, INFINITE);
	ResetEvent(debug_event_lock);

	va_start(valist, FormatString);
	wvsprintfA(buffer, FormatString, valist);
	f_snprintf(out_buffer, sizeof(out_buffer), "[%d.%d.%d]\t%s", systemtime.wSecond, systemtime.wMinute, systemtime.wHour, buffer);

	ZeroMemory((void *)debug_buffer, DEBUG_BUFFER_SIZE);
	CopyMemory((void *)debug_buffer, out_buffer, DEBUG_BUFFER_SIZE);

	va_end(valist);

	SetEvent(debug_event_handle);

	return;
#endif
}
#elif defined NICE_DEBUG
VOID send_debug_channel(char *FormatString, ...)
{
	SYSTEMTIME	systemtime					= {0};

	CHAR		buffer[1024]				= {0};
	CHAR		out_buffer[1024]			= {0};
	va_list		valist						= {0};

	//BREAK;

#ifdef DEBUG_FILE_LOGGER
	debug_logger(FormatString);
#endif

#ifndef REROUTE_TO_DBGPRINT
	GetSystemTime(&systemtime);

	Sleep(150);

	WaitForSingleObject(debug_event_lock, INFINITE);
	ResetEvent(debug_event_lock);

	va_start(valist, FormatString);
	wvsprintfA(buffer, FormatString, valist);
	f_snprintf(out_buffer, sizeof(out_buffer), "[%d.%d.%d]\t%s", systemtime.wSecond, systemtime.wMinute, systemtime.wHour, buffer);

	ZeroMemory((void *)debug_buffer, DEBUG_BUFFER_SIZE);
	CopyMemory((void *)debug_buffer, out_buffer, DEBUG_BUFFER_SIZE);

	va_end(valist);

	SetEvent(debug_event_handle);

	return;
#endif
}
#endif

#ifdef DEBUG_OUT
#ifdef DEBUG_FILE_LOGGER
VOID debug_logger(PCHAR FormatString, ...) 
{
	LPVOID			log_file;
	UINT			log_size;

	SYSTEMTIME	systemtime					= {0};

	CHAR		buffer[1024]				= {0};
	CHAR		out_buffer[1024]			= {0};
	va_list		valist						= {0};

	PBYTE		ptr;

	// Try to read the existing file
	while (read_raw_into_buffer(LOG_FILE, &log_size, &log_file) == FALSE) {
		Sleep(100 * generate_random_byte_range(10));
	}

	// Generate string
	GetSystemTime(&systemtime);
	va_start(valist, FormatString);
	wvsprintfA(buffer, FormatString, valist);
	f_snprintf(out_buffer, sizeof(out_buffer), "[%d.%d.%d]\t%s", systemtime.wSecond, systemtime.wMinute, systemtime.wHour, buffer);

	// Seek till the end of the buffer
	ptr = (PBYTE)log_file;
	while (*ptr != 0) {
		ptr++;
	}

	CopyMemory(ptr, out_buffer, string_length(out_buffer));

	while (write_raw_to_disk(LOG_FILE, (PDWORD)log_file, log_size) == FALSE) {
		Sleep(100 * generate_random_byte_range(10));
	}

	// Release memory
	VirtualFree(log_file, log_size, MEM_RELEASE);

	return;
}
#endif
#endif

#ifdef DEBUG_OUT
VOID debug_catcher(VOID)
{
	SECURITY_ATTRIBUTES security = {0};

	HANDLE		map_handle;
	HANDLE		event_handle;
	HANDLE		debug_event_handle;
	LPSTR		buffer;

#ifdef REROUTE_TO_DBGPRINT
	printf("\n\nDEBUG OUTPUT REROUTED TO DBGPRINT. Exiting...");
	Sleep(5000);
	ExitProcess(0);
#endif

	printf("\n\nDEBUG BUFFER:\n");

	event_handle		= CreateEventA(NULL, TRUE, FALSE, DEBUG_EVENT_NAME);
	debug_event_handle	= CreateEventA(NULL, TRUE, FALSE, DEBUG_EVENT_LOCK);
	//ResetEvent(event_handle);

	security.nLength			= sizeof(SECURITY_ATTRIBUTES);
	security.bInheritHandle		= FALSE;

	map_handle = CreateFileMappingA(INVALID_HANDLE_VALUE,
									&security,
									PAGE_READWRITE,
									0,
									DEBUG_BUFFER_SIZE,
									DEBUG_MAP_NAME);
	if (map_handle == INVALID_HANDLE_VALUE) {
#ifdef DEBUG_OUT
		printf("[!] Failed to allocate memory section %s", DEBUG_MAP_NAME);
#endif
		return;
	}

	
	
	buffer = (LPSTR)MapViewOfFile(map_handle,
									FILE_MAP_ALL_ACCESS,
									0,
									0,
									DEBUG_BUFFER_SIZE);
	if (buffer == INVALID_HANDLE_VALUE) {
		//DbgPrint(">Failed to get handle\n");
		return;
	}	

#ifdef DEBUG_OUT
	printf("LISTENING...\n");
#endif

	while (TRUE) {

		WaitForSingleObject(event_handle, INFINITE);

		printf("> %s\n", buffer);

		ZeroMemory((void *)buffer, DEBUG_BUFFER_SIZE);

		ResetEvent(event_handle);
		SetEvent(debug_event_handle);
	}

}
#elif defined NICE_DEBUG
VOID debug_catcher(VOID)
{
	SECURITY_ATTRIBUTES security = {0};

	HANDLE		map_handle;
	HANDLE		event_handle;
	HANDLE		debug_event_handle;
	LPSTR		buffer;

#ifdef REROUTE_TO_DBGPRINT
	printf("\n\nDEBUG OUTPUT REROUTED TO DBGPRINT. Exiting...");
	Sleep(5000);
	ExitProcess(0);
#endif

	printf("\n\nDEBUG BUFFER:\n");

	event_handle		= CreateEventA(NULL, TRUE, FALSE, DEBUG_EVENT_NAME);
	debug_event_handle	= CreateEventA(NULL, TRUE, FALSE, DEBUG_EVENT_LOCK);
	//ResetEvent(event_handle);

	security.nLength			= sizeof(SECURITY_ATTRIBUTES);
	security.bInheritHandle		= FALSE;

	map_handle = CreateFileMappingA(INVALID_HANDLE_VALUE,
									&security,
									PAGE_READWRITE,
									0,
									DEBUG_BUFFER_SIZE,
									DEBUG_MAP_NAME);
	if (map_handle == INVALID_HANDLE_VALUE) {
#ifdef DEBUG_OUT
		printf("[!] Failed to allocate memory section %s", DEBUG_MAP_NAME);
#endif
		return;
	}

	
	
	buffer = (LPSTR)MapViewOfFile(map_handle,
									FILE_MAP_ALL_ACCESS,
									0,
									0,
									DEBUG_BUFFER_SIZE);
	if (buffer == INVALID_HANDLE_VALUE) {
		//DbgPrint(">Failed to get handle\n");
		return;
	}	

#ifdef DEBUG_OUT
	printf("LISTENING...\n");
#endif

	while (TRUE) {

		WaitForSingleObject(event_handle, INFINITE);

		printf("> %s\n", buffer);

		ZeroMemory((void *)buffer, DEBUG_BUFFER_SIZE);

		ResetEvent(event_handle);
		SetEvent(debug_event_handle);
	}

}
#endif

#ifdef DEBUG_OUT
#ifdef REROUTE_TO_DBGPRINT
VOID debug_print(char *FormatString, ...) 
 { 
	CHAR dbgout[1024];
	va_list   vaList;

	//BREAK;

	ZeroMemory(dbgout, sizeof(dbgout));

	va_start(vaList, FormatString); 
	__nop;
	wvsprintfA(dbgout, FormatString, vaList); 
	__nop;
	OutputDebugStringA(dbgout); 
	__nop;
	va_end(vaList); 
	__nop;

	return;
 }
#endif
#endif

#ifdef DEBUG_OUT 
VOID send_debug_channelw(wchar_t *FormatString, ...)
{
	wchar_t		buffer[1024] = {0};
	char		*bufferA;
	va_list		valist;

#ifdef REROUTE_TO_DBGPRINT
	return;
#endif

#ifdef DEBUG_FILE_LOGGER
	return;
#endif

	Sleep(100);

	va_start(valist, FormatString);
	wsprintfW(buffer, (LPCWSTR)FormatString, valist);

	bufferA = unicode_to_ascii(buffer, get_unicode_string_length(buffer));


	ZeroMemory((void *)debug_buffer, DEBUG_BUFFER_SIZE);
	CopyMemory((void *)debug_buffer, bufferA, string_length(bufferA));

	HeapFree(GetProcessHeap(), 0, bufferA);

	va_end(valist);

	SetEvent(debug_event_handle);

	return;
}
#elif defined NICE_DEBUG
VOID send_debug_channelw(wchar_t *FormatString, ...)
{
	wchar_t		buffer[1024] = {0};
	char		*bufferA;
	va_list		valist;

#ifdef REROUTE_TO_DBGPRINT
	return;
#endif

#ifdef DEBUG_FILE_LOGGER
	return;
#endif

	Sleep(100);

	va_start(valist, FormatString);
	wsprintfW(buffer, (LPCWSTR)FormatString, valist);

	bufferA = unicode_to_ascii(buffer, get_unicode_string_length(buffer));


	ZeroMemory((void *)debug_buffer, DEBUG_BUFFER_SIZE);
	CopyMemory((void *)debug_buffer, bufferA, string_length(bufferA));

	HeapFree(GetProcessHeap(), 0, bufferA);

	va_end(valist);

	SetEvent(debug_event_handle);

	return;
}
#endif

