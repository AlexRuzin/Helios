#include "main.h"

BOOL find_pid(LPCSTR process_name, DWORD pid_array[MAX_PIDS])
{
	PROCESSENTRY32		process_info;
	HANDLE				process_snapshot;
	CHAR				process_char[1024];
	DWORD				pid;
	UINT				pid_count							= 0;

	ZeroMemory((void *)&process_info, sizeof(PROCESSENTRY32));
	process_info.dwSize = sizeof(PROCESSENTRY32);

	// If process_name is NULL, we return every PID on the system
	if (process_name == NULL) {
		process_snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
		if ( process_snapshot == INVALID_HANDLE_VALUE ) {
			return FALSE;
		}

		if (Process32First(process_snapshot, &process_info) == FALSE) {
			return FALSE;
		}

		while (Process32Next(process_snapshot, &process_info)) {
			pid_array[pid_count] = process_info.th32ProcessID;
			if (pid_array[pid_count] == 0) {
				continue;
			}

			ZeroMemory((void *)&process_info, sizeof(PROCESSENTRY32));
			process_info.dwSize = sizeof(PROCESSENTRY32);

			pid_count++;
		}
		return TRUE;
	}

	process_snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
	if ( process_snapshot == INVALID_HANDLE_VALUE ) {
		return FALSE;
	}

	if (Process32First(process_snapshot, &process_info) == FALSE) {
		return FALSE;
	}

	//ZeroMemory(process_char, sizeof(process_char));
	//WideCharToMultiByte(CP_ACP, 0, process_info.szExeFile, -1, (LPSTR)process_char, sizeof(process_char), NULL, NULL);

	//WideCharToMultiByte(CP_ACP, 0, wstr.c_str(), -1, szTo, (int)wstr.length(), NULL, NULL);
	//wcstombs(process_char, (wchar_t *)process_info.szExeFile, sizeof(process_char));

	if (string_compare(process_name, process_info.szExeFile, string_length(process_name) - 1) == 0) {
		pid_array[0] = process_info.th32ProcessID; 
	}

	while (TRUE) {
		if (Process32Next(process_snapshot, &process_info) == FALSE) break;

		//ZeroMemory(process_char, sizeof(process_char));
	//	WideCharToMultiByte(CP_ACP, 0, process_info.szExeFile, -1, (LPSTR)process_char, sizeof(process_char), NULL, NULL);

		if (memory_compare((LPVOID)process_name, process_info.szExeFile, string_length(process_name) - 1) == 0) {
			pid_array[pid_count] = process_info.th32ProcessID;
			pid_count++;
			continue;
		}
	}

	CloseHandle(process_snapshot);
	return TRUE;
}