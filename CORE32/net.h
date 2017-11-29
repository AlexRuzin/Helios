#define	HTTP_SERVER_HOST		"www.memtest86.com"
#define HTTP_FILE_URL			"/memtest86-4.0a.iso.zip"

#define LARGEST_PAYLOAD_SIZE	0x100000
#define MAX_HOSTNAME_IP_SIZE	4096

// File Downloader configs
#define DEFAULT_INET_AGENT		"WinInetGet/0.1"
#define ERROR_INTERNETOPEN		0x11110000
#define ERROR_PARAMETERS		0xFFFFFFFF
#define ERROR_CONNECT			0xAAAAAAAA
#define ERROR_REQUEST			0xBBBBBBBB
#define ERROR_SEND				0xCCCCCCCC
#define ERROR_RX				0xEEEEEEEE


// Prototypes
BOOL		grab_gateway_payload(	__out		PDWORD *out_buffer, 
									__out		PUINT out_buffer_size, 
									__in		LPCSTR url);