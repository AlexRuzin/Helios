#include "main.h"

DWORD generate_checksum(LPCSTR szFilename) 
{
	PIMAGE_NT_HEADERS pNTHeaders;

    HANDLE hFile = INVALID_HANDLE_VALUE;
    HANDLE hFileMapping = NULL;
    PVOID pBaseAddress = NULL;
    DWORD dwFileLength = 0;
    DWORD dwHeaderSum; // Checksum as stated by Header
    DWORD dwCheckSum; // Calculated Checksum

	DWORD dwSize;
	LARGE_INTEGER liSize	 = {0};

    /////////////////////////////////////////////////////////////
    hFile = CreateFileA( szFilename, GENERIC_READ, FILE_SHARE_READ,
        NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0 );
    if ( INVALID_HANDLE_VALUE == hFile ||
        NULL == hFile) { return 0; }

    /////////////////////////////////////////////////////////////
    hFileMapping = CreateFileMapping(hFile, NULL,
        PAGE_READONLY, 0, 0, NULL);
    if ( NULL == hFileMapping )
    {
        return 0;
    }

    /////////////////////////////////////////////////////////////
    pBaseAddress = MapViewOfFile( hFileMapping,
        FILE_MAP_READ, 0, 0, 0);
    if ( NULL == pBaseAddress )
    {
        return 0;
    }

    /////////////////////////////////////////////////////////////
    dwSize = 0;
    if( TRUE == GetFileSizeEx( hFile, &liSize ) )
    {
        dwSize = liSize.LowPart;
    }

    SetLastError( ERROR_SUCCESS );

    /////////////////////////////////////////////////////////////
    pNTHeaders = CheckSumMappedFile(
        pBaseAddress, dwSize, &dwHeaderSum, &dwCheckSum );

    

    /////////////////////////////////////////////////////////////
    UnmapViewOfFile( pBaseAddress );
    CloseHandle( hFile );

    return TRUE;
}