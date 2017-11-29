#include "main.h"

INT WSAAPI winet_pton(	__in INT	Family,
						__in LPCSTR pszAddrString,
						__out PDWORD pAddrBuf)
{
	int			size = sizeof(struct sockaddr_in);
	NTSTATUS	ntStatus;
	WSADATA		wsadata = {0};
	DWORD		*return_struct = (PDWORD)pAddrBuf;

	struct sockaddr_in address;


	//WSAStartup(MAKEWORD(2,2), &wsadata);

	ntStatus = WSAStringToAddressA(	(LPSTR)pszAddrString,
									Family,
									NULL,
									(PSOCKADDR)&address,
									&size);

	//WSACleanup();

	*return_struct = (DWORD)address.sin_addr.S_un.S_addr;
/*
	INT WSAAPI WSAStringToAddress(
  __in      LPTSTR AddressString,
  __in      INT AddressFamily,
  __in_opt  LPWSAPROTOCOL_INFO lpProtocolInfo,
  __out     LPSOCKADDR lpAddress,
  __inout   LPINT lpAddressLength
); */
	return ntStatus;
}

