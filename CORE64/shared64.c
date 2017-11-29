#include "..\CORE32\main.h"

QWORD	get_local_dll_base64(VOID)
{
	QWORD		base;
	QWORD		(*function)(VOID);

	function	= (QWORD (*)(VOID))get_local_base64;

	base		= function();

	return	base;
}
