#include "main.h"

BOOL enable_debug_priv(VOID)
{
    HANDLE              hToken;
    LUID                luid_value;
    TOKEN_PRIVILEGES    tkp;

    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
        return FALSE;
    }

    if (!LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &luid_value)) {
        CloseHandle(hToken);
        return FALSE;
    }

    tkp.PrivilegeCount              = 1;
    tkp.Privileges[0].Luid          = luid_value;
    tkp.Privileges[0].Attributes    = SE_PRIVILEGE_ENABLED;
    if (!AdjustTokenPrivileges(hToken, FALSE, &tkp, sizeof(tkp), NULL, NULL)) {
        return FALSE;
    }

    CloseHandle(hToken);
    return TRUE;
}
