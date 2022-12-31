#include <ntifs.h>
#include "Structs.h"
#include "Imports.h"
#include "Log.h"

/// <summary>
/// Search for pattern
/// </summary>
/// <param name="pattern">Pattern to search for</param>
/// <param name="wildcard">Used wildcard</param>
/// <param name="len">Pattern length</param>
/// <param name="base">Base address for searching</param>
/// <param name="size">Address range to search in</param>
/// <param name="ppFound">Found location</param>
/// <returns>Status code</returns>
NTSTATUS SearchPattern(IN PCUCHAR pattern, IN UCHAR wildcard, IN ULONG_PTR len, IN const VOID* base, IN ULONG_PTR size, OUT PVOID* ppFound)
{
	ASSERT(ppFound != NULL && pattern != NULL && base != NULL);
	if (ppFound == NULL || pattern == NULL || base == NULL)
		return STATUS_INVALID_PARAMETER;

	for (ULONG_PTR i = 0; i < size - len; i++)
	{
		BOOLEAN found = TRUE;
		for (ULONG_PTR j = 0; j < len; j++)
		{
			if (pattern[j] != wildcard && pattern[j] != ((PCUCHAR)base)[i + j])
			{
				found = FALSE;
				break;
			}
		}

		if (found != FALSE)
		{
			*ppFound = (PUCHAR)base + i;
			return STATUS_SUCCESS;
		}
	}

	return STATUS_NOT_FOUND;
}

/// <summary>
/// Gets name of process main module
/// </summary>
/// <param name="pid">PID of process</param>
/// <returns>Pointer to name</returns>
char* GetName(IN HANDLE pid)
{
	PEPROCESS Process;
	if (PsLookupProcessByProcessId(pid, &Process) == STATUS_INVALID_PARAMETER)
	{
		return "invalid";
	}
	return (CHAR*)PsGetProcessImageFileName(Process);
}

/// <summary>
/// Unsecure! Compares two char pointer and if one is part of another it returns true
/// </summary>
/// <param name="w1">First char pointer</param>
/// <param name="w2">Second char pointer</param>
/// <returns>Boolean</returns>
BOOLEAN IsPartOf(IN char* w1, IN char* w2)
{
	int i = 0;
	int j = 0;

	while (w1[i] != '\0') {
		if (w1[i] == w2[j])
		{
			while (w1[i] == w2[j] && w2[j] != '\0')
			{
				j++;
				i++;
			}
			if (w2[j] == '\0') {
				return TRUE;
			}
			j = 0;
		}
		i++;
	}
	return FALSE;
}

/// <summary>
/// Switch current thread mode
/// </summary>
/// <param name="Mode">Usermode if true</param>
/// <returns>Boolean</returns>
void SwitchMode(IN BOOLEAN Mode) 
{
	Log("[>] Switching mode...");
	PUCHAR pprevmode = (PUCHAR)PsGetCurrentThread() + 0x232; // PrevMode from blackbone
	UCHAR prevmode = *pprevmode;
	if (Mode) 
	{
		*pprevmode = UserMode;
	}
	else 
	{
		*pprevmode = KernelMode;
	}
	Log("[+] Switched mode (from %u, to %u)", prevmode, *pprevmode);
}