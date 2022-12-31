/*
		   _
  _ __  __| |_ ___ __
 | '_ \/ _` | '_\ V /
 | .__/\__,_|_|  \_/
 |_|

 Copyright (c) 2019 Samuel Tulach - All rights reserved
 
 Used sources:
  - BlackBone Driver
    - (c) 2015 DarthTon
    - MIT
    - https://github.com/DarthTon/Blackbone

 Tested on Windows 10 x64 1909 18363.476
*/

#include "ntifs.h"
#include "ntstrsafe.h"
#include "Log.h"
#include "Structs.h"
#include "Private.h"
#include "Funcs.h"
#include "Imports.h"
#include "Callbacks.h"
#include "Utils.h"
#include "Callbacks.h"
#include "Shared.h"

#pragma warning( disable : 4152 )

static ULONG64 ArrTID[0x256] = { 0 };
static ULONG ThreadNumber = 0;
static OLD_CALLBACKS OldCallbacks = { 0 };
static HANDLE Threads[0x256] = { 0 };

/// <summary>
/// Function executed when our hooked func is called
/// </summary>
/// <param name="DontUse1">Dummy arg</param>
/// <param name="DontUse2">Dummy arg</param>
/// <param name="Code">Argument used to indentify request</param>
/// <returns>Status</returns>
NTSTATUS HookHandler(UINT_PTR DontUse1, UINT_PTR DontUse2, PULONG32 Code)
{
	UNREFERENCED_PARAMETER(DontUse1);
	UNREFERENCED_PARAMETER(DontUse2);

	Log("[+] Hook call with code %x", *Code);
	
	if (!(*Code == CODE_DISABLE || *Code == CODE_RESTORE))
	{
		Log("[-] Invalid code");
		return STATUS_CANCELLED;
	}

	SwitchMode(FALSE);

	if (*Code == CODE_DISABLE) 
	{
		// Get anticheat threads to manupulate them
		Log("[>] Gettting anticheat threads...");
		NTSTATUS status = GetDriverThreads("EasyAntiCheat.sys", &ThreadNumber, ArrTID);
		if (!NT_SUCCESS(status) || ThreadNumber == 0)
		{
			Log("[-] Failed to get anticheat threads");
		}
		Log("[+] Found %u threads", ThreadNumber);

		// Suspend threads
		Log("[>] Suspending threads...");
		for (ULONG i = 0; i < ThreadNumber; i++)
		{
			Threads[i] = OpenThread(THREAD_ALL_ACCESS, FALSE, (DWORD)ArrTID[i]);
			status = SuspendThread(Threads[i]);
			Log("[+] Thread with HANDLE %p suspended (%x)", Threads[i], status);
		}

		// Unregister callbacks
		Log("[>] Disabling anticheat callbacks...");
		Disable(&OldCallbacks);
		Log("[+] Callbacks disabled");
	}

	if (*Code == CODE_RESTORE) 
	{
		// TODO: Check if CODE_DISABLE was called first
		
		// Resume threads
		Log("[>] Resuming threads...");
		for (ULONG i = 0; i < ThreadNumber; i++)
		{
			Threads[i] = OpenThread(THREAD_ALL_ACCESS, FALSE, (DWORD)ArrTID[i]);
			ResumeThread(Threads[i]);
			Log("[+] Thread with HANDLE %p resumed", Threads[i]);
		}

		// Restore old callbacks
		Log("[>] Restoring anticheat callbacks...");
		Restore(&OldCallbacks);
		Log("[+] Callbacks restored");
	}
	
	SwitchMode(TRUE);

	return STATUS_SUCCESS;
}

/// <summary>
/// Driver main entry point
/// </summary>
/// <param name="DriverObject">DriverObject pointer</param>
/// <returns>Status</returns>
NTSTATUS DriverEntry(IN PDRIVER_OBJECT DriverObject, IN PUNICODE_STRING RegistryPath) 
{
	// Both are undefined when we manual map the driver
	UNREFERENCED_PARAMETER(DriverObject);
	UNREFERENCED_PARAMETER(RegistryPath);
	
	// Print some copyright because that's what matters the most
	Log("\n\npdrv\n");

	// Hook NtQueryIntervalProfile
	Log("[>] Hooking functions...");
	
	PVOID ntosbase = GetKernelBase(NULL);
	if (!ntosbase) 
	{
		Log("[-] Failed to get kernel base");
		return STATUS_CANCELLED;
	}
	Log("[+] Kernel base: %p", ntosbase);

	PVOID* dsptbl = (PVOID*)(RtlFindExportedRoutineByName(ntosbase, "HalDispatchTable"));
	if (!dsptbl)
	{
		Log("[-] Failed to get HalDispatchTable");
		return STATUS_CANCELLED;
	}
	Log("[+] HalDispatchTable: %p", dsptbl);

	dsptbl[1] = &HookHandler;

	Log("[+] Functions hoooked");
	
	// Return dummy status
	return STATUS_SUCCESS;
}
