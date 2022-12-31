#include <ntifs.h>
#include <ntstrsafe.h>
#include "Log.h"
#include "Structs.h"
#include "Private.h"
#include "Imports.h"
#include "Utils.h"
#include "Funcs.h"

#define SSDT_NTSUSPENDTHRED		438
#define SSDT_RESUMETHREAD		82
#define SSDT_TERMINATETHREAD	83

static NTSTATUS
(__fastcall* NtSuspendThread)(
	__in HANDLE ThreadHandle,
	__out_opt PULONG PreviousSuspendCount
	);

static NTSTATUS
(__fastcall* NtTerminateThread)(
	__in HANDLE ThreadHandle,
	DWORD  dwExitCode
	);


static NTSTATUS
(__fastcall* NtResumeThread)(
	__in HANDLE ThreadHandle,
	__out_opt PULONG PreviousSuspendCount
	);

/// <summary>
/// Open HANDLE to the thread
/// </summary>
/// <param name="dwDesiredAccess">Desired access</param>
/// <param name="bInheritHandle">Inherit handle</param>
/// <param name="dwThreadId">Thread ID</param>
/// <returns>HANDLE for thread</returns>
HANDLE OpenThread(DWORD dwDesiredAccess, BOOLEAN bInheritHandle, DWORD dwThreadId)
{
	OBJECT_ATTRIBUTES      ObjectAttributes = { 0, };
	CLIENT_ID              ClientId = { 0, };
	HANDLE                 hThread = NULL;
	NTSTATUS               Status;

	InitializeObjectAttributes(&ObjectAttributes, NULL, 0, NULL, NULL);

	if (bInheritHandle) {
		ObjectAttributes.Attributes = OBJ_INHERIT;
	}

	ClientId.UniqueProcess = NULL;
	ClientId.UniqueThread = (HANDLE)dwThreadId;

	Status = ZwOpenThread(&hThread,
		dwDesiredAccess,
		&ObjectAttributes,
		&ClientId);
	return hThread;
}

/// <summary>
/// Suspend (pause) thread
/// </summary>
/// <param name="ThreadHandle">HANDLE to desired thread</param>
/// <returns>Status</returns>
NTSTATUS SuspendThread(__in HANDLE ThreadHandle)
{
	NTSTATUS Status;
	fnNtSuspendThread suspth = (fnNtSuspendThread)(ULONG_PTR)GetSSDTEntry(SSDT_NTSUSPENDTHRED); // Warning! Latest Windows has changed this!
	Status = suspth(ThreadHandle, 0);
	return Status;
}

/// <summary>
/// Terminate thread
/// </summary>
/// <param name="ThreadHandle">HANDLE to desired thread</param>
/// <returns>Status</returns>
NTSTATUS TerminateThread(__in HANDLE ThreadHandle)
{
	NTSTATUS Status;
	fnNtTerminateThread termth = (fnNtTerminateThread)(ULONG_PTR)GetSSDTEntry(SSDT_TERMINATETHREAD);
	Status = termth(ThreadHandle, 0);
	return Status;
}

/// <summary>
/// Resume (unpause) thread
/// </summary>
/// <param name="ThreadHandle">HANDLE to desired thread</param>
/// <returns>Status</returns>
NTSTATUS ResumeThread(__in HANDLE ThreadHandle)
{
	NTSTATUS               Status;
	NtResumeThread = (NTSTATUS(__cdecl*)(HANDLE, PULONG))GetSSDTEntry(SSDT_RESUMETHREAD);
	Status = NtResumeThread(ThreadHandle, NULL);
	return Status;
}

/// <summary>
/// Get base address of system module
/// </summary>
/// <param name="ModuleName">Name of module</param>
/// <returns>Found address, 0 if not found</returns>
PVOID GetModuleBase(IN char* ModuleName, OUT ULONG64* BaseAddr, OUT ULONG* DriverSize)
{
	NTSTATUS status = STATUS_SUCCESS;
	ULONG bytes = 0;
	PRTL_PROCESS_MODULES pMods = NULL;
	UNICODE_STRING routineName;

	RtlUnicodeStringInit(&routineName, L"NtOpenFile");

	// Protect from UserMode AV
	status = ZwQuerySystemInformation(SystemModuleInformation, 0, bytes, &bytes);
	if (bytes == 0)
	{
		//DPRINT("BlackBone: %s: Invalid SystemModuleInformation size\n", __FUNCTION__);
		Log("[-] Invalid SystemModuleInformation size");
		return NULL;
	}

	pMods = (PRTL_PROCESS_MODULES)ExAllocatePoolWithTag(NonPagedPool, bytes, POOL_TAG);
	RtlZeroMemory(pMods, bytes);

	status = ZwQuerySystemInformation(SystemModuleInformation, pMods, bytes, &bytes);

	if (NT_SUCCESS(status))
	{
		for (ULONG i = 0; i < pMods->NumberOfModules; i++)
		{
			// System routine is inside module
			if ((PVOID)pMods->Modules[i].ImageBase > (PVOID)0x8000000000000000)
			{
				char* pDrvName = (char*)(pMods->Modules[i].FullPathName) + pMods->Modules[i].OffsetToFileName;
				if (_stricmp(pDrvName, ModuleName) == 0) {
					*BaseAddr = (ULONG64)(pMods->Modules[i].ImageBase);
					*DriverSize = (ULONG64)(pMods->Modules[i].ImageSize);
					return (PVOID)(pMods->Modules[i].ImageBase);
				}
			}
		}
	}

	if (pMods)
		ExFreePoolWithTag(pMods, POOL_TAG);

	return 0;
}

// TODO: Comment
/// <summary>
/// ApcpQuerySystemProcessInformation
/// </summary>
/// <returns>Status</returns>
NTSTATUS ApcpQuerySystemProcessInformation(PSYSTEM_PROCESS_INFORMATION* SystemInfo)
{
	PSYSTEM_PROCESS_INFORMATION pBuffer = NULL;
	ULONG BufferSize = 0;
	ULONG RequiredSize = 0;

	NTSTATUS status = STATUS_SUCCESS;
	while ((status = ZwQuerySystemInformation(
		SystemProcessInformation,
		pBuffer,
		BufferSize,
		&RequiredSize//retn Length
	)) == STATUS_INFO_LENGTH_MISMATCH)
	{
		BufferSize = RequiredSize;
		pBuffer = (PSYSTEM_PROCESS_INFORMATION)ExAllocatePool(PagedPool, BufferSize);
	}

	if (!NT_SUCCESS(status))
	{
		if (pBuffer != NULL)
		{
			ExFreePool(pBuffer);
		}

		return status;
	}
	*SystemInfo = pBuffer;
	return status;
}

// TODO: Comment
/// <summary>
/// Gets information about thread
/// </summary>
/// <returns>Status</returns>
NTSTATUS GetProcessThreadInfo(IN ULONG Pid, OUT ULONG* ThreadNuber, OUT PULONG64 Tid, OUT PULONG64 StartAddr)
{
	PEPROCESS pEProcess;
	PSYSTEM_PROCESS_INFORMATION OriginalSystemProcessInfo = NULL;
	NTSTATUS status = PsLookupProcessByProcessId((HANDLE)Pid, &pEProcess);
	if (!NT_SUCCESS(status))
	{
		return status;
	}
	if (MmIsAddressValid(ThreadNuber) == 0)
	{
		status = STATUS_UNSUCCESSFUL;
		return status;
	}
	if (MmIsAddressValid(StartAddr) == 0)
	{
		status = STATUS_UNSUCCESSFUL;
		return status;
	}
	if (MmIsAddressValid(Tid) == 0)
	{
		status = STATUS_UNSUCCESSFUL;
		return status;
	}
	status = ApcpQuerySystemProcessInformation(&OriginalSystemProcessInfo);
	if (!NT_SUCCESS(status))
	{
		ObDereferenceObject(pEProcess);
		return status;
	}
	PSYSTEM_PROCESS_INFORMATION SystemProcessInfo = OriginalSystemProcessInfo;
	status = STATUS_NOT_FOUND;
	do
	{
		if (SystemProcessInfo->UniqueProcessId == PsGetProcessId(pEProcess))
		{
			status = STATUS_SUCCESS;
			break;
		}

		SystemProcessInfo = (PSYSTEM_PROCESS_INFORMATION)((PUCHAR)SystemProcessInfo + SystemProcessInfo->NextEntryOffset);
	} while (SystemProcessInfo->NextEntryOffset != 0);

	if (!NT_SUCCESS(status))
	{
		ObDereferenceObject(pEProcess);
		ExFreePool(OriginalSystemProcessInfo);
		return status;
	}
	*ThreadNuber = SystemProcessInfo->NumberOfThreads;

	for (ULONG Index = 0; Index < SystemProcessInfo->NumberOfThreads; ++Index)
	{
		HANDLE UniqueThreadId = SystemProcessInfo->Threads[Index].ClientId.UniqueThread;
		Tid[Index] = (ULONG64)UniqueThreadId;
		StartAddr[Index] = (ULONG64)SystemProcessInfo->Threads[Index].StartAddress;
	}

	ObDereferenceObject(pEProcess);
	return status;
}

/// <summary>
/// Gets driver threads
/// </summary>
/// <param name="DriverName">Name of module</param>
/// <param name="ThreadNuber">Number of threads</param>
/// <param name="Tid">Threads IDs (array)</param>
/// <returns>Found address, 0 if not found</returns>
NTSTATUS GetDriverThreads(char* DriverName, OUT ULONG* ThreadNuber, OUT PULONG64 Tid)
{
	ULONG64				DriverBaseAddr = 0;
	ULONG    			DriverSize = 0;
	ULONG				Number = 0;
	ULONG64              __Tid[0x256] = { 0 };
	ULONG64              __ThreadStartAddr[0x256] = { 0 };
	NTSTATUS            Status = STATUS_UNSUCCESSFUL;
	ULONG               Count = 0;
	GetModuleBase(DriverName, &DriverBaseAddr, &DriverSize);

	if (DriverBaseAddr == 0 || DriverSize == 0) {
		Log("[-] Driver base is 0");
		return Status;
	}
	Status = GetProcessThreadInfo(4, &Number, __Tid, __ThreadStartAddr);
	if (!NT_SUCCESS(Status)) {
		Log("[-] Failed to get thread info");
		return Status;
	}
	for (ULONG i = 0; i < Number; i++)
	{
		if (__ThreadStartAddr[i] >= DriverBaseAddr)
		{
			if (__ThreadStartAddr[i] <= DriverBaseAddr + DriverSize)
			{
				Tid[Count] = __Tid[i];
				Count++;
			}
		}
	}
	*ThreadNuber = Count;
	return STATUS_SUCCESS;
}