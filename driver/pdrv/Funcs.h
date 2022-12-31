#pragma once

typedef NTSTATUS(NTAPI* fnNtTerminateThread)(IN HANDLE ThreadHandle, IN NTSTATUS ExitStatus);
typedef NTSTATUS(NTAPI* fnNtSuspendThread)(IN HANDLE ThreadHandle, OUT PULONG PreviousSuspendCount);

HANDLE OpenThread(DWORD dwDesiredAccess, BOOLEAN bInheritHandle, DWORD dwThreadId);
NTSTATUS SuspendThread(__in HANDLE ThreadHandle);
NTSTATUS TerminateThread(__in HANDLE ThreadHandle);
NTSTATUS ResumeThread(HANDLE hThread);
PVOID GetModuleBase(IN char* ModuleName, OUT ULONG64* BaseAddr, OUT ULONG* DriverSize);
NTSTATUS ApcpQuerySystemProcessInformation(PSYSTEM_PROCESS_INFORMATION* SystemInfo);
NTSTATUS GetProcessThreadInfo(IN ULONG Pid, OUT ULONG* ThreadNuber, OUT PULONG64 Tid, OUT PULONG64 StartAddr);
NTSTATUS GetDriverThreads(char* DriverName, OUT ULONG* ThreadNuber, OUT PULONG64 Tid);