

// TODO: Use blank space instead of allocating memory
// TODO: Load driver automatically (add kdmapper)

#include <Windows.h>
#include <TlHelp32.h>
#include <iostream>
#include <string>
#include "skStr.h"



//#define TARGET_DLL_ADDRESS L""
#define TARGET_DLL_ADDRESS L"" //dllpath 
//#define TARGET_PROCESS L"RustClient.exe" 
#define TARGET_PROCESS L"FortniteClient-Win64-Shipping.exe" 
#define TARGET_THREAD 3

#define CODE_DISABLE 0x1601
#define CODE_RESTORE 0x1602

typedef HMODULE(WINAPI* pLoadLibraryA)(LPCSTR);
typedef FARPROC(WINAPI* pGetProcAddress)(HMODULE, LPCSTR);

typedef BOOL(WINAPI* PDLL_MAIN)(HMODULE, DWORD, PVOID);

typedef struct _MANUAL_INJECT
{
	PVOID ImageBase;
	PIMAGE_NT_HEADERS NtHeaders;
	PIMAGE_BASE_RELOCATION BaseRelocation;
	PIMAGE_IMPORT_DESCRIPTOR ImportDirectory;
	pLoadLibraryA fnLoadLibraryA;
	pGetProcAddress fnGetProcAddress;
}MANUAL_INJECT, * PMANUAL_INJECT;

DWORD WINAPI LoadDll(PVOID p)
{
	PMANUAL_INJECT ManualInject;

	HMODULE hModule;
	DWORD64 i, Function, count, delta;

	DWORD64* ptr;
	PWORD list;

	PIMAGE_BASE_RELOCATION pIBR;
	PIMAGE_IMPORT_DESCRIPTOR pIID;
	PIMAGE_IMPORT_BY_NAME pIBN;
	PIMAGE_THUNK_DATA FirstThunk, OrigFirstThunk;

	PDLL_MAIN EntryPoint;

	ManualInject = (PMANUAL_INJECT)p;

	pIBR = ManualInject->BaseRelocation;
	delta = (DWORD64)((LPBYTE)ManualInject->ImageBase - ManualInject->NtHeaders->OptionalHeader.ImageBase); // Calculate the delta

	while (pIBR->VirtualAddress)
	{
		if (pIBR->SizeOfBlock >= sizeof(IMAGE_BASE_RELOCATION))
		{
			count = (pIBR->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
			list = (PWORD)(pIBR + 1);

			for (i = 0; i < count; i++)
			{
				if (list[i])
				{
					ptr = (DWORD64*)((LPBYTE)ManualInject->ImageBase + (pIBR->VirtualAddress + (list[i] & 0xFFF)));
					*ptr += delta;
				}
			}
		}

		pIBR = (PIMAGE_BASE_RELOCATION)((LPBYTE)pIBR + pIBR->SizeOfBlock);
	}

	pIID = ManualInject->ImportDirectory;

	// Resolve DLL imports

	while (pIID->Characteristics)
	{
		OrigFirstThunk = (PIMAGE_THUNK_DATA)((LPBYTE)ManualInject->ImageBase + pIID->OriginalFirstThunk);
		FirstThunk = (PIMAGE_THUNK_DATA)((LPBYTE)ManualInject->ImageBase + pIID->FirstThunk);

		hModule = ManualInject->fnLoadLibraryA((LPCSTR)ManualInject->ImageBase + pIID->Name);

		if (!hModule)
		{
			return FALSE;
		}

		while (OrigFirstThunk->u1.AddressOfData)
		{
			if (OrigFirstThunk->u1.Ordinal & IMAGE_ORDINAL_FLAG)
			{
				// Import by ordinal

				Function = (DWORD64)ManualInject->fnGetProcAddress(hModule, (LPCSTR)(OrigFirstThunk->u1.Ordinal & 0xFFFF));

				if (!Function)
				{
					return FALSE;
				}

				FirstThunk->u1.Function = Function; 
			}

			else
			{
				// Import by name

				pIBN = (PIMAGE_IMPORT_BY_NAME)((LPBYTE)ManualInject->ImageBase + OrigFirstThunk->u1.AddressOfData);
				Function = (DWORD64)ManualInject->fnGetProcAddress(hModule, (LPCSTR)pIBN->Name);

				if (!Function)
				{
					return FALSE;
				}

				FirstThunk->u1.Function = Function;
			}

			OrigFirstThunk++;
			FirstThunk++;
		}

		pIID++;
	}

	if (ManualInject->NtHeaders->OptionalHeader.AddressOfEntryPoint)
	{
		EntryPoint = (PDLL_MAIN)((LPBYTE)ManualInject->ImageBase + ManualInject->NtHeaders->OptionalHeader.AddressOfEntryPoint);
		return EntryPoint((HMODULE)ManualInject->ImageBase, DLL_PROCESS_ATTACH, NULL); // Call the entry point
	}

	return TRUE;
}

DWORD WINAPI LoadDllEnd()
{
	return 0;
}

#pragma comment(lib, "ntdll.lib")

extern "C" NTSTATUS NTAPI RtlAdjustPrivilege(ULONG Privilege, BOOLEAN Enable, BOOLEAN CurrentThread, PBOOLEAN Enabled);

UCHAR code[] = {
  0x48, 0xB8, 0xF0, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,   // mov -16 to rax
  0x48, 0x21, 0xC4,                                             // and rsp, rax
  0x48, 0x83, 0xEC, 0x20,                                       // subtract 32 from rsp
  0x48, 0x8b, 0xEC,                                             // mov rbp, rsp
  0x90, 0x90,                                                   // nop nop
  0x48, 0xB9, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC,   // mov rcx,CCCCCCCCCCCCCCCC
  0x48, 0xB8, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA,   // mov rax,AAAAAAAAAAAAAAAA
  0xFF, 0xD0,                                                   // call rax
  0x90,                                                         // nop
  0x90,                                                         // nop
  0xEB, 0xFC                                                    // JMP to nop
};

void CallbackSwitch(bool restore) 
{
	FARPROC fnNtQueryIntervalProfile = GetProcAddress(LoadLibrary(L"ntdll.dll"), "NtQueryIntervalProfile");
	typedef HRESULT(__stdcall* tNtQueryIntervalProfile)(ULONG64 ProfileSource, PULONG Interval);

	tNtQueryIntervalProfile NtQueryIntervalProfile = reinterpret_cast<tNtQueryIntervalProfile>(fnNtQueryIntervalProfile);

	ULONG a2 = 0;
	if (restore) 
	{
		NtQueryIntervalProfile(CODE_RESTORE, &a2);
	}
	else 
	{
		NtQueryIntervalProfile(CODE_DISABLE, &a2);
	}

}

DWORD GetPID() 
{
	PROCESSENTRY32 entry;
	entry.dwSize = sizeof(PROCESSENTRY32);
	
	HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);

	if (Process32First(snapshot, &entry) == TRUE)
	{
		while (Process32Next(snapshot, &entry) == TRUE)
		{
			if (wcscmp(entry.szExeFile, TARGET_PROCESS) == 0)
			{
				return entry.th32ProcessID;
			}
		}
	}

	CloseHandle(snapshot);
	return 0;
}

void End() 
{
	Beep(300, 300);
	printf(skCrypt("\[+] Successfully injected!\n"));
	getchar();
	while (true) 
	{
		exit(0);
	}
}

int main()
{

	LPBYTE ptr;
	HANDLE hProcess, hThread, hSnap, hFile;
	PVOID mem, mem1;
	DWORD ProcessId, FileSize, read, i;
	PVOID buffer, image;
	BOOLEAN bl;
	PIMAGE_DOS_HEADER pIDH;
	PIMAGE_NT_HEADERS pINH;
	PIMAGE_SECTION_HEADER pISH;

	THREADENTRY32 te32;
	CONTEXT ctx;

	MANUAL_INJECT ManualInject;

	te32.dwSize = sizeof(te32);
	ctx.ContextFlags = CONTEXT_FULL;

	system("cls");
	printf(skCrypt("[+] Initialized\n"));

	printf(skCrypt("[>] Disabling anticheat callbacks...\n"));
	CallbackSwitch(false);
	printf(skCrypt("[+] Callbacks disabled\n"));
	Sleep(100);
	system("cls");
	
	printf(skCrypt("[>] Getting game PID...\n"));
	DWORD PID = GetPID();
	if (PID == 0) 
	{
		system("cls");
		printf(skCrypt("[-] Game is not running\n"));
		Sleep(1000);
		exit(0);
		End();
	}
	system("cls");
	printf(skCrypt("[+] Found on PID %u\n"), PID);
	system("cls");
	printf(skCrypt("[>] Injecting...\n"));
	//std::vector<std::uint8_t> bytes = KeyAuthApp.download("	858860");
	//if (!KeyAuthApp.data.success) // check whether file downloaded correctly
	//{
	//	system("cls");
	//	std::cout << skCrypt("\n\nStatus: ") << KeyAuthApp.data.message;
	//	Sleep(1500);
	//	exit(0);
	//}
	//std::ofstream file("file.dll", std::ios_base::out | std::ios_base::binary);
	//file.write((char*)bytes.data(), bytes.size());
	//file.close();

	hFile = CreateFile(TARGET_DLL_ADDRESS, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL); // Open the DLL

	if (hFile == INVALID_HANDLE_VALUE)
	{
		system("cls");
		printf(skCrypt("[-] Unable to open the DLL (%d)\n"), GetLastError());
		Sleep(100);
		system("cls");
		End();
	}

	FileSize = GetFileSize(hFile, NULL);
	buffer = VirtualAlloc(NULL, FileSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

	if (!buffer)
	{
		system("cls");
		printf(skCrypt("[-] Unable to allocate memory for DLL data (%d)\n"), GetLastError());

		CloseHandle(hFile);
		Sleep(100);
		system("cls");
		End();
	}

	// Read the DLL

	if (!ReadFile(hFile, buffer, FileSize, &read, NULL))
	{
		system("cls");
		printf(skCrypt("[-] Unable to read the DLL (%d)\n"), GetLastError());

		VirtualFree(buffer, 0, MEM_RELEASE);
		CloseHandle(hFile);
		Sleep(100);
		system("cls");
		End();
	}

	CloseHandle(hFile);

	pIDH = (PIMAGE_DOS_HEADER)buffer;

	if (pIDH->e_magic != IMAGE_DOS_SIGNATURE)
	{
		system("cls");
		printf(skCrypt("[-] Invalid executable image\n"));

		VirtualFree(buffer, 0, MEM_RELEASE);
		Sleep(100);
		system("cls");
		End();
	}

	pINH = (PIMAGE_NT_HEADERS)((LPBYTE)buffer + pIDH->e_lfanew);

	if (pINH->Signature != IMAGE_NT_SIGNATURE)
	{
		system("cls");
		printf(skCrypt("[-] Invalid PE header\n"));

		VirtualFree(buffer, 0, MEM_RELEASE);
		End();
	}

	if (!(pINH->FileHeader.Characteristics & IMAGE_FILE_DLL))
	{
		system("cls");
		printf(skCrypt("[-] The image is not DLL\n"));

		VirtualFree(buffer, 0, MEM_RELEASE);
		End();
	}

	RtlAdjustPrivilege(20, TRUE, FALSE, &bl);

	ProcessId = PID;
	hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, ProcessId);

	if (!hProcess)
	{
		system("cls");
		printf(skCrypt("[-] Unable to open target process handle (%d)\n"), GetLastError());
		End();
	}

	image = VirtualAllocEx(hProcess, NULL, pINH->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE); // Allocate memory for the DLL

	if (!image)
	{
		system("cls");
		printf(skCrypt("[-] Unable to allocate memory for the DLL (%d)\n"), GetLastError());

		VirtualFree(buffer, 0, MEM_RELEASE);
		CloseHandle(hProcess);

		End();
	}

	// Copy the header to target process

	if (!WriteProcessMemory(hProcess, image, buffer, pINH->OptionalHeader.SizeOfHeaders, NULL))
	{
		system("cls");
		printf(skCrypt("[-] Unable to copy headers to target process (%d)\n"), GetLastError());

		VirtualFreeEx(hProcess, image, 0, MEM_RELEASE);
		CloseHandle(hProcess);

		VirtualFree(buffer, 0, MEM_RELEASE);
		End();
	}

	pISH = (PIMAGE_SECTION_HEADER)(pINH + 1);

	// Copy the DLL to target process

	for (i = 0; i < pINH->FileHeader.NumberOfSections; i++)
	{
		WriteProcessMemory(hProcess, (PVOID)((LPBYTE)image + pISH[i].VirtualAddress), (PVOID)((LPBYTE)buffer + pISH[i].PointerToRawData), pISH[i].SizeOfRawData, NULL);
	}

	mem1 = VirtualAllocEx(hProcess, NULL, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE); // Allocate memory for the loader code

	if (!mem1)
	{
		system("cls");
		printf(skCrypt("[-] Unable to allocate memory for the loader code (%d)\n"), GetLastError());

		VirtualFreeEx(hProcess, image, 0, MEM_RELEASE);
		CloseHandle(hProcess);

		VirtualFree(buffer, 0, MEM_RELEASE);
		End();
	}

	printf(skCrypt("[+] Loader code allocated at %#x\n"), mem1);
	memset(&ManualInject, 0, sizeof(MANUAL_INJECT));

	ManualInject.ImageBase = image;
	ManualInject.NtHeaders = (PIMAGE_NT_HEADERS)((LPBYTE)image + pIDH->e_lfanew);
	ManualInject.BaseRelocation = (PIMAGE_BASE_RELOCATION)((LPBYTE)image + pINH->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
	ManualInject.ImportDirectory = (PIMAGE_IMPORT_DESCRIPTOR)((LPBYTE)image + pINH->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
	ManualInject.fnLoadLibraryA = LoadLibraryA;
	ManualInject.fnGetProcAddress = GetProcAddress;


	if (!WriteProcessMemory(hProcess, mem1, &ManualInject, sizeof(MANUAL_INJECT), NULL))
		system("cls");
		printf(skCrypt("[-] Memory write error (%d)\n"), GetLastError());
	//std::cout << "LoadDllSize " << std::dec << (DWORD64)LoadDllEnd - (DWORD64)LoadDll << std::endl;

	// FIXED by removing optimiations : some fat fucking error here.. writing LoadDll directly appears to write a bunch of JMP instructions to undefined memory and the sizes are messed
	if (!WriteProcessMemory(hProcess, (PVOID)((PMANUAL_INJECT)mem1 + 1), LoadDll, 4096 - sizeof(MANUAL_INJECT), NULL))
		system("cls");
		printf(skCrypt("[-] Memory write error (%d)\n"), GetLastError());
	//std::cout << "LoadDllAddress " << std::hex << (PVOID)((PMANUAL_INJECT)mem1 + 1) << std::endl;

	hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);

	Thread32First(hSnap, &te32);

	int number = 0;
	while (Thread32Next(hSnap, &te32))
	{
		if (te32.th32OwnerProcessID == ProcessId)
		{
			if (number == TARGET_THREAD)
			{
				break;
			}
			number++;
		}
	}
	system("cls");
	printf(skCrypt("[+] Thread found on ID: %d\n"), te32.th32ThreadID);

	CloseHandle(hSnap);

	mem = VirtualAllocEx(hProcess, NULL, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

	if (!mem)
	{
		system("cls");
		printf(skCrypt("[-] Unable to allocate memory in target process (%d)\n"), GetLastError());

		CloseHandle(hProcess);
		End();
	}
	system("cls");
	printf(skCrypt("[+] Memory allocated at %#x\n"), mem);

	hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, te32.th32ThreadID);

	if (!hThread)
	{
		system("cls");
		printf(skCrypt("[-] Unable to open target thread handle (%d)\n"), GetLastError());

		VirtualFreeEx(hProcess, mem, 0, MEM_RELEASE);
		CloseHandle(hProcess);
		End();
	}

	SuspendThread(hThread);
	GetThreadContext(hThread, &ctx);

	buffer = VirtualAlloc(NULL, 65536, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	ptr = (LPBYTE)buffer;
	ZeroMemory(buffer, 65536);
	memcpy(buffer, code, sizeof(code));

	for (BYTE* ptr = (LPBYTE)buffer; ptr < ((LPBYTE)buffer + 300); ptr++)
	{
		DWORD64 address = *(DWORD64*)ptr;
		if (address == 0xCCCCCCCCCCCCCCCC)
		{
			system("cls");
			printf(skCrypt("[>] Writing param 1 (rcx)...\n"));
			*(DWORD64*)ptr = (DWORD64)mem1;
		}

		if (address == 0xAAAAAAAAAAAAAAAA)
		{
			system("cls");
			printf(skCrypt("[>] Writing function address (rax)...\n"));
			*(DWORD64*)ptr = (DWORD64)((PMANUAL_INJECT)mem1 + 1);
		}
	}

	if (!WriteProcessMemory(hProcess, mem, buffer, sizeof(code), NULL)) // + 0x4 because a DWORD is 0x4 big
	{
		system("cls");
		printf(skCrypt("[-] Unable to write shellcode into target process (%d)\n"), GetLastError());

		VirtualFreeEx(hProcess, mem, 0, MEM_RELEASE);
		ResumeThread(hThread);

		CloseHandle(hThread);
		CloseHandle(hProcess);

		VirtualFree(buffer, 0, MEM_RELEASE);
		End();
	}

	ctx.Rip = (DWORD64)mem;

	if (!SetThreadContext(hThread, &ctx))
	{
		system("cls");
		printf("[-] Unable to hijack target thread (%d)\n"), GetLastError();

		VirtualFreeEx(hProcess, mem, 0, MEM_RELEASE);
		ResumeThread(hThread);

		CloseHandle(hThread);
		CloseHandle(hProcess);

		VirtualFree(buffer, 0, MEM_RELEASE);
		End();
	}

	ResumeThread(hThread);

	CloseHandle(hThread);
	CloseHandle(hProcess);

	VirtualFree(buffer, 0, MEM_RELEASE);

	system("cls");
	printf(skCrypt("[+] Injected successfully\n"));

	/*printf(xorstr_("[>] Waiting... "));
	for (int i = 1; i <= 10; i++) 
	{
		printf(xorstr_(" %i "), i);
		Sleep(1000);
	}
	printf(xorstr_("\n[+] Wait complete\n"));*/

	system("cls");
	printf(skCrypt("[>] Restoring anticheat callbacks...\n"));
	CallbackSwitch(true);
	system("cls");
	printf(skCrypt("[+] Callbacks restored\n"));

	End();
}
