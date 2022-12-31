#pragma once

#define WORD USHORT
#define QWORD UINT64

// OLD_CALLBACKS
typedef struct _OLD_CALLBACKS {
	QWORD PreOperationProc;
	QWORD PostOperationProc;
	QWORD PreOperationThread;
	QWORD PostOperationThread;
} OLD_CALLBACKS, * POLD_CALLBACKS;

// CALLBACK_ENTRY
typedef struct _CALLBACK_ENTRY {
	WORD Version; // 0x0
	WORD OperationRegistrationCount; // 0x2
	DWORD unk1; // 0x4
	PVOID RegistrationContext; // 0x8
	UNICODE_STRING Altitude; // 0x10
} CALLBACK_ENTRY, * PCALLBACK_ENTRY; // header size: 0x20 (0x6C if you count the array afterwards - this is only the header. The array of CALLBACK_ENTRY_ITEMs is useless.)

// CALLBACK_ENTRY_ITEM
typedef struct _CALLBACK_ENTRY_ITEM {
	LIST_ENTRY CallbackList; // 0x0
	OB_OPERATION Operations; // 0x10
	DWORD Active; // 0x14
	CALLBACK_ENTRY* CallbackEntry; // 0x18
	PVOID ObjectType; // 0x20
	POB_PRE_OPERATION_CALLBACK PreOperation; // 0x28
	POB_POST_OPERATION_CALLBACK PostOperation; // 0x30
	QWORD unk1; // 0x38
} CALLBACK_ENTRY_ITEM, * PCALLBACK_ENTRY_ITEM; // size: 0x40

void Disable(POLD_CALLBACKS oldCallbacks);
void Restore(POLD_CALLBACKS oldCallbacks);