#include <ntifs.h>
#include <ntstrsafe.h>
#include "Log.h"
#include "Callbacks.h"

/*
  Sorry for inconsistent types and naming. This code was ported from
  one driver to another and I have lost a track of it (little bit).
*/

// https://www.unknowncheats.me/forum/arma-2-a/175227-driver-disable-process-thread-object-callbacks.html

// https://docs.microsoft.com/en-us/windows-hardware/drivers/ifs/allocated-altitudes
#define DRIVER_ALT "327530"

/// <summary>
/// Dummy precallback
/// </summary>
/// <returns>Dummy status</returns>
OB_PREOP_CALLBACK_STATUS DummyObjectPreCallback(PVOID RegistrationContext, POB_PRE_OPERATION_INFORMATION OperationInformation) 
{
	UNREFERENCED_PARAMETER(RegistrationContext);
	UNREFERENCED_PARAMETER(OperationInformation);
	return(OB_PREOP_SUCCESS);
}

/// <summary>
/// Dummy postcallback
/// </summary>
/// <returns>Dummy status</returns>
VOID DummyObjectPostCallback(PVOID RegistrationContext, POB_POST_OPERATION_INFORMATION OperationInformation) 
{
	UNREFERENCED_PARAMETER(RegistrationContext);
	UNREFERENCED_PARAMETER(OperationInformation);
	return;
}

/// <summary>
/// Bruteforces offset
/// </summary>
/// <returns>Callback offset</returns>
QWORD GetCallbackListOffset() 
{
	POBJECT_TYPE procType = *PsProcessType;

	__try {
		if (procType && MmIsAddressValid((void*)procType)) {
			for (int i = 0xF8; i > 0; i -= 8) {
				QWORD first = *(QWORD*)((QWORD)procType + i), second = *(QWORD*)((QWORD)procType + (i + 8));
				if (first && MmIsAddressValid((void*)first) && second && MmIsAddressValid((void*)second)) {
					QWORD test1First = *(QWORD*)(first + 0x0), test1Second = *(QWORD*)(first + 0x8);
					if (test1First && MmIsAddressValid((void*)test1First) && test1Second && MmIsAddressValid((void*)test1Second)) {
						QWORD testObjectType = *(QWORD*)(first + 0x20);
						if (testObjectType == (QWORD)procType)
							return((QWORD)i);
					}
				}
			}
		}
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {
		Log("There was fatal error in %s", __FUNCTION__);
		return(0);
	}

	return 0;
}

/// <summary>
/// Disables all anticheat callsback to allow access from usermode
/// </summary>
/// <param name="oldCallbacks">Pointer to callback object to we can restore them later</param>
/// <returns>Callback offset</returns>
void Disable(POLD_CALLBACKS oldCallbacks) {
	POBJECT_TYPE procType = *PsProcessType;
	if (procType && MmIsAddressValid((void*)procType)) {
		__try {
			QWORD callbackListOffset = GetCallbackListOffset();
			if (callbackListOffset && MmIsAddressValid((void*)((QWORD)procType + callbackListOffset))) {
				LIST_ENTRY* callbackList = (LIST_ENTRY*)((QWORD)procType + callbackListOffset);
				if (callbackList->Flink && MmIsAddressValid((void*)callbackList->Flink)) {
					CALLBACK_ENTRY_ITEM* firstCallback = (CALLBACK_ENTRY_ITEM*)callbackList->Flink;
					CALLBACK_ENTRY_ITEM* curCallback = firstCallback;

					do {
						// Make sure the callback is valid.
						if (curCallback && MmIsAddressValid((void*)curCallback) && MmIsAddressValid((void*)curCallback->CallbackEntry)) {
							ANSI_STRING altitudeAnsi = { 0 };
							UNICODE_STRING altitudeUni = curCallback->CallbackEntry->Altitude;
							RtlUnicodeStringToAnsiString(&altitudeAnsi, &altitudeUni, 1);

							if (!strcmp(altitudeAnsi.Buffer, DRIVER_ALT)) {
								if (curCallback->PreOperation) {
									oldCallbacks->PreOperationProc = (QWORD)curCallback->PreOperation;
									curCallback->PreOperation = DummyObjectPreCallback;
								}
								if (curCallback->PostOperation) {
									oldCallbacks->PostOperationProc = (QWORD)curCallback->PostOperation;
									curCallback->PostOperation = DummyObjectPostCallback;
								}
								RtlFreeAnsiString(&altitudeAnsi);
								break;
							}

							RtlFreeAnsiString(&altitudeAnsi);
						}

						// Get the next callback.
						curCallback = (CALLBACK_ENTRY_ITEM*)(curCallback->CallbackList.Flink);
					} while (curCallback != firstCallback);
				}
			}
		}
		__except (EXCEPTION_EXECUTE_HANDLER) {
			Log("There was fatal error in %s", __FUNCTION__);
			return;
		}
	}

	POBJECT_TYPE threadType = *PsThreadType;
	if (threadType && MmIsAddressValid((void*)threadType)) {
		__try {
			QWORD callbackListOffset = GetCallbackListOffset();
			if (callbackListOffset && MmIsAddressValid((void*)((QWORD)threadType + callbackListOffset))) {
				LIST_ENTRY* callbackList = (LIST_ENTRY*)((QWORD)threadType + callbackListOffset);
				if (callbackList->Flink && MmIsAddressValid((void*)callbackList->Flink)) {
					CALLBACK_ENTRY_ITEM* firstCallback = (CALLBACK_ENTRY_ITEM*)callbackList->Flink;
					CALLBACK_ENTRY_ITEM* curCallback = firstCallback;

					do {
						// Make sure the callback is valid.
						if (curCallback && MmIsAddressValid((void*)curCallback) && MmIsAddressValid((void*)curCallback->CallbackEntry)) {
							ANSI_STRING altitudeAnsi = { 0 };
							UNICODE_STRING altitudeUni = curCallback->CallbackEntry->Altitude;
							RtlUnicodeStringToAnsiString(&altitudeAnsi, &altitudeUni, 1);

							if (!strcmp(altitudeAnsi.Buffer, DRIVER_ALT)) {
								if (curCallback->PreOperation) {
									oldCallbacks->PreOperationThread = (QWORD)curCallback->PreOperation;
									curCallback->PreOperation = DummyObjectPreCallback;
								}
								if (curCallback->PostOperation) {
									oldCallbacks->PostOperationThread = (QWORD)curCallback->PostOperation;
									curCallback->PostOperation = DummyObjectPostCallback;
								}
								RtlFreeAnsiString(&altitudeAnsi);
								break;
							}

							RtlFreeAnsiString(&altitudeAnsi);
						}

						// Get the next callback.
						curCallback = (CALLBACK_ENTRY_ITEM*)(curCallback->CallbackList.Flink);
					} while (curCallback != firstCallback);
				}
			}
		}
		__except (EXCEPTION_EXECUTE_HANDLER) {
			Log("There was fatal error in %s", __FUNCTION__);
			return;
		}
	}
}

/// <summary>
/// Restores anticheat callbacks
/// </summary>
/// <param name="oldCallbacks">Pointer to callback object</param>
/// <returns>Callback offset</returns>
void Restore(POLD_CALLBACKS oldCallbacks) {
	POBJECT_TYPE procType = *PsProcessType;
	if (procType && MmIsAddressValid((void*)procType)) {
		__try {
			QWORD callbackListOffset = GetCallbackListOffset();
			if (callbackListOffset && MmIsAddressValid((void*)((QWORD)procType + callbackListOffset))) {
				LIST_ENTRY* callbackList = (LIST_ENTRY*)((QWORD)procType + callbackListOffset);
				if (callbackList->Flink && MmIsAddressValid((void*)callbackList->Flink)) {
					CALLBACK_ENTRY_ITEM* firstCallback = (CALLBACK_ENTRY_ITEM*)callbackList->Flink;
					CALLBACK_ENTRY_ITEM* curCallback = firstCallback;

					do {
						// Make sure the callback is valid.
						if (curCallback && MmIsAddressValid((void*)curCallback) && MmIsAddressValid((void*)curCallback->CallbackEntry)) {
							ANSI_STRING altitudeAnsi = { 0 };
							UNICODE_STRING altitudeUni = curCallback->CallbackEntry->Altitude;
							RtlUnicodeStringToAnsiString(&altitudeAnsi, &altitudeUni, 1);

							if (!strcmp(altitudeAnsi.Buffer, DRIVER_ALT)) {
								if (curCallback->PreOperation && oldCallbacks->PreOperationProc)
									curCallback->PreOperation = (POB_PRE_OPERATION_CALLBACK)oldCallbacks->PreOperationProc;
								if (curCallback->PostOperation && oldCallbacks->PostOperationProc)
									curCallback->PostOperation = (POB_POST_OPERATION_CALLBACK)oldCallbacks->PostOperationProc;
								RtlFreeAnsiString(&altitudeAnsi);
								break;
							}

							RtlFreeAnsiString(&altitudeAnsi);
						}

						// Get the next callback.
						curCallback = (CALLBACK_ENTRY_ITEM*)(curCallback->CallbackList.Flink);
					} while (curCallback != firstCallback);
				}
			}
		}
		__except (EXCEPTION_EXECUTE_HANDLER) {
			Log("There was fatal error in %s", __FUNCTION__);
			return;
		}
	}

	POBJECT_TYPE threadType = *PsThreadType;
	if (threadType && MmIsAddressValid((void*)threadType)) {
		__try {
			QWORD callbackListOffset = GetCallbackListOffset();
			if (callbackListOffset && MmIsAddressValid((void*)((QWORD)threadType + callbackListOffset))) {
				LIST_ENTRY* callbackList = (LIST_ENTRY*)((QWORD)threadType + callbackListOffset);
				if (callbackList->Flink && MmIsAddressValid((void*)callbackList->Flink)) {
					CALLBACK_ENTRY_ITEM* firstCallback = (CALLBACK_ENTRY_ITEM*)callbackList->Flink;
					CALLBACK_ENTRY_ITEM* curCallback = firstCallback;

					do {
						// Make sure the callback is valid.
						if (curCallback && MmIsAddressValid((void*)curCallback) && MmIsAddressValid((void*)curCallback->CallbackEntry)) {
							ANSI_STRING altitudeAnsi = { 0 };
							UNICODE_STRING altitudeUni = curCallback->CallbackEntry->Altitude;
							RtlUnicodeStringToAnsiString(&altitudeAnsi, &altitudeUni, 1);

							if (!strcmp(altitudeAnsi.Buffer, DRIVER_ALT)) {
								if (curCallback->PreOperation && oldCallbacks->PreOperationThread)
									curCallback->PreOperation = (POB_PRE_OPERATION_CALLBACK)oldCallbacks->PreOperationThread;
								if (curCallback->PostOperation && oldCallbacks->PostOperationThread)
									curCallback->PostOperation = (POB_POST_OPERATION_CALLBACK)oldCallbacks->PostOperationThread;
								RtlFreeAnsiString(&altitudeAnsi);
								break;
							}

							RtlFreeAnsiString(&altitudeAnsi);
						}

						// Get the next callback.
						curCallback = (CALLBACK_ENTRY_ITEM*)(curCallback->CallbackList.Flink);
					} while (curCallback != firstCallback);
				}
			}
		}
		__except (EXCEPTION_EXECUTE_HANDLER) {
			Log("There was fatal error in %s", __FUNCTION__);
			return;
		}
	}
}