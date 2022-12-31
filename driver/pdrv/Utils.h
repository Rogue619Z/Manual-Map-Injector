#pragma once

NTSTATUS SearchPattern(IN PCUCHAR pattern, IN UCHAR wildcard, IN ULONG_PTR len, IN const VOID* base, IN ULONG_PTR size, OUT PVOID* ppFound);
char* GetName(IN HANDLE pid);
BOOLEAN IsPartOf(IN char* w1, IN char* w2);
void SwitchMode(IN BOOLEAN Restore);