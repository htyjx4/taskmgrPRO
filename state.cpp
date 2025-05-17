#include <winternl.h>
#include<windows.h>
#pragma once
typedef struct _MYSYSTEM_PROCESS_INFORMATION {
	ULONG NextEntryOffset;
	ULONG NumberOfThreads;
	LARGE_INTEGER Reserved[3];
	LARGE_INTEGER CreateTime;
	LARGE_INTEGER UserTime;
	LARGE_INTEGER KernelTime;
	UNICODE_STRING ImageName;
	KPRIORITY BasePriority;
	HANDLE UniqueProcessId;
	HANDLE InheritedFromUniqueProcessId;
	ULONG HandleCount;
	ULONG SessionId;
	ULONG PageDirectoryBase;
	VM_COUNTERS VirtualMemoryCounters;
	SIZE_T PrivatePageCount;
	IO_COUNTERS IoCounters;
	SYSTEM_THREAD_INFORMATION Threads[0];
} MYSYSTEM_PROCESS_INFORMATION, *PMYSYSTEM_PROCESS_INFORMATION;
#define SYSTEM_PROCESS_INFORMATION MYSYSTEM_PROCESS_INFORMATION
#define PSYSTEM_PROCESS_INFORMATION PMYSYSTEM_PROCESS_INFORMATION
typedef NTSTATUS(NTSYSAPI NTAPI *FunNtQuerySystemInformation)
(IN SYSTEM_INFORMATION_CLASS SystemInformationClass, IN OUT PVOID SystemInformation,
 IN ULONG SystemInformationLength, OUT PULONG ReturnLength OPTIONAL);
int getprocessstate(DWORD dwProcessID) {
	int nStatus = -1;
	FunNtQuerySystemInformation mNtQuerySystemInformation = FunNtQuerySystemInformation(GetProcAddress(GetModuleHandle("ntdll.dll"), "NtQuerySystemInformation"));
	DWORD dwSize;
	mNtQuerySystemInformation(SystemProcessInformation, NULL, 0, &dwSize);
	HGLOBAL hBuffer = GlobalAlloc(LPTR, dwSize);
	if (hBuffer == NULL)
		return nStatus;
	PSYSTEM_PROCESS_INFORMATION pInfo = PSYSTEM_PROCESS_INFORMATION(hBuffer);
	NTSTATUS lStatus = mNtQuerySystemInformation(SystemProcessInformation, pInfo, dwSize, 0);
	if (!NT_SUCCESS(lStatus)) {
		GlobalFree(hBuffer);
		return nStatus;
	}
	while (true) {
		if (((DWORD)(ULONG_PTR) pInfo->UniqueProcessId) == dwProcessID) {
			nStatus = 1;
			for (ULONG i = 0; i < pInfo->NumberOfThreads; i++) {
				if (pInfo->Threads[i].WaitReason != Suspended) {
					nStatus = 0;
					break;
				}
			}
			break;
		}
		if (pInfo->NextEntryOffset == 0)
			break;
		pInfo = PSYSTEM_PROCESS_INFORMATION(PBYTE(pInfo) + pInfo->NextEntryOffset);
	}
	GlobalFree(hBuffer);
	return nStatus;
}
