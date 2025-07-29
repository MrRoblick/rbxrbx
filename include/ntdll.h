#pragma once
#include <Windows.h>
#include <winternl.h>

using NTSTATUS = long;

typedef enum _MEMORY_INFORMATION_CLASS {
    MemoryBasicInformation,           // 0
    MemoryWorkingSetInformation,      // 1
    MemoryMappedFilenameInformation,  // 2
    MemoryRegionInformation,          // 3
    MemoryWorkingSetExInformation,    // 4
    MemorySharedCommitInformation,    // 5
    MemoryImageInformation,           // 6
    MemoryRegionInformationEx,        // 7
    MemoryPrivilegedBasicInformation, // 8
    MemoryEnclaveImageInformation,    // 9
    MemoryBasicInformationCapped      // 10
} MEMORY_INFORMATION_CLASS;
typedef _Function_class_(USER_THREAD_START_ROUTINE)
NTSTATUS NTAPI USER_THREAD_START_ROUTINE(
    _In_ PVOID ThreadParameter
);
typedef struct _PS_ATTRIBUTE
{
    ULONG_PTR Attribute;
    SIZE_T Size;
    union
    {
        ULONG_PTR Value;
        PVOID ValuePtr;
    };
    PSIZE_T ReturnLength;
} PS_ATTRIBUTE, * PPS_ATTRIBUTE;

typedef struct _PS_ATTRIBUTE_LIST
{
    SIZE_T TotalLength;
    PS_ATTRIBUTE Attributes[1];
} PS_ATTRIBUTE_LIST, * PPS_ATTRIBUTE_LIST;

typedef USER_THREAD_START_ROUTINE* PUSER_THREAD_START_ROUTINE;

typedef NTSTATUS (*NtReadVirtualMemory_proc)(HANDLE ProcessHandle, PVOID BaseAddress, PVOID Buffer, SIZE_T NumberOfBytesToRead, PSIZE_T NumberOfBytesRead);
typedef NTSTATUS (*NtWriteVirtualMemory_proc)(HANDLE ProcessHandle, PVOID BaseAddress, PVOID Buffer, SIZE_T NumberOfBytesToWrite, PSIZE_T NumberOfBytesWritten);
typedef NTSTATUS (*NtAllocateVirtualMemory_proc)(HANDLE ProcessHandle, PVOID* BaseAddress, ULONG_PTR ZeroBits, PSIZE_T RegionSize, ULONG AllocationType, ULONG PageProtection);
typedef NTSTATUS (*NtFreeVirtualMemory_proc)(HANDLE ProcessHandle, PVOID* BaseAddress, PSIZE_T RegionSize, ULONG FreeType);
typedef NTSTATUS (*NtProtectVirtualMemory_proc)(HANDLE ProcessHandle, PVOID* BaseAddress, PSIZE_T RegionSize, ULONG NewProtection, PULONG OldProtection);
typedef NTSTATUS (*NtQueryVirtualMemory_proc)(HANDLE ProcessHandle, PVOID BaseAddress, MEMORY_INFORMATION_CLASS MemoryInformationClass, PVOID MemoryInformation, SIZE_T MemoryInformationLength, PSIZE_T ReturnLength);
typedef NTSTATUS (*NtCreateThreadEx_proc)(PHANDLE ThreadHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, HANDLE ProcessHandle, PUSER_THREAD_START_ROUTINE StartRoutine, PVOID Argument, ULONG CreateFlags, SIZE_T ZeroBits, SIZE_T StackSize, SIZE_T MaximumStackSize, PPS_ATTRIBUTE_LIST AttributeList);
typedef NTSTATUS (*NtLockVirtualMemory_proc)(HANDLE ProcessHandle, PVOID* BaseAddress, PSIZE_T RegionSize, ULONG MapType);
typedef NTSTATUS (*NtUnlockVirtualMemory_proc)(HANDLE ProcessHandle, PVOID* BaseAddress, PSIZE_T RegionSize, ULONG MapType);

extern const HMODULE ntdll;
extern NtReadVirtualMemory_proc NtReadVirtualMemory;
extern NtWriteVirtualMemory_proc NtWriteVirtualMemory;
extern NtAllocateVirtualMemory_proc NtAllocateVirtualMemory;
extern NtFreeVirtualMemory_proc NtFreeVirtualMemory;
extern NtProtectVirtualMemory_proc NtProtectVirtualMemory;
extern NtQueryVirtualMemory_proc NtQueryVirtualMemory;
extern NtCreateThreadEx_proc NtCreateThreadEx;
extern NtLockVirtualMemory_proc NtLockVirtualMemory;
extern NtUnlockVirtualMemory_proc NtUnlockVirtualMemory;


extern PVOID ZwContinueRaw;
extern size_t ZwContinueRawSize;