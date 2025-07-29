#include <ntdll.h>

const HMODULE ntdll = GetModuleHandleA("ntdll.dll");

NtReadVirtualMemory_proc NtReadVirtualMemory = reinterpret_cast<NtReadVirtualMemory_proc>(GetProcAddress(ntdll, "NtReadVirtualMemory"));
NtWriteVirtualMemory_proc NtWriteVirtualMemory = reinterpret_cast<NtWriteVirtualMemory_proc>(GetProcAddress(ntdll, "NtWriteVirtualMemory"));
NtAllocateVirtualMemory_proc NtAllocateVirtualMemory = reinterpret_cast<NtAllocateVirtualMemory_proc>(GetProcAddress(ntdll, "NtAllocateVirtualMemory"));
NtFreeVirtualMemory_proc NtFreeVirtualMemory = reinterpret_cast<NtFreeVirtualMemory_proc>(GetProcAddress(ntdll, "NtFreeVirtualMemory"));
NtProtectVirtualMemory_proc NtProtectVirtualMemory = reinterpret_cast<NtProtectVirtualMemory_proc>(GetProcAddress(ntdll, "NtProtectVirtualMemory"));
NtQueryVirtualMemory_proc NtQueryVirtualMemory = reinterpret_cast<NtQueryVirtualMemory_proc>(GetProcAddress(ntdll, "NtQueryVirtualMemory"));
NtCreateThreadEx_proc NtCreateThreadEx = reinterpret_cast<NtCreateThreadEx_proc>(GetProcAddress(ntdll, "NtCreateThreadEx"));
NtLockVirtualMemory_proc NtLockVirtualMemory = reinterpret_cast<NtLockVirtualMemory_proc>(GetProcAddress(ntdll, "NtLockVirtualMemory"));
NtUnlockVirtualMemory_proc NtUnlockVirtualMemory = reinterpret_cast<NtUnlockVirtualMemory_proc>(GetProcAddress(ntdll, "NtUnlockVirtualMemory"));


PVOID ZwContinueRaw = reinterpret_cast<PVOID>(GetProcAddress(ntdll, "ZwContinue"));
size_t ZwContinueRawSize = 31;