#pragma once
#include <Windows.h>
#include <string>
#include <ntdll.h>


class Memory {
private:
	std::string processName;
	DWORD processId;
	HANDLE processHandle;

public:
	Memory(const std::string& processName);
	~Memory();
	
	template<typename T>
	bool Write(uintptr_t baseAddress, T* value, size_t size) {
		return NtWriteVirtualMemory(processHandle, reinterpret_cast<PVOID>(baseAddress), reinterpret_cast<PVOID>(value), size, nullptr);
	}

	template<typename T>
	bool Read(uintptr_t baseAddress, T* value, size_t size) {
		return NtReadVirtualMemory(processHandle, reinterpret_cast<PVOID>(baseAddress), reinterpret_cast<PVOID>(value), size, nullptr);
	}

	uintptr_t Alloc(size_t size);
	bool Free(uintptr_t baseAddress, size_t size);

	ULONG Protect(uintptr_t baseAddress, size_t size, ULONG newProtection);

	HANDLE Call(uintptr_t baseAddress, uintptr_t lpParameter);

	bool LockMemory(uintptr_t baseAddress, size_t size);
	bool UnlockMemory(uintptr_t baseAddress, size_t size);

	uintptr_t GetRemoteProcAddress(const std::wstring& dllName, const std::string& funcName);

	std::string GetProcessName() const;
	DWORD GetProcessId() const;
};