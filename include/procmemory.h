#pragma once
#include <Windows.h>
#include <ntdll.h>
#include <vector>
#include <optional>
#include <cstdint>
#include <string>

class Memory {
private:
	std::string processName;
	DWORD processId;
	HANDLE processHandle;

public:
	Memory(const std::string& processName);
	~Memory();
	
	template<typename T>
	bool Write(uintptr_t baseAddress, T* value, size_t size) const {
		return NtWriteVirtualMemory(processHandle, reinterpret_cast<PVOID>(baseAddress), reinterpret_cast<PVOID>(value), size, nullptr);
	}

	template<typename T>
	bool Read(uintptr_t baseAddress, T* value, size_t size) const {
		return NtReadVirtualMemory(processHandle, reinterpret_cast<PVOID>(baseAddress), reinterpret_cast<PVOID>(value), size, nullptr);
	}

	uintptr_t Alloc(size_t size) const;
	bool Free(const uintptr_t baseAddress, size_t size) const;

	ULONG Protect(const uintptr_t baseAddress, size_t size, const ULONG newProtection) const;

	HANDLE Call(const uintptr_t baseAddress, uintptr_t lpParameter) const;

	bool LockMemory(const uintptr_t baseAddress, size_t size) const;
	bool UnlockMemory(const uintptr_t baseAddress, size_t size) const;

	uintptr_t GetExecutableAddress() const;
	uintptr_t GetRemoteProcAddress(const std::wstring& dllName, const std::string& funcName) const;

	std::string GetProcessName() const;
	DWORD GetProcessId() const;

	std::vector<uintptr_t> FindAddresses(const std::string& patternStr) const;
	std::vector<uintptr_t> FindAddresses(const uintptr_t value) const;
};