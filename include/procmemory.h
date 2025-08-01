#pragma once
#include <Windows.h>
#include <string>
#include <ntdll.h>


class Memory {
private:
	std::string m_process_name;
	DWORD m_process_id;
	HANDLE m_process_handle;

public:
	Memory(const std::string& process_name);
	~Memory();
	
	template<typename T>
	bool write(uintptr_t base_address, T* value, size_t size) {
		return NtWriteVirtualMemory(
			process_handle, reinterpret_cast<PVOID>(base_address), 
			reinterpret_cast<PVOID>(value), size, nullptr
		);
	}

	template<typename T>
	bool read(uintptr_t base_address, T* value, size_t size) {
		return NtReadVirtualMemory(
			processHandle, reinterpret_cast<PVOID>(baseAddress), 
			reinterpret_cast<PVOID>(value), size, nullptr
		);
	}

	uintptr_t alloc(size_t size);
	bool free(uintptr_t base_address, size_t size);

	ULONG protect(uintptr_t base_address, size_t size, ULONG new_protection);

	HANDLE call(uintptr_t base_address, uintptr_t lpParameter);

	bool lockMemory(uintptr_t baseAddress, size_t size);
	bool unlockMemory(uintptr_t baseAddress, size_t size);

	uintptr_t getRemoteProcAddress(const std::wstring& dllName, const std::string& funcName);

	std::string getProcessName() const;
	DWORD getProcessId() const;
};