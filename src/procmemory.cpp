#include <procmemory.h>
#include <string>
#include <optional>
#include <Windows.h>
#include <TlHelp32.h>
#include <stdexcept>
#include <vector>
#include <iostream>

std::optional<PROCESSENTRY32> FindProcess(const std::string& name) {
	const HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	PROCESSENTRY32 proc{};
	proc.dwSize = sizeof(proc);

	if (!Process32First(snapshot, &proc)) {
		CloseHandle(snapshot);
		return std::nullopt;
	}
	do {
		if (name == proc.szExeFile) {
			CloseHandle(snapshot);
			return proc;
		}
	} while (Process32Next(snapshot, &proc));

	CloseHandle(snapshot);
	return std::nullopt;
}

Memory::Memory(const std::string& processName) : processName(processName){
	std::optional<PROCESSENTRY32> proc = FindProcess(processName);
	if (!proc.has_value()) {
		throw std::runtime_error("Failed to find process");
	}
	const HANDLE hwnd = OpenProcess(PROCESS_ALL_ACCESS, FALSE, (*proc).th32ProcessID);

	if (!hwnd) {
		throw std::runtime_error("Failed to open process");
	}
	this->processId = (*proc).th32ProcessID;
	this->processHandle = hwnd;
}

Memory::~Memory() {
	CloseHandle(processHandle);
}

uintptr_t Memory::Alloc(size_t size) {
	PVOID addr = 0;
	NtAllocateVirtualMemory(
		processHandle,
		&addr,
		NULL,
		&size,
		MEM_RESERVE | MEM_COMMIT,
		PAGE_EXECUTE_READWRITE
	);
	return reinterpret_cast<uintptr_t>(addr);
}

bool Memory::Free(uintptr_t baseAddress, size_t size) {
	PVOID addr = reinterpret_cast<PVOID>(baseAddress);
	return NtFreeVirtualMemory(processHandle, &addr, &size, MEM_FREE);
}

ULONG Memory::Protect(uintptr_t baseAddress, size_t size, ULONG newProtection) {
	ULONG oldProtect = 0;
	VirtualProtectEx(processHandle, reinterpret_cast<LPVOID>(baseAddress), size, newProtection, &oldProtect);
	return oldProtect;
}

HANDLE Memory::Call(uintptr_t baseAddress, uintptr_t lpParameter) {
	HANDLE threadHandle;
	NtCreateThreadEx(
		&threadHandle,
		THREAD_ALL_ACCESS,
		NULL,
		processHandle,
		reinterpret_cast<PUSER_THREAD_START_ROUTINE>(baseAddress),
		reinterpret_cast<PVOID>(lpParameter),
		0,
		0,
		0,
		0,
		NULL
	);
	return threadHandle;
}

std::string Memory::GetProcessName() const {
	return processName;
}

DWORD Memory::GetProcessId() const{
	return processId;
}

std::optional<MODULEENTRY32W> FindModuleW(DWORD processID, const std::wstring& name) {
	HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, processID);
	if (snapshot == INVALID_HANDLE_VALUE) {
		return std::nullopt;
	}

	MODULEENTRY32W module{};
	module.dwSize = sizeof(module);

	if (!Module32FirstW(snapshot, &module)) {
		CloseHandle(snapshot);
		return std::nullopt;
	}

	do {
		//std::printf("%ws\n", module.szModule);
		if (name == module.szModule) {
			
			CloseHandle(snapshot);
			return module;
		}
	} while (Module32NextW(snapshot, &module));

	CloseHandle(snapshot);
	return std::nullopt;
}
uintptr_t Memory::GetRemoteProcAddress(const std::wstring& dllName, const std::string& funcName) {
	std::optional<MODULEENTRY32W> mod = FindModuleW(processId, dllName);
	if (!mod.has_value()) {
		std::cerr << "Error: Module " << std::string(dllName.begin(), dllName.end()) << " not found\n";
		return 0;
	}
	const HMODULE remoteModuleBase = (*mod).hModule;
	std::cout << "Module base address: 0x" << std::hex << remoteModuleBase << std::endl;

	IMAGE_DOS_HEADER dosHeader{};
	if (!ReadProcessMemory(processHandle, remoteModuleBase, &dosHeader, sizeof(dosHeader), nullptr) ||
		dosHeader.e_magic != IMAGE_DOS_SIGNATURE) {
		std::cerr << "Error: Failed to read DOS header or invalid DOS signature\n";
		return 0;
	}

	IMAGE_NT_HEADERS ntHeaders{};
	LPVOID ntHeaderAddr = (LPBYTE)remoteModuleBase + dosHeader.e_lfanew;
	if (!ReadProcessMemory(processHandle, ntHeaderAddr, &ntHeaders, sizeof(ntHeaders), nullptr) ||
		ntHeaders.Signature != IMAGE_NT_SIGNATURE) {
		std::cerr << "Error: Failed to read NT headers or invalid NT signature\n";
		return 0;
	}

	const auto& expDirRVA = ntHeaders.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
	if (expDirRVA == 0) {
		std::cerr << "Error: No export directory found\n";
		return 0;
	}

	IMAGE_EXPORT_DIRECTORY expDir{};
	LPVOID expDirAddr = (LPBYTE)remoteModuleBase + expDirRVA;
	if (!ReadProcessMemory(processHandle, expDirAddr, &expDir, sizeof(expDir), nullptr)) {
		std::cerr << "Error: Failed to read export directory\n";
		return 0;
	}

	std::vector<DWORD> nameRVAs(expDir.NumberOfNames);
	std::vector<WORD> ordinals(expDir.NumberOfNames);
	std::vector<DWORD> funcRVAs(expDir.NumberOfFunctions);

	LPBYTE base = (LPBYTE)remoteModuleBase;

	if (!ReadProcessMemory(processHandle, base + expDir.AddressOfNames, nameRVAs.data(), nameRVAs.size() * sizeof(DWORD), nullptr)) {
		std::cerr << "Error: Failed to read AddressOfNames\n";
		return 0;
	}

	if (!ReadProcessMemory(processHandle, base + expDir.AddressOfNameOrdinals, ordinals.data(), ordinals.size() * sizeof(WORD), nullptr)) {
		std::cerr << "Error: Failed to read AddressOfNameOrdinals\n";
		return 0;
	}

	if (!ReadProcessMemory(processHandle, base + expDir.AddressOfFunctions, funcRVAs.data(), funcRVAs.size() * sizeof(DWORD), nullptr)) {
		std::cerr << "Error: Failed to read AddressOfFunctions\n";
		return 0;
	}

	for (size_t i = 0; i < nameRVAs.size(); ++i) {
		char buffer[256] = {};
		if (!ReadProcessMemory(processHandle, base + nameRVAs[i], buffer, sizeof(buffer) - 1, nullptr)) {
			std::cerr << "Error: Failed to read function name at index " << i << "\n";
			continue;
		}
		if (funcName == buffer) {
			WORD ordinalIndex = ordinals[i];
			if (ordinalIndex >= funcRVAs.size()) {
				std::cerr << "Error: Invalid ordinal index " << ordinalIndex << "\n";
				return 0;
			}
			DWORD funcRVA = funcRVAs[ordinalIndex];
			std::cout << "Found function " << funcName << " at RVA 0x" << std::hex << funcRVA << std::endl;
			return reinterpret_cast<uintptr_t>(remoteModuleBase) + funcRVA;
		}
	}

	std::cerr << "Error: Function " << funcName << " not found in export table\n";
	return 0;
}


bool Memory::LockMemory(uintptr_t baseAddress, size_t size) {
	PVOID base = reinterpret_cast<PVOID>(baseAddress);
	SIZE_T regionSize = size;
	return NtLockVirtualMemory(processHandle, &base, reinterpret_cast<PSIZE_T>(&size), 0);
}
bool Memory::UnlockMemory(uintptr_t baseAddress, size_t size) {
	PVOID base = reinterpret_cast<PVOID>(baseAddress);
	SIZE_T regionSize = size;
	return NtUnlockVirtualMemory(processHandle, &base, reinterpret_cast<PSIZE_T>(&size), 0);
}