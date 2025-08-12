#include <procmemory.h>
#include <string>
#include <optional>
#include <Windows.h>
#include <TlHelp32.h>
#include <stdexcept>
#include <vector>
#include <iostream>
#include <processScanner.h>
#include <locale>
#include <codecvt>
#include <algorithm>
#include <thread>
#include <mutex>
#include <functional>
#include <sstream>

struct RegionToScan {
	uintptr_t base;
	size_t size;
};

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

uintptr_t Memory::Alloc(size_t size) const {
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

bool Memory::Free(const uintptr_t baseAddress, size_t size) const {
	PVOID addr = reinterpret_cast<PVOID>(baseAddress);
	return NtFreeVirtualMemory(processHandle, &addr, &size, MEM_FREE);
}

ULONG Memory::Protect(const uintptr_t baseAddress, size_t size, const ULONG newProtection) const {
	ULONG oldProtect = 0;
	PVOID addr = reinterpret_cast<PVOID>(baseAddress);
	NtProtectVirtualMemory(processHandle, &addr, reinterpret_cast<PSIZE_T>(&size), newProtection, &oldProtect);
	return oldProtect;
}

HANDLE Memory::Call(const uintptr_t baseAddress, const uintptr_t lpParameter) const {
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

uintptr_t Memory::GetRemoteProcAddress(const std::wstring& dllName, const std::string& funcName) const {
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


bool Memory::LockMemory(const uintptr_t baseAddress, size_t size) const {
	PVOID base = reinterpret_cast<PVOID>(baseAddress);
	SIZE_T regionSize = size;
	return NtLockVirtualMemory(processHandle, &base, reinterpret_cast<PSIZE_T>(&size), 1);
}
bool Memory::UnlockMemory(const uintptr_t baseAddress, size_t size) const {
	PVOID base = reinterpret_cast<PVOID>(baseAddress);
	SIZE_T regionSize = size;
	return NtUnlockVirtualMemory(processHandle, &base, reinterpret_cast<PSIZE_T>(&size), 1);
}

uintptr_t Memory::GetExecutableAddress() const
{
	std::wstring_convert<std::codecvt_utf8<wchar_t>> conv;
	const std::wstring wstr = conv.from_bytes(processName);

	const std::optional<MODULEENTRY32W> mod = FindModuleW(processId, wstr);

	return mod.has_value() ? reinterpret_cast<uintptr_t>((*mod).modBaseAddr) : 0;
}

std::vector<std::optional<byte>> ParsePattern(const std::string& patternStr) {
	std::vector<std::optional<byte>> pattern;
	std::stringstream ss(patternStr);
	std::string token;

	while (ss >> token) {
		if (token == "?" || token == "??") {
			pattern.push_back(std::nullopt);
		}
		else {
			try {
				pattern.push_back(static_cast<byte>(std::stoi(token, nullptr, 16)));
			}
			catch (const std::invalid_argument& e) {
				std::cerr << "Invalid pattern token: " << token << std::endl;
				return {}; // Возвращаем пустой вектор при ошибке
			}
			catch (const std::out_of_range& e) {
				std::cerr << "Pattern token out of range: " << token << std::endl;
				return {};
			}
		}
	}
	return pattern;
}

std::vector<size_t> SearchInBuffer(const std::vector<byte>& buffer, const std::vector<std::optional<byte>>& pattern, SIZE_T bufferSize) {
	std::vector<size_t> offsets;
	const size_t patternSize = pattern.size();

	if (bufferSize < patternSize) {
		return offsets;
	}

	for (size_t i = 0; i <= bufferSize - patternSize; ++i) {
		bool match = true;
		for (size_t j = 0; j < patternSize; ++j) {
			if (pattern[j].has_value() && pattern[j].value() != buffer[i + j]) {
				match = false;
				break;
			}
		}
		if (match) {
			offsets.push_back(i);
		}
	}
	return offsets;
}

std::vector<size_t> SearchInBuffer(const std::vector<byte>& buffer, const std::vector<byte>& pattern, SIZE_T bufferSize) {
	std::vector<size_t> offsets;
	const size_t patternSize = pattern.size();

	if (bufferSize < patternSize) {
		return offsets;
	}

	for (size_t i = 0; i <= bufferSize - patternSize; ++i) {
		bool match = true;
		for (size_t j = 0; j < patternSize; ++j) {
			if (pattern[j] != buffer[i + j]) {
				match = false;
				break;
			}
		}
		if (match) {
			offsets.push_back(i);
		}
	}
	return offsets;
}

std::vector<uintptr_t> Memory::FindAddresses(const std::string& patternStr) const {
	const auto pattern = ParsePattern(patternStr);
	if (pattern.empty()) {
		return {};
	}

	std::vector<uintptr_t> results;
	uintptr_t currentAddr = 0;
	MEMORY_BASIC_INFORMATION mbi;

	while (VirtualQueryEx(processHandle, reinterpret_cast<LPCVOID>(currentAddr), &mbi, sizeof(mbi))) {
		const bool isReadable = (mbi.State == MEM_COMMIT) &&
			(mbi.Protect & (PAGE_READONLY | PAGE_READWRITE | PAGE_WRITECOPY | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)) &&
			!(mbi.Protect & (PAGE_GUARD | PAGE_NOACCESS));

		if (isReadable && mbi.RegionSize >= pattern.size()) {
			std::vector<byte> buffer(mbi.RegionSize);
			SIZE_T bytesRead;
			if (ReadProcessMemory(processHandle, mbi.BaseAddress, buffer.data(), mbi.RegionSize, &bytesRead)) {
				auto offsets = SearchInBuffer(buffer, pattern, bytesRead);
				for (const auto& offset : offsets) {
					results.push_back(reinterpret_cast<uintptr_t>(mbi.BaseAddress) + offset);
				}
			}
		}

		currentAddr = reinterpret_cast<uintptr_t>(mbi.BaseAddress) + mbi.RegionSize;
	}

	return results;
}

std::vector<uintptr_t> Memory::FindAddresses(const uintptr_t value) const {
	std::vector<byte> pattern;
	pattern.resize(sizeof(value));

	std::memcpy(pattern.data(), &value, sizeof(value));

	std::vector<uintptr_t> results;
	uintptr_t currentAddr = 0;
	MEMORY_BASIC_INFORMATION mbi;

	while (VirtualQueryEx(processHandle, reinterpret_cast<LPCVOID>(currentAddr), &mbi, sizeof(mbi))) {
		const bool isReadable = (mbi.State == MEM_COMMIT) &&
			(mbi.Protect & (PAGE_READONLY | PAGE_READWRITE | PAGE_WRITECOPY | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)) &&
			!(mbi.Protect & (PAGE_GUARD | PAGE_NOACCESS));

		if (isReadable && mbi.RegionSize >= pattern.size()) {
			std::vector<byte> buffer(mbi.RegionSize);
			SIZE_T bytesRead;
			if (ReadProcessMemory(processHandle, mbi.BaseAddress, buffer.data(), mbi.RegionSize, &bytesRead)) {
				auto offsets = SearchInBuffer(buffer, pattern, bytesRead);
				for (const auto& offset : offsets) {
					results.push_back(reinterpret_cast<uintptr_t>(mbi.BaseAddress) + offset);
				}
			}
		}

		currentAddr = reinterpret_cast<uintptr_t>(mbi.BaseAddress) + mbi.RegionSize;
	}

	return results;
}
