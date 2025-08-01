#include <procmemory.h>
#include <string>
#include <optional>
#include <Windows.h>
#include <TlHelp32.h>
#include <stdexcept>
#include <vector>
#include <iostream>

static std::optional<PROCESSENTRY32> findProcess(const std::string& name) {
	struct Snapshot {
		HANDLE handle;
		Snapshot() : handle(CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)) {}
		~Snapshot() { CloseHandle(handle); }
	};
	const Snapshot snapshot{};
	PROCESSENTRY32 proc{};
	proc.dwSize = sizeof(proc);
	for (
		bool success = Process32First(snapshot.handle, &proc);
		success;
		Process32Next(snapshot.handle, &proc)
	) {
		if (name == proc.szExeFile) return proc;
	}
	return std::nullopt;
}

Memory::Memory(const std::string& process_name) : m_process_name(process_name){
	std::optional<PROCESSENTRY32> proc = findProcess(process_name);
	if (!proc.has_value()) {
		throw std::runtime_error("Failed to find process");
	}
	const HANDLE handle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, (*proc).th32ProcessID);

	if (!handle) {
		throw std::runtime_error("Failed to open process");
	}
	this->m_process_id = (*proc).th32ProcessID;
	this->m_process_handle = handle;
}

Memory::~Memory() {
	CloseHandle(m_process_handle);
}

uintptr_t Memory::alloc(size_t size) {
	PVOID addr = 0;
	NtAllocateVirtualMemory(
		m_process_handle,
		&addr,
		NULL,
		&size,
		MEM_RESERVE | MEM_COMMIT,
		PAGE_EXECUTE_READWRITE
	);
	return reinterpret_cast<uintptr_t>(addr);
}

bool Memory::free(uintptr_t base_address, size_t size) {
	PVOID addr = reinterpret_cast<PVOID>(base_address);
	return NtFreeVirtualMemory(m_process_handle, &addr, &size, MEM_FREE);
}

ULONG Memory::protect(uintptr_t base_address, size_t size, ULONG new_protection) {
	ULONG oldProtect = 0;
	VirtualProtectEx(m_process_handle, reinterpret_cast<LPVOID>(base_address), size, new_protection, &oldProtect);
	return oldProtect;
}

HANDLE Memory::call(uintptr_t base_address, uintptr_t lp_parameter) {
	HANDLE thread_handle;
	NtCreateThreadEx(
		&thread_handle,
		THREAD_ALL_ACCESS,
		NULL,
		m_process_handle,
		reinterpret_cast<PUSER_THREAD_START_ROUTINE>(base_address),
		reinterpret_cast<PVOID>(lp_parameter),
		0,
		0,
		0,
		0,
		NULL
	);
	return thread_handle;
}

std::string Memory::getProcessName() const {
	return m_process_name;
}

DWORD Memory::getProcessId() const{
	return m_process_id;
}

static std::optional<MODULEENTRY32W> findModuleW(DWORD process_id, const std::wstring& name) {
	HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, process_id);
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
uintptr_t Memory::getRemoteProcAddress(const std::wstring& dll_name, const std::string& func_name) {
	std::optional<MODULEENTRY32W> mod = findModuleW(m_process_id, dll_name);
	if (!mod.has_value()) {
		std::cerr << "Error: Module " << std::string(dll_name.begin(), dll_name.end()) << " not found\n";
		return 0;
	}
	const HMODULE remote_module_base = (*mod).hModule;
	std::cout << "Module base address: 0x" << std::hex << remote_module_base << std::endl;

	IMAGE_DOS_HEADER dos_header{};
	if (!ReadProcessMemory(m_process_handle, remote_module_base, &dos_header, sizeof(dos_header), nullptr) ||
		dos_header.e_magic != IMAGE_DOS_SIGNATURE) {
		std::cerr << "Error: Failed to read DOS header or invalid DOS signature\n";
		return 0;
	}

	IMAGE_NT_HEADERS nt_headers{};
	LPVOID nt_header_addr = (LPBYTE)remote_module_base + dos_header.e_lfanew;
	if (!ReadProcessMemory(m_process_handle, nt_header_addr, &nt_headers, sizeof(nt_headers), nullptr) ||
		nt_headers.Signature != IMAGE_NT_SIGNATURE) {
		std::cerr << "Error: Failed to read NT headers or invalid NT signature\n";
		return 0;
	}

	const auto& exp_dir_rva = nt_headers.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
	if (exp_dir_rva == 0) {
		std::cerr << "Error: No export directory found\n";
		return 0;
	}

	IMAGE_EXPORT_DIRECTORY exp_dir{};
	LPVOID exp_dir_addr = (LPBYTE)remote_module_base + exp_dir_rva;
	if (!ReadProcessMemory(m_process_handle, exp_dir_addr, &exp_dir, sizeof(exp_dir), nullptr)) {
		std::cerr << "Error: Failed to read export directory\n";
		return 0;
	}

	std::vector<DWORD> names_rva(exp_dir.NumberOfNames);
	std::vector<WORD> ordinals(exp_dir.NumberOfNames);
	std::vector<DWORD> funcs_rva(exp_dir.NumberOfFunctions);

	LPBYTE base = (LPBYTE) remote_module_base;

	if (!ReadProcessMemory(m_process_handle, base + exp_dir.AddressOfNames, names_rva.data(), names_rva.size() * sizeof(DWORD), nullptr)) {
		std::cerr << "Error: Failed to read AddressOfNames\n";
		return 0;
	}

	if (!ReadProcessMemory(
		m_process_handle, base + exp_dir.AddressOfNameOrdinals,
		ordinals.data(), ordinals.size() * sizeof(WORD), nullptr)
	) {
		std::cerr << "Error: Failed to read AddressOfNameOrdinals\n";
		return 0;
	}

	if (!ReadProcessMemory(
		m_process_handle, base + exp_dir.AddressOfFunctions,
		funcs_rva.data(), funcs_rva.size() * sizeof(DWORD), nullptr)
	) {
		std::cerr << "Error: Failed to read AddressOfFunctions\n";
		return 0;
	}

	for (size_t i = 0; i < names_rva.size(); ++i) {
		char buffer[256] = {};
		if (!ReadProcessMemory(m_process_handle, base + names_rva[i], buffer, sizeof(buffer) - 1, nullptr)) {
			std::cerr << "Error: Failed to read function name at index " << i << "\n";
			continue;
		}
		if (func_name == buffer) {
			WORD ordinal_index = ordinals[i];
			if (ordinal_index >= funcs_rva.size()) {
				std::cerr << "Error: Invalid ordinal index " << ordinal_index << "\n";
				return 0;
			}
			DWORD func_rva = funcs_rva[ordinal_index];
			std::cout << "Found function " << func_name << " at RVA 0x" << std::hex << func_rva << std::endl;
			return reinterpret_cast<uintptr_t>(remote_module_base) + func_rva;
		}
	}

	std::cerr << "Error: Function " << func_name << " not found in export table\n";
	return 0;
}


bool Memory::lockMemory(uintptr_t base_address, size_t size) {
	PVOID base = reinterpret_cast<PVOID>(base_address);
	SIZE_T regionSize = size;
	return NtLockVirtualMemory(m_process_handle, &base, reinterpret_cast<PSIZE_T>(&size), 0);
}
bool Memory::unlockMemory(uintptr_t base_address, size_t size) {
	PVOID base = reinterpret_cast<PVOID>(base_address);
	SIZE_T regionSize = size;
	return NtUnlockVirtualMemory(m_process_handle, &base, reinterpret_cast<PSIZE_T>(&size), 0);
}