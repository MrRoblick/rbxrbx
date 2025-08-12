#include <processScanner.h>
#include <Windows.h>
#include <optional>
#include <TlHelp32.h>
#include <string>

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

std::optional<MODULEENTRY32W> FindModuleW(const DWORD processID, const std::wstring& name) {
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