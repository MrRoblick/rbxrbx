#pragma once
#include <Windows.h>
#include <optional>
#include <TlHelp32.h>
#include <string>

std::optional<PROCESSENTRY32> FindProcess(const std::string& name);
std::optional<MODULEENTRY32W> FindModuleW(const DWORD processID, const std::wstring& name);