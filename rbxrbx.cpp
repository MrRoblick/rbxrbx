#include <iostream>
#include <rbxclient.h>
#include <optional>
#include <Windows.h>
#include <TlHelp32.h>
#include <processScanner.h>
#include <Roblox/info.h>
#include <thread>

#define EXTERNAL

int FindRoblox() {
	const std::optional<PROCESSENTRY32> proc = FindProcess(ROBLOX_CLIENT_NAME);
	return proc.has_value() ? (*proc).th32ProcessID : 0;
}

int main()
{
	int robloxProcessId = FindRoblox();
	if (robloxProcessId) {
		std::cout << "[INFO] Roblox found " << "{ " << robloxProcessId << " }\n";
	}
	else {
		
		std::cout << "[WARNING] Roblox not found, please open the roblox!\n";
		while (!robloxProcessId) {
			std::this_thread::sleep_for(std::chrono::seconds{ 1 });
			robloxProcessId = FindRoblox();
		}
		std::cout << "[INFO] Roblox found " << "{ " << robloxProcessId << " }\n";
	}
#ifdef EXTERNAL
	return runExternal();
#elif INTERNAL
	return runInternal();
#else
	MessageBox(NULL, TEXT("Unknown build"), TEXT("Error"), MB_ICONERROR);
	return 400;
#endif
}
