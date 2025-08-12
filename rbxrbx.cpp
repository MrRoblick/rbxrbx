#include <iostream>
#include <Windows.h>
#include <TlHelp32.h>
#include <string>
#include <optional>
#include <expected>
#include <winternl.h>
#include <format>
#include <vector>
#include <memory.h>

#include <procmemory.h>

struct Payload {
	uintptr_t messageBoxAAddr;
	uintptr_t text;
	uintptr_t caption;
	uintptr_t exitThreadAddr;
};

int main()
{
	Memory client{ "RobloxPlayerBeta.exe" };
	std::cout << "process id: " << client.GetProcessId() << std::endl;


	const uintptr_t messageBoxAAddr = client.GetRemoteProcAddress(L"USER32.dll", "MessageBoxA");
	const uintptr_t exitThreadAddr = client.GetRemoteProcAddress(L"KERNEL32.DLL", "ExitThread");
	const uintptr_t ntdllZwContinueAddr = client.GetRemoteProcAddress(L"ntdll.dll", "ZwContinue");
	std::cout << "Message box address: " << std::hex << messageBoxAAddr << std::endl;
	std::cout << "ExitThread address: " << std::hex << exitThreadAddr << std::endl;
	std::cout << "ZwContinue address: " << std::hex << ntdllZwContinueAddr << std::endl;
	byte buf[31] = { 0 };

	std::cout << "Old: ";
	client.Read(ntdllZwContinueAddr, buf, sizeof(buf));
	for (byte i : buf) {
		std::cout << std::hex << static_cast<uint32_t>(i) << ", ";
	}
	std::cout << std::endl;

	ULONG oldProtect = client.Protect(ntdllZwContinueAddr, ZwContinueRawSize, PAGE_EXECUTE_READWRITE);
	client.Write(ntdllZwContinueAddr, ZwContinueRaw, ZwContinueRawSize);
	client.Protect(ntdllZwContinueAddr, ZwContinueRawSize, oldProtect);

	std::cout << "New: ";
	client.Read(ntdllZwContinueAddr, buf, sizeof(buf));
	for (byte i : buf) {
		std::cout << std::hex << static_cast<uint32_t>(i) << ", ";
	}
	std::cout << std::endl;

	byte shellcode[] = {
		0x48, 0x83, 0xEC, 0x28,       // sub rsp, 0x28         ; Выделение 40 байт (32 теневое + 8 для выравнивания)
		0x48, 0x8B, 0x01,             // mov rax, [rcx]        ; Адрес MessageBoxA в rax
		0x48, 0x8B, 0x51, 0x08,       // mov rdx, [rcx+8]      ; Аргумент #2: lpText
		0x4C, 0x8B, 0x41, 0x10,       // mov r8, [rcx+16]      ; Аргумент #3: lpCaption
		0x31, 0xC9,                   // xor ecx, ecx          ; Аргумент #1: hWnd = 0
		0x45, 0x31, 0xC9,             // xor r9d, r9d          ; Аргумент #4: uType = 0 (MB_OK)
		0xFF, 0xD0,                   // call rax              ; Вызов MessageBoxA

		0x48, 0x83, 0xC4, 0x28,       // add rsp, 0x28         ; Очистка стека

		0xC3, // ret
	};

	uintptr_t addr = client.Alloc(sizeof(shellcode));
	client.Write(addr, reinterpret_cast<byte*>(shellcode), sizeof(shellcode));
	std::cout << "shellcode: " << std::hex << addr << std::endl;

	char textData[] = "Hello World!";
	uintptr_t addrText = client.Alloc(strlen(textData) + 1);
	client.Write(addrText, textData, strlen(textData) + 1);

	char captionData[] = "Real caption!";
	uintptr_t addrCaption = client.Alloc(strlen(captionData) + 1);
	client.Write(addrCaption, captionData, strlen(captionData) + 1);


	

	Payload pl{};
	pl.caption = addrCaption;
	pl.text = addrText;
	pl.messageBoxAAddr = messageBoxAAddr;
	pl.exitThreadAddr = exitThreadAddr;

	uintptr_t payloadAddr = client.Alloc(sizeof(pl));
	client.Write(payloadAddr, &pl, sizeof(pl));

	client.Call(addr, payloadAddr);

	return 0;
}
