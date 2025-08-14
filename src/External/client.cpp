#include <External/client.h>
#include <External/info.h>
#include <procmemory.h>
#include <processScanner.h>
#include <Roblox/info.h>
#include <Roblox/instance.h>
#include <Roblox/offsets.h>
#include <optional>
#include <string>
#include <Windows.h>
#include <TlHelp32.h>
#include <iostream>

ExternalClient::ExternalClient()
	: memory(new Memory{ROBLOX_CLIENT_NAME}) {}

ExternalClient::~ExternalClient() {
	delete memory;
}

Memory* ExternalClient::GetMemory() const {
	return memory;
}

std::optional<Instance> ExternalClient::GetDataModel() const {
	uintptr_t absoluteAddress = memory->GetExecutableAddress();

	uintptr_t fakeDataModel;
	memory->Read(absoluteAddress + RobloxOffsets::Core::FakeDataModelPointer, &fakeDataModel, sizeof(fakeDataModel));

	uintptr_t dataModelAddress;
	memory->Read(fakeDataModel + RobloxOffsets::Core::FakeDataModelToDataModel, &dataModelAddress, sizeof(dataModelAddress));

	if (!dataModelAddress) return std::nullopt;

	std::cout << "[INFO] DataModel Address: " << std::hex << fakeDataModel << std::endl;

	return Instance{ memory, dataModelAddress };
}

std::vector<uintptr_t> ExternalClient::FindAddresses(const std::string& pattern) const {
	return memory->FindAddresses(pattern);
}

uintptr_t ExternalClient::FindBuffer() const {
	const std::vector<uintptr_t> addresses = memory->FindAddresses(bufferSignature);
	if (addresses.size() <= 0 || addresses.size() > 1) {
		std::cerr << "[ERROR] Buffer not found or multiple addresses found!" << std::endl;
		return 0;
	}
	const uintptr_t addr = addresses[0];
	return addr;
}

std::optional<ModuleScript> ExternalClient::GetPlayerListManager() const {
	const std::vector<uintptr_t> addresses = memory->FindAddresses(playerListManagerBytecode);
	if (addresses.size() <= 0 || addresses.size() > 1) {
		std::cerr << "[ERROR] PlayerListManager not found or multiple instances found!" << std::endl;
		return std::nullopt;
	}
	const uintptr_t playerListManagerBytecodeSourceAddress = addresses[0];
	std::cout << "[INFO] PlayerListManager Address: " << std::hex << playerListManagerBytecodeSourceAddress << std::endl;

	const std::vector<uintptr_t> addressesPtr = memory->FindAddresses(playerListManagerBytecodeSourceAddress);
	if (addressesPtr.size() <= 0 || addressesPtr.size() > 1) {
		std::cerr << "[ERROR] PlayerListManager not found or multiple instances found!" << std::endl;
		return std::nullopt;
	}

	const uintptr_t playerListManagerBytecodeStructAddress = addressesPtr[0] - RobloxOffsets::Bytecode::BytecodePointer;
	std::cout << "[INFO] PlayerListManager Bytecode Struct Address: " << std::hex << playerListManagerBytecodeStructAddress << std::endl;
	const std::vector<uintptr_t> bytecodeAddress = memory->FindAddresses(playerListManagerBytecodeStructAddress);
	if (bytecodeAddress.size() <= 0) {
		std::cerr << "[ERROR] PlayerListManager bytecode address not found!" << std::endl;
		return std::nullopt;
	}
	uintptr_t playerListManager = 0;
	for (const uintptr_t addr : bytecodeAddress) {

		uintptr_t plm;
		memory->Read(addr - RobloxOffsets::ModuleScript::ModuleScriptByteCode, &plm, sizeof(plm));

		std::cout << std::hex << addr << " : " << plm << std::endl;

		if (plm < 0x000FFFFFFFFFFFFF) {
			playerListManager = addr - RobloxOffsets::ModuleScript::ModuleScriptByteCode;
			std::cout << "[INFO] PlayerListManager Bytecode Address: " << std::hex << playerListManager << std::endl;
			break;
		}
	}

	

	return ModuleScript{ memory, playerListManager };
}