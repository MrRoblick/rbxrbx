#include <rbxclient.h>
#include <External/client.h>

#include <iostream>
#include <fstream>

#include <Roblox/instance.h>
#include <Roblox/types.h>
#include <Roblox/info.h>
#include <External/info.h>
#include <Roblox/tools.h>
#include <tuple>

#include <string>
#include <vector>

#include <thread>
#include <lua.h>
#include <luacode.h>

struct BytecodeContainer {
	uint32_t unk00[3]; // 0x00
	char* bytecode; // 0x10
	char* unk01; // 0x18
	uint32_t bytecode_size; // 0x20
	uint32_t flag00; // 0x24
	uint32_t unk01_size; // 0x28
	uint32_t flag01; // 0x2C
	uint32_t flag02; // 0x30
	uint32_t flag03; // 0x34
};


inline std::tuple<uintptr_t, uintptr_t, uintptr_t, uintptr_t> writePayload(Memory* externalClientMem, uintptr_t address) {
	size_t offset = 0;

	uintptr_t hashPtr;

	char* memoryManagement = new char[rbxrbxSignatureSize];

	std::memset(memoryManagement + offset, 0, rbxrbxSignatureSize);

	std::memcpy(memoryManagement, payloadBytecodeHash.data(), BYTECODE_HASH_SIZE);
	hashPtr = address + offset;
	offset += BYTECODE_HASH_SIZE + 1;

	/* BYTECODE 0 */
	BytecodeContainer container{};
	container.unk00[0] = 0;
	container.unk00[1] = 0;
	container.unk00[2] = 0;

	std::memcpy(memoryManagement + offset, payloadBytecodeCompressed, payloadBytecodeSize); // bytecode
	container.bytecode = reinterpret_cast<char*>(address + offset);
	offset += payloadBytecodeSize + 1;

	container.unk01 = 0;
	container.bytecode_size = payloadBytecodeSize;
	container.unk01_size = payloadBytecodeSize;
	container.flag00 = 0;
	container.flag01 = 0;
	container.flag02 = 0;
	container.flag03 = 0;

	std::memcpy(memoryManagement + offset, &container, sizeof(container)); // CONTENT
	uintptr_t payloadBytecodePtr = address + offset;
	offset += sizeof(container) + 1;

	/* BYTECODE 1 */
	BytecodeContainer container1{};
	container1.unk00[0] = 0;
	container1.unk00[1] = 0;
	container1.unk00[2] = 0;

	std::memcpy(memoryManagement + offset, clientRunBytecode, clientRunBytecodeSize); // bytecode
	container1.bytecode = reinterpret_cast<char*>(address + offset);
	offset += clientRunBytecodeSize + 1;

	container1.unk01 = 0;
	container1.bytecode_size = clientRunBytecodeSize;
	container1.unk01_size = clientRunBytecodeSize;
	container1.flag00 = 0;
	container1.flag01 = 0;
	container1.flag02 = 0;
	container1.flag03 = 0;

	std::memcpy(memoryManagement + offset, &container1, sizeof(container1)); // CONTENT
	uintptr_t clientRunBytecodePtr = address + offset;
	offset += sizeof(container1) + 1;

	/* BYTECODE 2 */
	BytecodeContainer container2{};
	container2.unk00[0] = 0;
	container2.unk00[1] = 0;
	container2.unk00[2] = 0;

	std::memcpy(memoryManagement + offset, virtualMachineBytecode, virtualMachineBytecodeSize); // bytecode
	container2.bytecode = reinterpret_cast<char*>(address + offset);
	offset += virtualMachineBytecodeSize + 1;

	container2.unk01 = 0;
	container2.bytecode_size = virtualMachineBytecodeSize;
	container2.unk01_size = virtualMachineBytecodeSize;
	container2.flag00 = 0;
	container2.flag01 = 0;
	container2.flag02 = 0;
	container2.flag03 = 0;

	std::memcpy(memoryManagement + offset, &container2, sizeof(container2)); // CONTENT
	uintptr_t virtualMachineBytecodePtr = address + offset;
	offset += sizeof(container2) + 1;

	externalClientMem->Write(address, memoryManagement, rbxrbxSignatureSize);
	delete[] memoryManagement;

	return { hashPtr, payloadBytecodePtr, clientRunBytecodePtr, virtualMachineBytecodePtr };
}

const char* source = R"(
print("#########")
print('test nigga')
printidentity()
print("#########")
)";

//#define DOWNLOAD_CODE

int runExternal() {
	
	ExternalClient cl{};
	const auto dataModel = cl.GetDataModel();
	if (!dataModel) {
		std::cerr << "[Error] DataModel not found!" << std::endl;
		return 1;
	}

#ifdef DOWNLOAD_CODE
	const auto replicatedStorage = dataModel.value().FindFirstChildOfClass<Instance>("ReplicatedStorage");
	if (!replicatedStorage) {
		std::cerr << "[Error] ReplicatedStorage not found!" << std::endl;
		return 1;
	}
	const auto runtime = replicatedStorage.value().FindFirstChild<LocalScript>("Runtime");
	if (!runtime) {
		std::cerr << "[Error] Runtime not found!" << std::endl;
		return 1;
	}
	std::cout << "Runtime address: " << std::hex << runtime.value().GetAddress() << std::endl;

	const auto clientRun = runtime.value().FindFirstChild<ModuleScript>("ClientRun@rbxrbx");
	if (!clientRun) {
		std::cerr << "[Error] ClientRun@rbxrbx not found!" << std::endl;
		return 1;
	}
	std::cout << "ClientRun@rbxrbx address: " << std::hex << clientRun.value().GetAddress() << std::endl;

	const auto virtualMachine = runtime.value().FindFirstChild<ModuleScript>("VirtualMachine@rbxrbx");
	if (!virtualMachine) {
		std::cerr << "[Error] VirtualMachine@rbxrbx not found!" << std::endl;
		return 1;
	}
	std::cout << "VirtualMachine@rbxrbx address: " << std::hex << virtualMachine.value().GetAddress() << std::endl;

	const auto t = runtime.value().GetBytecode();
	std::ofstream file{ "Runtime_Bytecode.luauc", std::ios::binary };
	file.write(t.data(), t.size());
	file.close();

	const auto t2 = clientRun.value().GetBytecode();
	std::ofstream file2{ "ClientRun_Bytecode.luauc", std::ios::binary };
	file2.write(t2.data(), t2.size());
	file2.close();

	const auto t3 = virtualMachine.value().GetBytecode();
	std::ofstream file3{ "VirtualMachine_Bytecode.luauc", std::ios::binary };
	file3.write(t3.data(), t3.size());
	file3.close();

	std::cout << "[Info] Runtime bytecode downloaded, watch \"Runtime_Bytecode.luauc\"!" << std::endl;
#else
	const auto playerListManager = cl.GetPlayerListManager();
	if (!playerListManager) {
		std::cerr << "[Error] PlayerListManager not found!" << std::endl;
		return 1;
	}
	const auto cls = playerListManager.value().Get_ClassName();
	std::cout << cls << std::endl;

	if (cls != "ModuleScript") {
		std::cerr << "[Error] PlayerListManager is not a ModuleScript!" << std::endl;
		return 1;
	}
	else {
		std::cout << "[Info] PlayerListManager is a ModuleScript." << std::endl;
		std::cout << "[Info] PlayerListManager Address: " << std::hex << playerListManager.value().GetAddress() << std::endl;
		std::cout << "[Info] PlayerListManager Name: " << playerListManager.value().GetName() << std::endl;
		std::cout << "[Info] PlayerListManager ClassName: " << playerListManager.value().Get_ClassName() << std::endl;
	}

	const auto script = playerListManager.value();
	std::cout << script.GetAddress() << std::endl;

	std::vector<uintptr_t> safeAllocations = cl.FindAddresses(rbxrbxSignature);
	if (safeAllocations.size() <= 0) {
		std::cerr << "[Error] Empty addresses\n";
		return 1;
	}
	uintptr_t safeAddr = safeAllocations[0];

	std::cout << "[Info] Safe address found: " << safeAddr << std::endl;

	Memory* externalClientMem = cl.GetMemory();
	const auto [hashPtr, runtimeBytecodePtr, clientRunBytecodePtr, virtualMachineBytecodePtr] = writePayload(externalClientMem, safeAddr);

	system("PAUSE");
	std::cout << "[Info] Writing PlayerListManager bytecode to safe address\n";

	script.SetBytecodePointer(runtimeBytecodePtr);
	script.SetBytecodeHash(hashPtr);
	script.RemoveCoreDetections();

	std::cout << "[Info] Please join to place\n";
	system("PAUSE");
	
	std::cout << "[Info] ScriptContext RequireBypass enabled\n";
	const auto scriptCtx = dataModel.value().FindFirstChildOfClass<ScriptContext>("ScriptContext");
	if (!scriptCtx) {
		std::cerr << "[Error] ScriptContext not found!" << std::endl;
		return 1;
	}
	std::cout << "Script Context Address: 0x" << std::hex << scriptCtx.value().GetAddress() << std::endl;
	scriptCtx.value().RequireBypass();
	system("PAUSE");


	std::cout << "[Info] Finding the buffer\n";

	uintptr_t bufferAddress = cl.FindBuffer();
	if (bufferAddress == 0) {
		std::cerr << "[Info] Buffer not found\n";
		return 1;
	}
	std::cout << "[Info] Buffer found: 0x" << std::hex << bufferAddress << std::endl;
	// TODO

	const auto clientRun = script.FindFirstChild<ModuleScript>("ClientRun@rbxrbx");
	if (!clientRun) {
		std::cerr << "[Error] ClientRun@rbxrbx not found!" << std::endl;
		return 1;
	}
	std::cout << "ClientRun@rbxrbx address: " << std::hex << clientRun.value().GetAddress() << std::endl;

	const auto virtualMachine = script.FindFirstChild<ModuleScript>("VirtualMachine@rbxrbx");
	if (!virtualMachine) {
		std::cerr << "[Error] VirtualMachine@rbxrbx not found!" << std::endl;
		return 1;
	}
	std::cout << "VirtualMachine@rbxrbx address: " << std::hex << virtualMachine.value().GetAddress() << std::endl;

	const auto scriptsFolder = script.FindFirstChild<Instance>("ScriptsFolder");
	if (!scriptsFolder) {
		std::cerr << "[Error] ScriptsFolder not found!" << std::endl;
		return 1;
	}
	std::cout << "ScriptsFolder address: " << std::hex << scriptsFolder.value().GetAddress() << std::endl;


	clientRun.value().SetBytecodePointer(clientRunBytecodePtr);
	clientRun.value().RemoveCoreDetections();
	virtualMachine.value().SetBytecodePointer(virtualMachineBytecodePtr);
	virtualMachine.value().RemoveCoreDetections();

	byte* bridgeBuf = new byte[bufferSize];
	size_t bridgeBufOffset = 0;
	std::memset(bridgeBuf, 0, bufferSize);

	externalClientMem->Write(bufferAddress, bridgeBuf, bufferSize);
	std::cout << "[Info] Buffer cleared\n";
	system("PAUSE");

	size_t bytecodeSize = 0;
	char* bytecode = luau_compile(source, strlen(source), nullptr, &bytecodeSize);

	std::cout << "Compiled bytecode: ";
	for (size_t i = 0; i < bytecodeSize; i++) {
		std::cout << std::hex << static_cast<uint32_t>(static_cast<unsigned char>(bytecode[i])) << " ";
	}
	std::cout << std::endl;

	bridgeBuf[bridgeBufOffset++] = 1; // Exec Event

	std::memcpy(bridgeBuf + bridgeBufOffset, &bytecodeSize, 4); // length write
	bridgeBufOffset += 4;

	std::memcpy(bridgeBuf + bridgeBufOffset, bytecode, bytecodeSize); // bytecode write
	bridgeBufOffset += bytecodeSize;

	std::free(bytecode);

	externalClientMem->Write(bufferAddress, bridgeBuf, bufferSize);

	std::cout << "[Info] Buffer -> script executed\n";

	
	while (true) {
		const auto mod = scriptsFolder->FindFirstChildOfClass<ModuleScript>("ModuleScript");
		if (mod.has_value()) {
			mod.value().RemoveCoreDetections();
			std::memset(bridgeBuf, 0, bufferSize);
			externalClientMem->Write(bufferAddress, bridgeBuf, bufferSize);
		}
	}
	

	system("PAUSE");

#endif

	return 0;
}