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

inline std::tuple<uintptr_t, uintptr_t> writePayload(Memory* externalClientMem, uintptr_t address) {
	size_t offset = 0;
	size_t sz = payloadBytecodeSize;

	uintptr_t hashPtr, bytecodePtr;

	char* memoryManagement = new char[rbxrbxSignatureSize];

	std::memset(memoryManagement + offset, 0, rbxrbxSignatureSize);

	std::memcpy(memoryManagement, payloadBytecodeHash.data(), BYTECODE_HASH_SIZE);
	hashPtr = address + offset;
	offset += BYTECODE_HASH_SIZE + 1;

	BytecodeContainer container{};
	container.unk00[0] = 0;
	container.unk00[1] = 0;
	container.unk00[2] = 0;

	std::memcpy(memoryManagement + offset, payloadBytecodeCompressed, sz); // bytecode
	container.bytecode = reinterpret_cast<char*>(address + offset);
	offset += sz + 1;

	container.unk01 = 0;
	container.bytecode_size = sz;
	container.unk01_size = 207;
	container.flag00 = 0;
	container.flag01 = 0;
	container.flag02 = 0;
	container.flag03 = 0;

	std::memcpy(memoryManagement + offset, &container, sizeof(container)); // CONTENT
	bytecodePtr = address + offset;
	offset += sizeof(container) + 1;

	externalClientMem->Write(address, memoryManagement, rbxrbxSignatureSize);
	delete[] memoryManagement;

	return { hashPtr, bytecodePtr };
}

int runExternal() {
	ExternalClient cl{};
	const auto dataModel = cl.GetDataModel();
	if (!dataModel) {
		std::cerr << "[Error] DataModel not found!" << std::endl;
		return 1;
	}
	
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

	const auto script = playerListManager.value(); //  //  dataModel.value().FindFirstChildOfClass<Instance>("ReplicatedStorage").value().FindFirstChild<ModuleScript>("homo").value();  // 
	std::cout << script.GetAddress() << std::endl;

	std::vector<uintptr_t> safeAllocations = cl.FindAddresses(rbxrbxSignature);
	if (safeAllocations.size() <= 0) {
		std::cout << "[Error] Empty addresses\n";
		return 1;
	}
	uintptr_t safeAddr = safeAllocations[0];

	std::cout << "[Info] Safe address found: " << safeAddr << std::endl;

	Memory* externalClientMem = cl.GetMemory();
	const auto [hashPtr, bytecodePtr] = writePayload(externalClientMem, safeAddr);

	system("PAUSE");
	std::cout << "[Info] ScriptContext RequireBypass enabled\n";
	const ScriptContext scriptCtx = dataModel.value().FindFirstChildOfClass<ScriptContext>("ScriptContext").value();
	scriptCtx.RequireBypass();

	system("PAUSE");
	std::cout << "[Info] Writing PlayerListManager bytecode to safe address\n";

	script.SetBytecodePointer(bytecodePtr);
	script.SetBytecodeHash(hashPtr);

	/*
	* 
	* 
	const auto corePackages = dataModel.value().FindFirstChildOfClass<Instance>("CorePackages");
	if (!corePackages) {
		std::cerr << "[Error] CorePackages not found!" << std::endl;
		return 1;
	}
	const auto packages = corePackages.value().FindFirstChild<Instance>("Packages");
	if (!packages) {
		std::cerr << "[Error] Packages not found!" << std::endl;
		return 1;
	}
	const auto _index = packages.value().FindFirstChild<Instance>("_Index");
	if (!_index) {
		std::cerr << "[Error] _Index not found!" << std::endl;
		return 1;
	}
	const auto collisionMatchers2D = _index.value().FindFirstChild<Instance>("CollisionMatchers2D");
	if (!collisionMatchers2D) {
		std::cerr << "[Error] CollisionMatchers2D folder not found!" << std::endl;
		return 1;
	}
	const auto collisionMatchers2D_2 = collisionMatchers2D.value().FindFirstChild<Instance>("CollisionMatchers2D");
	if (!collisionMatchers2D_2) {
		std::cerr << "[Error] CollisionMatchers2D_2 not found!" << std::endl;
		return 1;
	}
	const auto jest = collisionMatchers2D_2.value().FindFirstChild<ModuleScript>("Jest");
	if (!jest) {
		std::cerr << "[Error] Jest not found!" << std::endl;
		return 1;
	}


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

	const auto script = playerListManager.value(); // dataModel.value().FindFirstChildOfClass<Instance>("ReplicatedStorage").value().FindFirstChild<ModuleScript>("homo").value(); // 

	std::cout << "[Info] Script address: " << script.GetAddress() << std::endl;

	std::ofstream hash("hash.txt");
	hash << script.GetBytecodeHash();
	hash.flush();
	hash.close();

	std::ofstream bcCompressed("bytecode_decompressed.txt");
	bcCompressed << Decompress(script.GetBytecode());
	bcCompressed.flush();
	bcCompressed.close();


	std::cout << "[Info] Finding the safe address\n";

	std::vector<uintptr_t> safeAllocations = cl.FindAddresses(rbxrbxSignature);
	if (safeAllocations.size() <= 0) {
		std::cout << "[Error] Empty addresses\n";
		return 1;
	}
	uintptr_t safeAddr = safeAllocations[0];

	std::cout << "[Info] Safe address found: " << safeAddr << std::endl;

	Memory* externalClientMem = cl.GetMemory();
	writePayload(externalClientMem, safeAddr);

	system("PAUSE");
	std::cout << "[Info] ScriptContext RequireBypass enabled\n";
	const ScriptContext scriptCtx = dataModel.value().FindFirstChildOfClass<ScriptContext>("ScriptContext").value();
	scriptCtx.RequireBypass();

	system("PAUSE");
	std::cout << "[Info] Writing PlayerListManager bytecode to safe address\n";

	playerListManager.value().SetBytecodePointer(safeAddr + BYTECODE_HASH_SIZE + 1, payloadBytecodeSize);
	playerListManager.value().SetBytecodeHash(safeAddr);
	*/

	/*
	
	
	*/

	

	return 0;
}