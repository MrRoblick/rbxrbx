#include <rbxclient.h>
#include <External/client.h>

#include <iostream>
#include <fstream>

#include <Roblox/instance.h>
#include <Roblox/types.h>
#include <Roblox/info.h>
#include <External/info.h>

#include <string>
#include <vector>

#include <thread>

/*
struct BufferPayload {
	char hash[32 + 1];
	char pad[];
};

*/

inline void writePayload(Memory* externalClientMem, uintptr_t address) {

	char* memoryManagement = new char[rbxrbxSignatureSize];
	std::memset(memoryManagement, 0, rbxrbxSignatureSize);
	std::memcpy(memoryManagement, payloadBytecodeHash.data(), BYTECODE_HASH_SIZE);
	std::memcpy(memoryManagement + BYTECODE_HASH_SIZE + 1, payloadBytecodeCompressed.data(), payloadBytecodeSize);

	externalClientMem->Write(address, memoryManagement, rbxrbxSignatureSize);

	delete[] memoryManagement;
}

int runExternal() {
	ExternalClient cl{};
	const auto dataModel = cl.GetDataModel();
	if (!dataModel) {
		std::cerr << "[Error] DataModel not found!" << std::endl;
		return 1;
	}
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

	playerListManager.value().SetBytecodeCompressed(safeAddr + BYTECODE_HASH_SIZE + 1, payloadBytecodeSize);
	playerListManager.value().SetBytecodeHash(safeAddr);


	/*
	* 
	* 
	
	*/

	/*
	
	const auto script = dataModel.value().FindFirstChildOfClass<Instance>("ReplicatedStorage").value().FindFirstChild<ModuleScript>("homo").value(); // playerListManager.value(); //

	std::cout << "[Info] Script address: " << script.GetAddress() << std::endl;

	std::ofstream hash("hash.txt");
	hash << script.GetBytecodeHash();
	hash.flush();
	hash.close();


	std::ofstream bcCompressed("bytecode_compressed.txt");
	bcCompressed << script.GetBytecodeCompressed();
	bcCompressed.flush();
	bcCompressed.close();
	*/

	return 0;
}