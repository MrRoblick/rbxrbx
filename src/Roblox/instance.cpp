#include <Roblox/instance.h>
#include <string>
#include <procmemory.h>
#include <Roblox/offsets.h>
#include <Roblox/info.h>
#include <iostream>
#include <vector>

inline std::string ReadRobloxString(Memory* memory, const uintptr_t address) {
	uint64_t length;
	memory->Read(address + RobloxOffsets::RobloxString::Length, &length, sizeof(length));
	if (length > 15000 || length <= 0) {
		return "";
	}

	uintptr_t ptr = address;
	if (length > 15) {
		memory->Read(address, &ptr, sizeof(ptr));
	}

	std::string buffer(length, '\0');
	memory->Read(ptr, buffer.data(), length);

	return buffer;
}

Instance::Instance(Memory* mem, const uintptr_t address)
	: memory(mem), address(address) {}

Instance::~Instance() {}

Memory* Instance::GetMemory() const
{
	return memory;
}

uintptr_t Instance::GetAddress() const
{
	return address;
}

std::string Instance::Get_ClassName() const
{
	uintptr_t classDescriptor;
	memory->Read(address + RobloxOffsets::Instance::ClassDescriptor, &classDescriptor, sizeof(classDescriptor));

	uintptr_t ptrClassName;
	memory->Read(classDescriptor + RobloxOffsets::Instance::ClassDescriptorToClassName, &ptrClassName, sizeof(ptrClassName));

	return ReadRobloxString(memory, ptrClassName);
}

std::string Instance::GetName() const
{
	uintptr_t ptrName;
	memory->Read(address + RobloxOffsets::Instance::Name, &ptrName, sizeof(ptrName));

	return ReadRobloxString(memory, ptrName);
}

std::optional<Instance> Instance::GetParent() const
{
	uintptr_t parentAddress;
	memory->Read(address + RobloxOffsets::Instance::Parent, &parentAddress, sizeof(parentAddress));

	if (!parentAddress) {
		return std::nullopt;
	}

	return Instance{memory, parentAddress};
}

std::vector<Instance> Instance::GetChildren() const
{
	uintptr_t childrenPtr;
	memory->Read(address + RobloxOffsets::Instance::Children, &childrenPtr, sizeof(childrenPtr));

	uintptr_t childrenStart;
	memory->Read(childrenPtr, &childrenStart, sizeof(childrenStart));

	uintptr_t childrenEnd;
	memory->Read(childrenPtr + RobloxOffsets::Instance::ChildrenEnd, &childrenEnd, sizeof(childrenEnd));

	uintptr_t count = (childrenEnd - childrenStart) / 0x10;
	std::vector<Instance> children{};
	children.reserve(count);

	for (uintptr_t addr = childrenStart; addr < childrenEnd; addr += 0x10) {
		uintptr_t instanceAddr;
		memory->Read(addr, &instanceAddr, sizeof(instanceAddr));
		if (!instanceAddr) continue;
		children.push_back(Instance{memory, instanceAddr });
	}

	return children;
}

std::optional<Player> Players::GetLocalPlayer() const
{
	uintptr_t playerAddress;
	memory->Read(address + RobloxOffsets::Players::LocalPlayer, &playerAddress, sizeof(playerAddress));
	if (!playerAddress) return std::nullopt;

	return Player{memory, playerAddress};
}

uint64_t Player::GetUserId() const
{
	uint64_t userId;
	memory->Read(address + RobloxOffsets::Player::UserId, &userId, sizeof(userId));
	return userId;
}

std::optional<Camera> Workspace::GetCurrentCamera() const
{
	return std::optional<Camera>();
}

float Camera::GetFieldOfView() const
{
	float fov;
	memory->Read(address + RobloxOffsets::Camera::FOV, &fov, sizeof(fov));
	return fov;
}

Vector3 BasePart::GetVelocity() const
{
	Vector3 velocity = Vector3::zero();
	memory->Read(address + RobloxOffsets::BasePart::Velocity, &velocity, sizeof(velocity));
	return velocity;
}

Vector3 BasePart::GetPosition() const
{
	Vector3 velocity = Vector3::zero();
	memory->Read(address + RobloxOffsets::BasePart::Position, &velocity, sizeof(velocity));
	return velocity;
}

std::optional<Model> Player::GetCharacter() const
{
	uintptr_t characterAddress;
	memory->Read(address + RobloxOffsets::Player::Character, &characterAddress, sizeof(characterAddress));
	if (!characterAddress) return std::nullopt;

	return Model{ memory, characterAddress };
}


float Humanoid::GetWalkSpeed() const {
	float walkspeed;
	memory->Read(address + RobloxOffsets::Humanoid::WalkSpeed, &walkspeed, sizeof(walkspeed));

	return walkspeed;
}

void Humanoid::SetWalkSpeed(float speed) const {
	memory->Write(address + RobloxOffsets::Humanoid::WalkSpeed, &speed, sizeof(speed));
	memory->Write(address + RobloxOffsets::Humanoid::WalkSpeedCheck, &speed, sizeof(speed));
}

std::string LocalScript::GetBytecode() const {
	uintptr_t bytecodeContainerPtr;
	memory->Read(address + RobloxOffsets::LocalScript::LocalScriptByteCode, &bytecodeContainerPtr, sizeof(bytecodeContainerPtr));

	uint32_t bytecodeSize;
	memory->Read(bytecodeContainerPtr + RobloxOffsets::Bytecode::BytecodeSize, &bytecodeSize, sizeof(bytecodeSize));

	std::string bytecodeCompressed(bytecodeSize, '\0');

	uintptr_t bytecodePtr;
	memory->Read(bytecodeContainerPtr + RobloxOffsets::Bytecode::BytecodePointer, &bytecodePtr, sizeof(bytecodePtr));

	memory->Read(bytecodePtr, bytecodeCompressed.data(), bytecodeCompressed.size());

	return bytecodeCompressed;
}
std::string LocalScript::GetBytecodeHash() const {
	uintptr_t hashPtr;
	memory->Read(address + RobloxOffsets::LocalScript::LocalScriptHash, &hashPtr, sizeof(hashPtr));

	std::string hash(BYTECODE_HASH_SIZE, '\0');
	memory->Read(hashPtr, hash.data(), BYTECODE_HASH_SIZE);

	return hash;
}

void Instance::GetDescendantsRecursive(std::vector<Instance>& descendants) const {
	std::vector<Instance> children = this->GetChildren();

	for (const Instance& child : children) {
		descendants.push_back(child);
		child.GetDescendantsRecursive(descendants);
	}
}

std::vector<Instance> Instance::GetDescendants() const {
	std::vector<Instance> descendants;
	GetDescendantsRecursive(descendants);
	return descendants;
}

void LocalScript::SetBytecodePointer(uintptr_t safePageAddress) const {
	memory->Write(address + RobloxOffsets::LocalScript::LocalScriptByteCode, &safePageAddress, sizeof(safePageAddress));
}

void LocalScript::SetBytecodeHash(uintptr_t safePageAddress) const {
	memory->Write(address + RobloxOffsets::LocalScript::LocalScriptHash, &safePageAddress, sizeof(safePageAddress));
}

bool LocalScript::GetEnabled() const {
	bool enabled;
	memory->Read(address + RobloxOffsets::LocalScript::Enabled, &enabled, sizeof(enabled));
	return enabled;
}
void LocalScript::SetEnabled(bool enabled) const {
	bool state = enabled ? 2 : 0;
	// 0x168
	memory->Write(address + RobloxOffsets::LocalScript::Enabled, &enabled, sizeof(enabled));
	memory->Write(address + 0x168, &state, sizeof(state));
	//memory->Write(address + 0x15D, &state, sizeof(state));
	//memory->Write(address + 0x165, &state, sizeof(state));
	//memory->Write(address + 0x165, &state, sizeof(state));
	//memory->Write(address + 0x18d, &state, sizeof(state));
}

std::string ModuleScript::GetBytecode() const {
	uintptr_t bytecodeContainerPtr;
	memory->Read(address + RobloxOffsets::ModuleScript::ModuleScriptByteCode, &bytecodeContainerPtr, sizeof(bytecodeContainerPtr));

	uint32_t bytecodeSize;
	memory->Read(bytecodeContainerPtr + RobloxOffsets::Bytecode::BytecodeSize, &bytecodeSize, sizeof(bytecodeSize));

	std::string bytecodeCompressed(bytecodeSize, '\0');

	uintptr_t bytecodePtr;
	memory->Read(bytecodeContainerPtr + RobloxOffsets::Bytecode::BytecodePointer, &bytecodePtr, sizeof(bytecodePtr));

	memory->Read(bytecodePtr, bytecodeCompressed.data(), bytecodeCompressed.size());

	return bytecodeCompressed;
}
std::string ModuleScript::GetBytecodeHash() const {
	uintptr_t hashPtr;
	memory->Read(address + RobloxOffsets::ModuleScript::ModuleScriptHash, &hashPtr, sizeof(hashPtr));

	std::string hash(BYTECODE_HASH_SIZE, '\0');
	memory->Read(hashPtr, hash.data(), BYTECODE_HASH_SIZE);

	return hash;
}

void ModuleScript::SetBytecodePointer(uintptr_t safePageAddress) const {
	memory->Write(address + RobloxOffsets::ModuleScript::ModuleScriptByteCode, &safePageAddress, sizeof(safePageAddress));
}


void ModuleScript::SetBytecodeHash(uintptr_t safePageAddress) const {
	memory->Write(address + RobloxOffsets::ModuleScript::ModuleScriptHash, &safePageAddress, sizeof(safePageAddress));
}

uintptr_t Instance::GetSelf() const {
	uintptr_t self;
	memory->Read(address + RobloxOffsets::Instance::Self, &self, sizeof(self));
	return self;
}
void Instance::SetSelf(uintptr_t address) const {
	memory->Write(address + RobloxOffsets::Instance::Self, &address, sizeof(address));
}

void ScriptContext::RequireBypass() const {
	bool bypass = true;
	memory->Write(address + RobloxOffsets::ScriptContext::RequireBypass, &bypass, sizeof(bypass));
}

uintptr_t Instance::GetParentPointer() const {
	uintptr_t ptr;
	memory->Read(address + RobloxOffsets::Instance::Parent, &ptr, sizeof(ptr));
	return ptr;
}
uintptr_t Instance::GetReferencePointer() const {
	uintptr_t ptr;
	memory->Read(address + RobloxOffsets::Instance::Reference, &ptr, sizeof(ptr));
	return ptr;
}
uintptr_t Instance::GetClassDescriptorPointer() const {
	uintptr_t ptr;
	memory->Read(address + RobloxOffsets::Instance::ClassDescriptor, &ptr, sizeof(ptr));
	return ptr;
}


void Instance::SetParentPointer(uintptr_t safePageAddress) const {
	memory->Write(address + RobloxOffsets::Instance::Parent, &safePageAddress, sizeof(safePageAddress));
}
void Instance::SetReferencePointer(uintptr_t safePageAddress) const {
	memory->Write(address + RobloxOffsets::Instance::Reference, &safePageAddress, sizeof(safePageAddress));
}
void Instance::SetClassDescriptorPointer(uintptr_t safePageAddress) const {
	memory->Write(address + RobloxOffsets::Instance::ClassDescriptor, &safePageAddress, sizeof(safePageAddress));
}

/*
void ModuleScript::RemoveCoreDetections() const {

}
*/

ScriptContext::ScriptContext(Memory* mem, const uintptr_t address) : Instance(Instance{ mem, address }) {};
ModuleScript::ModuleScript(Memory* mem, const uintptr_t address) : Instance(Instance{ mem, address }) {};
LocalScript::LocalScript(Memory* mem, const uintptr_t address) : Instance(Instance{ mem, address }) {};
BasePart::BasePart(Memory* mem, const uintptr_t address) : Instance(Instance{mem, address}) {}
Camera::Camera(Memory* mem, const uintptr_t address) : Instance(Instance{ mem, address }) {}
Workspace::Workspace(Memory* mem, const uintptr_t address) : Instance(Instance{ mem, address }) {}
Player::Player(Memory* mem, const uintptr_t address) : Instance(Instance{ mem, address }) {}
Players::Players(Memory* mem, const uintptr_t address) : Instance(Instance{ mem, address }) {}
Model::Model(Memory* mem, const uintptr_t address) : Instance(Instance{ mem, address }) {}
Humanoid::Humanoid(Memory* mem, const uintptr_t address) : Instance(Instance{ mem, address }) {}
