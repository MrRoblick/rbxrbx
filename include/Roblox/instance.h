#pragma once

#include <procmemory.h>
#include <string>
#include <Roblox/types.h>
#include <Roblox/offsets.h>
#include <vector>
#include <ctype.h>
#include <optional>
#include <iostream>


class Instance {
protected:
	Memory* memory = nullptr;
	uintptr_t address = 0;
	void GetDescendantsRecursive(std::vector<Instance>& descendants) const;
public:
	explicit Instance(Memory* mem, const uintptr_t address);
	virtual ~Instance();

	Memory* GetMemory() const;
	uintptr_t GetAddress() const;

	std::string GetName() const;
	std::string Get_ClassName() const;
	std::optional<Instance> GetParent() const;
	void SetParentPointer(uintptr_t safePageAddress) const;
	void SetReferencePointer(uintptr_t safePageAddress) const;
	void SetClassDescriptorPointer(uintptr_t safePageAddress) const;

	uintptr_t GetParentPointer() const;
	uintptr_t GetReferencePointer() const;
	uintptr_t GetClassDescriptorPointer() const;

	std::vector<Instance> GetChildren() const;
	std::vector<Instance> GetDescendants() const;

	template<typename T>
	std::optional<T> FindFirstChild(const std::string& name) const {
		uintptr_t childrenPtr;
		memory->Read(address + RobloxOffsets::Instance::Children, &childrenPtr, sizeof(childrenPtr));

		uintptr_t childrenStart;
		memory->Read(childrenPtr, &childrenStart, sizeof(childrenStart));

		uintptr_t childrenEnd;
		memory->Read(childrenPtr + RobloxOffsets::Instance::ChildrenEnd, &childrenEnd, sizeof(childrenEnd));

		std::cout << "//////////\n";
		for (uintptr_t addr = childrenStart; addr < childrenEnd; addr += 0x10) {

			uintptr_t instanceAddr;
			memory->Read(addr, &instanceAddr, sizeof(instanceAddr));
			if (!instanceAddr) continue;

			const Instance inst = Instance{ memory, instanceAddr };
			std::cout << "[" << std::hex << address << "]" << name << " : " << inst.GetName() << std::endl;
			if (inst.GetName() == name) {
				return T{ memory, instanceAddr };
			}
		}
		return std::nullopt;
	};

	template<typename T>
	std::optional<T> FindFirstChildOfClass(const std::string& className) const {
		uintptr_t childrenPtr;
		memory->Read(address + RobloxOffsets::Instance::Children, &childrenPtr, sizeof(childrenPtr));

		uintptr_t childrenStart;
		memory->Read(childrenPtr, &childrenStart, sizeof(childrenStart));

		uintptr_t childrenEnd;
		memory->Read(childrenPtr + RobloxOffsets::Instance::ChildrenEnd, &childrenEnd, sizeof(childrenEnd));

		for (uintptr_t addr = childrenStart; addr < childrenEnd; addr += 0x10) {
			uintptr_t instanceAddr;
			memory->Read(addr, &instanceAddr, sizeof(instanceAddr));
			if (!instanceAddr) continue;
			const Instance inst = Instance{ memory, instanceAddr };
			if (inst.Get_ClassName() == className) {
				return T{ memory, instanceAddr };
			}
		}
		return std::nullopt;
	};
	uintptr_t GetSelf() const;
	void SetSelf(uintptr_t address) const;
};

class ScriptContext: public Instance{
public:
	explicit ScriptContext(Memory* mem, const uintptr_t address);
	void RequireBypass() const;
};

class ModuleScript : public Instance {
public:
	explicit ModuleScript(Memory* mem, const uintptr_t address);
	std::string GetBytecode() const;
	std::string GetBytecodeHash() const;

	void SetBytecodePointer(uintptr_t safePageAddress) const;
	void SetBytecodeHash(uintptr_t safePageAddress) const;
	void RemoveCoreDetections() const;

	//void RemoveCoreDetections() const;
};

class LocalScript : public Instance {
public:
	explicit LocalScript(Memory* mem, const uintptr_t address);
	std::string GetBytecode() const;
	std::string GetBytecodeHash() const;

	bool GetEnabled() const;
	void SetEnabled(bool enabled) const;

	void SetBytecodePointer(uintptr_t safePageAddress) const;
	void SetBytecodeHash(uintptr_t safePageAddress) const;
};


class BasePart : public Instance {
public:
	explicit BasePart(Memory* mem, const uintptr_t address);
	Vector3 GetPosition() const;
	Vector3 GetVelocity() const;
};

class Camera : public Instance {
public:
	explicit Camera(Memory* mem, const uintptr_t address);
	float GetFieldOfView() const;
};

class Workspace : public Instance {
public:
	explicit Workspace(Memory* mem, const uintptr_t address);
	std::optional<Camera> GetCurrentCamera() const;
};

class Humanoid : public Instance {
public:
	explicit Humanoid(Memory* mem, const uintptr_t address);
	float GetWalkSpeed() const;
	void SetWalkSpeed(float speed) const;
};

class Model : public Instance {
public:
	explicit Model(Memory* mem, const uintptr_t address);
};

class Player: public Instance {
public:
	explicit Player(Memory* mem, const uintptr_t address);
	uint64_t GetUserId() const;
	std::optional<Model> GetCharacter() const;
};

class Players : public Instance {
public:
	explicit Players(Memory* mem, const uintptr_t address);
	std::optional<Player> GetLocalPlayer() const;
};