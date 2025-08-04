#pragma once

#include <procmemory.h>
#include <Roblox/instance.h>
#include <optional>
#include <vector>
#include <string>

class ExternalClient {
private:
	Memory* memory;
public:
	ExternalClient();
	~ExternalClient();

	std::optional<Instance> GetDataModel() const;
	std::optional<ModuleScript> GetPlayerListManager() const;

	Memory* GetMemory() const;
	std::vector<uintptr_t> FindAddresses(const std::string& pattern) const;
};