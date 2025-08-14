#pragma once
#include <string>

std::string Compress(const std::string& bytecode);
std::string Decompress(const std::string& compressed);