
cmake_minimum_required (VERSION 3.8)

if (POLICY CMP0141)
  cmake_policy(SET CMP0141 NEW)
  set(CMAKE_MSVC_DEBUG_INFORMATION_FORMAT "$<IF:$<AND:$<C_COMPILER_ID:MSVC>,$<CXX_COMPILER_ID:MSVC>>,$<$<CONFIG:Debug,RelWithDebInfo>:EditAndContinue>,$<$<CONFIG:Debug,RelWithDebInfo>:ProgramDatabase>>")
endif()

project ("rbxrbx")

include_directories(
	"${CMAKE_SOURCE_DIR}/include/"
)

add_executable (rbxrbx "rbxrbx.cpp" "src/procmemory.cpp" "src/ntdll.cpp" "include/rbxclient.h"  "include/Roblox/offsets.h" "include/Roblox/instance.h" "src/Roblox/instance.cpp" "include/Roblox/types.h" "include/External/client.h" "src/External/client.cpp" "include/processScanner.h" "src/processScanner.cpp" "include/Roblox/info.h" "src/internal.cpp" "src/external.cpp" "include/External/info.h")

if (CMAKE_VERSION VERSION_GREATER 3.12)
  set_property(TARGET rbxrbx PROPERTY CXX_STANDARD 20)
  target_link_options(rbxrbx PRIVATE /INCREMENTAL:NO /GS- /Oy- /GL-)
endif()

