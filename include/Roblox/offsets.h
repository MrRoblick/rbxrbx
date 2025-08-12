#pragma once
#include <cstdint>

namespace RobloxOffsets {
	namespace RobloxString {
		inline constexpr uintptr_t Length = 0x10;
	}
	namespace Script {
		inline constexpr uintptr_t RunContext = 0x150;
	}
	namespace Bytecode {
		inline constexpr uintptr_t BytecodePointer = 0x10;
		inline constexpr uintptr_t BytecodeSize = 0x20;
	}
	namespace LocalScript {
		inline constexpr uintptr_t LocalScriptByteCode = 0x1B0;
		inline constexpr uintptr_t LocalScriptHash = 0x1C0;
		inline constexpr uintptr_t Enabled = 0x154;
	}
	namespace ModuleScript {
		inline constexpr uintptr_t ModuleScriptByteCode = 0x158;
		inline constexpr uintptr_t ModuleScriptHash = 0x180;
	}
	namespace Core {
		inline constexpr uintptr_t TaskSchedulerPointer = 0x6F55720;
		inline constexpr uintptr_t ViewMatrix = 0x4B0;
		inline constexpr uintptr_t ScriptContext = 0x3D0;

		inline constexpr uintptr_t FakeDataModelPointer = 0x6E854F8;
		inline constexpr uintptr_t FakeDataModelToDataModel = 0x1C0;
	}
	namespace Workspace {
		inline constexpr uintptr_t Gravity = 0x990;
		inline constexpr uintptr_t Camera = 0x450;
	}
	namespace Lighting {
		inline constexpr uintptr_t ClockTime = 0x1C0;
	}
	namespace DataModel {
		inline constexpr uintptr_t Workspace = 0x180;
		inline constexpr uintptr_t PlaceId = 0x1A0;
		inline constexpr uintptr_t CreatorId = 0x190;
		inline constexpr uintptr_t GameLoaded = 0x680;
	}
	namespace Camera {
		inline constexpr uintptr_t ViewportSize = 0x2F0;
		inline constexpr uintptr_t Position = 0x14C;
		inline constexpr uintptr_t Rotation = 0x130;
		inline constexpr uintptr_t FOV = 0x168;

	}
	namespace ScriptContext {
		inline constexpr uintptr_t RequireBypass = 0x7E8;
	}
	namespace Players {
		inline constexpr uintptr_t LocalPlayer = 0x128;
	}
	namespace Player {
		inline constexpr uintptr_t UserId = 0x270;
		inline constexpr uintptr_t Character = 0x328;
	}
	namespace Humanoid {
		inline constexpr uintptr_t WalkSpeed = 0x1DC;
		inline constexpr uintptr_t WalkSpeedCheck = 0x3B8;

		inline constexpr uintptr_t JumpPower = 0x1B8;
		inline constexpr uintptr_t Health = 0x19C;
		inline constexpr uintptr_t HipHeight = 0x1A8;
		inline constexpr uintptr_t MoveDirection = 0x160;
		inline constexpr uintptr_t Sit = 0x1E3;
	}
	namespace BasePart {
		inline constexpr uintptr_t Position = 0x14C;
		inline constexpr uintptr_t CanCollide = 0x301;
		inline constexpr uintptr_t CanTouch = 0x301;
		inline constexpr uintptr_t Velocity = 0x158;
		inline constexpr uintptr_t Transparency = 0xF8;
		
	}
	namespace Instance {
		inline constexpr uintptr_t Self = 0x8;
		inline constexpr uintptr_t Reference = 0x10;

		inline constexpr uintptr_t Parent = 0x50;
		inline constexpr uintptr_t Name = 0x88;

		inline constexpr uintptr_t Children = 0x68;
		inline constexpr uintptr_t ChildrenEnd = 0x8;
		inline constexpr uintptr_t TagList = 0x120;

		inline constexpr uintptr_t ClassDescriptor = 0x18;
		inline constexpr uintptr_t ClassDescriptorToClassName = 0x8;
	}
}