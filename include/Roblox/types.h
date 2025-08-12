#pragma once

#include <math.h>

struct Vector2 {
	float x;
	float y;

	Vector2 operator+ (const Vector2& Other) const {
		return Vector2{ x + Other.x, y + Other.y};
	}
	Vector2 operator- (const Vector2& Other) const {
		return Vector2{ x - Other.x, y - Other.y };
	}
	Vector2 operator* (const Vector2& Other) const {
		return Vector2{ x * Other.x, y * Other.y};
	}
	Vector2 operator/ (const Vector2& Other) const {
		return Vector2{ x / Other.x, y / Other.y };
	}
	Vector2 operator* (const float Other) const {
		return Vector2{ x * Other, y * Other};
	}
	Vector2 operator/ (const float Other) const {
		return Vector2{ x / Other, y / Other};
	}

	static Vector2 zero() { return Vector2{ 0.0f, 0.0f }; }
	static Vector2 one() { return Vector2{ 1.0f, 1.0f }; }

	static Vector2 xAxis() { return Vector2{ 1.0f, 0.0f }; }
	static Vector2 yAxis() { return Vector2{ 0.0f, 1.0f }; }

	float length() { return sqrtf(x * x + y * y); }

	Vector2 normalize() {
		float length = sqrtf(x * x + y * y);
		if (length == 0.0f) {
			return Vector2::zero();
		}
		return Vector2{
			x / length,
			y / length,
		};
	};

	explicit Vector2(float x, float y) : x(x), y(y) {};
};

struct Vector3 {
	float x;
	float y;
	float z;

	Vector3 operator+ (const Vector3& Other) const {
		return Vector3{ x + Other.x, y + Other.y, z + Other.z};
	}
	Vector3 operator- (const Vector3& Other) const {
		return Vector3{ x - Other.x, y - Other.y, z - Other.z };
	}
	Vector3 operator* (const Vector3& Other) const {
		return Vector3{ x * Other.x, y * Other.y, z * Other.z };
	}
	Vector3 operator/ (const Vector3& Other) const {
		return Vector3{ x / Other.x, y / Other.y, z / Other.z };
	}
	Vector3 operator* (const float Other) const {
		return Vector3{ x * Other, y * Other, z * Other };
	}
	Vector3 operator/ (const float Other) const {
		return Vector3{ x / Other, y / Other, z / Other };
	}

	static Vector3 zero() { return Vector3{ 0.0f, 0.0f, 0.0f }; }
	static Vector3 one() { return Vector3{ 1.0f, 1.0f, 1.0f }; }

	static Vector3 xAxis() { return Vector3{ 1.0f, 0.0f, 0.0f }; }
	static Vector3 yAxis() { return Vector3{ 0.0f, 1.0f, 0.0f }; }
	static Vector3 zAxis() { return Vector3{ 0.0f, 0.0f, 1.0f }; }

	float length() { return sqrtf(x * x + y * y + z * z); }

	Vector3 normalize() {
		float length = sqrtf(x * x + y * y + z * z);
		if (length == 0.0f) {
			return Vector3::zero();
		}
		return Vector3{
			x / length,
			y / length,
			z / length
		};
	};

	explicit Vector3(float x, float y, float z) : x(x), y(y), z(z) {};
};