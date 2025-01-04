#ifndef VECTOR_H
#define VECTOR_H

#include "compat.h"

// Note: virtual function overloads appear in the virtual table
// in reverse order of appearance.

// VTABLE: LEGO1 0x100d4288
// VTABLE: BETA10 0x101b8440
// SIZE 0x08
class Vector2 {
protected:
	inline virtual void AddImpl(const float* p_value);                      // vtable+0x04
	inline virtual void AddImpl(float p_value);                             // vtable+0x00
	inline virtual void SubImpl(const float* p_value);                      // vtable+0x08
	inline virtual void MulImpl(const float* p_value);                      // vtable+0x10
	inline virtual void MulImpl(const float& p_value);                      // vtable+0x0c
	inline virtual void DivImpl(const float& p_value);                      // vtable+0x14
	inline virtual float DotImpl(const float* p_a, const float* p_b) const; // vtable+0x18
	inline virtual void SetData(float* p_data);                             // vtable+0x1c
	inline virtual void EqualsImpl(const float* p_data);                    // vtable+0x20

	float* m_data; // 0x04

public:
	// FUNCTION: LEGO1 0x1000c0f0
	// FUNCTION: BETA10 0x100116a0
	Vector2(float* p_data) { SetData(p_data); }

	// FUNCTION: BETA10 0x100109e0
	Vector2(const float* p_data) { m_data = (float*) p_data; }

	inline virtual float* GetData();                                        // vtable+0x28
	inline virtual const float* GetData() const;                            // vtable+0x24
	inline virtual void Clear();                                            // vtable+0x2c
	inline virtual float Dot(const float* p_a, const float* p_b) const;     // vtable+0x3c
	inline virtual float Dot(const Vector2& p_a, const Vector2& p_b) const; // vtable+0x38
	inline virtual float Dot(const float* p_a, const Vector2& p_b) const;   // vtable+0x34
	inline virtual float Dot(const Vector2& p_a, const float* p_b) const;   // vtable+0x30
	inline virtual float LenSquared() const;                                // vtable+0x40
	inline virtual int Unitize();                                           // vtable+0x44
	inline virtual void operator+=(float p_value);                          // vtable+0x50
	inline virtual void operator+=(const float* p_other);                   // vtable+0x4c
	inline virtual void operator+=(const Vector2& p_other);                 // vtable+0x48
	inline virtual void operator-=(const float* p_other);                   // vtable+0x58
	inline virtual void operator-=(const Vector2& p_other);                 // vtable+0x54
	inline virtual void operator*=(const float* p_other);                   // vtable+0x64
	inline virtual void operator*=(const Vector2& p_other);                 // vtable+0x60
	inline virtual void operator*=(const float& p_value);                   // vtable+0x5c
	inline virtual void operator/=(const float& p_value);                   // vtable+0x68
	inline virtual void operator=(const float* p_other);                    // vtable+0x70
	inline virtual void operator=(const Vector2& p_other);                  // vtable+0x6c

	// SYNTHETIC: LEGO1 0x10010be0
	// SYNTHETIC: BETA10 0x100121e0
	// Vector3::operator=

	// SYNTHETIC: BETA10 0x1004af40
	// Vector4::operator=

	// FUNCTION: BETA10 0x1001d140
	float& operator[](int idx) { return m_data[idx]; }

	// FUNCTION: BETA10 0x1001d170
	const float& operator[](int idx) const { return m_data[idx]; }
};

// VTABLE: LEGO1 0x100d4518
// VTABLE: BETA10 0x101b8398
// SIZE 0x08
class Vector3 : public Vector2 {
protected:
	inline void AddImpl(const float* p_value) override;                      // vtable+0x04
	inline void AddImpl(float p_value) override;                             // vtable+0x00
	inline void SubImpl(const float* p_value) override;                      // vtable+0x08
	inline void MulImpl(const float* p_value) override;                      // vtable+0x10
	inline void MulImpl(const float& p_value) override;                      // vtable+0x0c
	inline void DivImpl(const float& p_value) override;                      // vtable+0x14
	inline float DotImpl(const float* p_a, const float* p_b) const override; // vtable+0x18
	inline void EqualsImpl(const float* p_data) override;                    // vtable+0x20
	inline virtual void EqualsCrossImpl(const float* p_a, const float* p_b); // vtable+0x74

public:
	// FUNCTION: LEGO1 0x1001d150
	// FUNCTION: BETA10 0x10011660
	Vector3(float* p_data) : Vector2(p_data) {}

	// Hack: Some code initializes a Vector3 from a (most likely) const float* source.
	// Example: LegoCameraController::GetWorldUp
	// Vector3 however is a class that can mutate its underlying source, making
	// initialization with a const source fundamentally incompatible.

	// FUNCTION: BETA10 0x100109a0
	Vector3(const float* p_data) : Vector2(p_data) {}

	inline void Clear() override;                                            // vtable+0x2c
	inline float LenSquared() const override;                                // vtable+0x40
	inline virtual void EqualsCross(const Vector3& p_a, const Vector3& p_b); // vtable+0x80
	inline virtual void EqualsCross(const Vector3& p_a, const float* p_b);   // vtable+0x7c
	inline virtual void EqualsCross(const float* p_a, const Vector3& p_b);   // vtable+0x78
	inline virtual void Fill(const float& p_value);                          // vtable+0x84

	friend class Mx3DPointFloat;
};

// VTABLE: LEGO1 0x100d45a0
// VTABLE: BETA10 0x101bac38
// SIZE 0x08
class Vector4 : public Vector3 {
protected:
	inline void AddImpl(const float* p_value) override;                      // vtable+0x04
	inline void AddImpl(float p_value) override;                             // vtable+0x00
	inline void SubImpl(const float* p_value) override;                      // vtable+0x08
	inline void MulImpl(const float* p_value) override;                      // vtable+0x10
	inline void MulImpl(const float& p_value) override;                      // vtable+0x0c
	inline void DivImpl(const float& p_value) override;                      // vtable+0x14
	inline float DotImpl(const float* p_a, const float* p_b) const override; // vtable+0x18
	inline void EqualsImpl(const float* p_data) override;                    // vtable+0x20

public:
	// FUNCTION: BETA10 0x10048780
	Vector4(float* p_data) : Vector3(p_data) {}

	// Some code initializes a Vector4 from a `const float*` source.
	// Example: `LegoCarBuild::VTable0x6c`
	// Vector4 however is a class that can mutate its underlying source, making
	// initialization with a const source fundamentally incompatible.
	// BETA10 appears to have two separate constructors for Vector4 as well,
	// supporting the theory that this decompilation is correct.

	// FUNCTION: BETA10 0x100701b0
	Vector4(const float* p_data) : Vector3(p_data) {}

	inline void Clear() override;                                                     // vtable+0x2c
	inline float LenSquared() const override;                                         // vtable+0x40
	inline void Fill(const float& p_value) override;                                  // vtable+0x84
	inline virtual void SetMatrixProduct(const float* p_vec, const float* p_mat);     // vtable+0x8c
	inline virtual void SetMatrixProduct(const Vector4& p_a, const float* p_b);       // vtable+0x88
	inline virtual int NormalizeQuaternion();                                         // vtable+0x90
	inline virtual int EqualsHamiltonProduct(const Vector4& p_a, const Vector4& p_b); // vtable+0x94

	float& operator[](int idx) { return m_data[idx]; }

	// FUNCTION: BETA10 0x10010890
	const float& operator[](int idx) const { return m_data[idx]; }

	friend class Mx4DPointFloat;
};

#endif // VECTOR_H
