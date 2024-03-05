#ifndef VECTOR_H
#define VECTOR_H

#include "compat.h"

#include <math.h>
#include <memory.h>

// VTABLE: LEGO1 0x100d4288
// SIZE 0x08
class Vector2 {
public:
	// FUNCTION: LEGO1 0x1000c0f0
	inline Vector2(float* p_data) { SetData(p_data); }

	// Note: virtual function overloads appear in the virtual table
	// in reverse order of appearance.

	// FUNCTION: LEGO1 0x10001f80
	virtual void AddImpl(float* p_value)
	{
		m_data[0] += p_value[0];
		m_data[1] += p_value[1];
	} // vtable+0x04

	// FUNCTION: LEGO1 0x10001fa0
	virtual void AddImpl(float p_value)
	{
		m_data[0] += p_value;
		m_data[1] += p_value;
	} // vtable+0x00

	// FUNCTION: LEGO1 0x10001fc0
	virtual void SubImpl(float* p_value)
	{
		m_data[0] -= p_value[0];
		m_data[1] -= p_value[1];
	} // vtable+0x08

	// Those are also overloads in all likelihood,
	// but we need a type to do that.

	// FUNCTION: LEGO1 0x10002000
	virtual void MulScalarImpl(float* p_value)
	{
		m_data[0] *= *p_value;
		m_data[1] *= *p_value;
	} // vtable+0x0c

	// FUNCTION: LEGO1 0x10001fe0
	virtual void MulVectorImpl(float* p_value)
	{
		m_data[0] *= p_value[0];
		m_data[1] *= p_value[1];
	} // vtable+0x10

	// FUNCTION: LEGO1 0x10002020
	virtual void DivScalarImpl(float* p_value)
	{
		m_data[0] /= *p_value;
		m_data[1] /= *p_value;
	} // vtable+0x14

	// FUNCTION: LEGO1 0x10002040
	virtual float DotImpl(float* p_a, float* p_b) const { return p_b[0] * p_a[0] + p_b[1] * p_a[1]; } // vtable+0x18

	// FUNCTION: LEGO1 0x10002060
	virtual void SetData(float* p_data) { m_data = p_data; } // vtable+0x1c

	// FUNCTION: LEGO1 0x10002070
	virtual void EqualsImpl(float* p_data) { memcpy(m_data, p_data, sizeof(float) * 2); } // vtable+0x20

	// FUNCTION: LEGO1 0x10002090
	virtual float* GetData() { return m_data; } // vtable+0x28

	// FUNCTION: LEGO1 0x100020a0
	virtual const float* GetData() const { return m_data; } // vtable+0x24

	// FUNCTION: LEGO1 0x100020b0
	virtual void Clear() { memset(m_data, 0, sizeof(float) * 2); } // vtable+0x2c

	// FUNCTION: LEGO1 0x100020d0
	virtual float Dot(float* p_a, float* p_b) const { return DotImpl(p_a, p_b); } // vtable+0x3c

	// FUNCTION: LEGO1 0x100020f0
	virtual float Dot(Vector2* p_a, Vector2* p_b) const { return DotImpl(p_a->m_data, p_b->m_data); } // vtable+0x38

	// FUNCTION: LEGO1 0x10002110
	virtual float Dot(float* p_a, Vector2* p_b) const { return DotImpl(p_a, p_b->m_data); } // vtable+0x34

	// FUNCTION: LEGO1 0x10002130
	virtual float Dot(Vector2* p_a, float* p_b) const { return DotImpl(p_a->m_data, p_b); } // vtable+0x30

	// FUNCTION: LEGO1 0x10002150
	virtual float LenSquared() const { return m_data[0] * m_data[0] + m_data[1] * m_data[1]; } // vtable+0x40

	// FUNCTION: LEGO1 0x10002160
	virtual int Unitize()
	{
		float sq = LenSquared();
		if (sq > 0.0f) {
			float root = sqrt(sq);
			if (root > 0) {
				DivScalarImpl(&root);
				return 0;
			}
		}
		return -1;
	} // vtable+0x44

	// FUNCTION: LEGO1 0x100021c0
	virtual void Add(float p_value) { AddImpl(p_value); } // vtable+0x50

	// FUNCTION: LEGO1 0x100021d0
	virtual void Add(float* p_other) { AddImpl(p_other); } // vtable+0x4c

	// FUNCTION: LEGO1 0x100021e0
	virtual void Add(Vector2* p_other) { AddImpl(p_other->m_data); } // vtable+0x48

	// FUNCTION: LEGO1 0x100021f0
	virtual void Sub(float* p_other) { SubImpl(p_other); } // vtable+0x58

	// FUNCTION: LEGO1 0x10002200
	virtual void Sub(Vector2* p_other) { SubImpl(p_other->m_data); } // vtable+0x54

	// FUNCTION: LEGO1 0x10002210
	virtual void Mul(float* p_other) { MulVectorImpl(p_other); } // vtable+0x64

	// FUNCTION: LEGO1 0x10002220
	virtual void Mul(Vector2* p_other) { MulVectorImpl(p_other->m_data); } // vtable+0x60

	// FUNCTION: LEGO1 0x10002230
	virtual void Mul(float& p_value) { MulScalarImpl(&p_value); } // vtable+0x5c

	// FUNCTION: LEGO1 0x10002240
	virtual void Div(float& p_value) { DivScalarImpl(&p_value); } // vtable+0x68

	// FUNCTION: LEGO1 0x10002250
	virtual void SetVector(float* p_other) { EqualsImpl(p_other); } // vtable+0x70

	// FUNCTION: LEGO1 0x10002260
	virtual void SetVector(const Vector2* p_other) { EqualsImpl(p_other->m_data); } // vtable+0x6c

	// SYNTHETIC: LEGO1 0x10010be0
	// Vector3::operator=

	inline Vector2& operator=(const Vector2& p_other)
	{
		Vector2::SetVector(&p_other);
		return *this;
	}
	inline float& operator[](size_t idx) { return m_data[idx]; }
	inline const float& operator[](size_t idx) const { return m_data[idx]; }

protected:
	float* m_data; // 0x04
};

// VTABLE: LEGO1 0x100d4518
// SIZE 0x08
class Vector3 : public Vector2 {
public:
	// FUNCTION: LEGO1 0x1001d150
	inline Vector3(float* p_data) : Vector2(p_data) {}

	// Hack: Some code initializes a Vector3 from a (most likely) const float* source.
	// Example: LegoCameraController::GetWorldUp
	// Vector3 however is a class that can mutate its underlying source, making
	// initialization with a const source fundamentally incompatible.
	inline Vector3(const float* p_data) : Vector2((float*) p_data) {}

	// Note: virtual function overloads appear in the virtual table
	// in reverse order of appearance.

	// FUNCTION: LEGO1 0x10002270
	virtual void EqualsCrossImpl(float* p_a, float* p_b)
	{
		m_data[0] = p_a[1] * p_b[2] - p_a[2] * p_b[1];
		m_data[1] = p_a[2] * p_b[0] - p_a[0] * p_b[2];
		m_data[2] = p_a[0] * p_b[1] - p_a[1] * p_b[0];
	} // vtable+0x74

	// FUNCTION: LEGO1 0x100022c0
	virtual void EqualsCross(Vector3* p_a, Vector3* p_b) { EqualsCrossImpl(p_a->m_data, p_b->m_data); } // vtable+0x80

	// FUNCTION: LEGO1 0x100022e0
	virtual void EqualsCross(Vector3* p_a, float* p_b) { EqualsCrossImpl(p_a->m_data, p_b); } // vtable+0x7c

	// FUNCTION: LEGO1 0x10002300
	virtual void EqualsCross(float* p_a, Vector3* p_b) { EqualsCrossImpl(p_a, p_b->m_data); } // vtable+0x78

	// FUNCTION: LEGO1 0x10003bf0
	virtual void EqualsScalar(float* p_value)
	{
		m_data[0] = *p_value;
		m_data[1] = *p_value;
		m_data[2] = *p_value;
	} // vtable+0x84

	// Vector2 overrides

	// FUNCTION: LEGO1 0x10003a60
	void AddImpl(float* p_value) override
	{
		m_data[0] += p_value[0];
		m_data[1] += p_value[1];
		m_data[2] += p_value[2];
	} // vtable+0x04

	// FUNCTION: LEGO1 0x10003a90
	void AddImpl(float p_value) override
	{
		m_data[0] += p_value;
		m_data[1] += p_value;
		m_data[2] += p_value;
	} // vtable+0x00

	// FUNCTION: LEGO1 0x10003ac0
	void SubImpl(float* p_value) override
	{
		m_data[0] -= p_value[0];
		m_data[1] -= p_value[1];
		m_data[2] -= p_value[2];
	} // vtable+0x08

	// FUNCTION: LEGO1 0x10003b20
	void MulScalarImpl(float* p_value) override
	{
		m_data[0] *= *p_value;
		m_data[1] *= *p_value;
		m_data[2] *= *p_value;
	} // vtable+0x0c

	// FUNCTION: LEGO1 0x10003af0
	void MulVectorImpl(float* p_value) override
	{
		m_data[0] *= p_value[0];
		m_data[1] *= p_value[1];
		m_data[2] *= p_value[2];
	} // vtable+0x10

	// FUNCTION: LEGO1 0x10003b50
	void DivScalarImpl(float* p_value) override
	{
		m_data[0] /= *p_value;
		m_data[1] /= *p_value;
		m_data[2] /= *p_value;
	} // vtable+0x14

	// FUNCTION: LEGO1 0x10003b80
	float DotImpl(float* p_a, float* p_b) const override
	{
		return p_a[0] * p_b[0] + p_a[2] * p_b[2] + p_a[1] * p_b[1];
	} // vtable+0x18

	// FUNCTION: LEGO1 0x10003ba0
	void EqualsImpl(float* p_data) override { memcpy(m_data, p_data, sizeof(float) * 3); } // vtable+0x20

	// FUNCTION: LEGO1 0x10003bc0
	void Clear() override { memset(m_data, 0, sizeof(float) * 3); } // vtable+0x2c

	// FUNCTION: LEGO1 0x10003bd0
	float LenSquared() const override
	{
		return m_data[1] * m_data[1] + m_data[0] * m_data[0] + m_data[2] * m_data[2];
	} // vtable+0x40

	inline void Fill(float p_value) { EqualsScalar(&p_value); }

	friend class Mx3DPointFloat;
};

// VTABLE: LEGO1 0x100d45a0
// SIZE 0x08
class Vector4 : public Vector3 {
public:
	inline Vector4(float* p_data) : Vector3(p_data) {}

	// Note: virtual function overloads appear in the virtual table
	// in reverse order of appearance.

	// FUNCTION: LEGO1 0x10002a40
	virtual void SetMatrixProduct(float* p_vec, float* p_mat)
	{
		m_data[0] = p_vec[0] * p_mat[0] + p_vec[1] * p_mat[4] + p_vec[2] * p_mat[8] + p_vec[3] * p_mat[12];
		m_data[1] = p_vec[0] * p_mat[1] + p_vec[1] * p_mat[5] + p_vec[2] * p_mat[9] + p_vec[4] * p_mat[13];
		m_data[2] = p_vec[0] * p_mat[2] + p_vec[1] * p_mat[6] + p_vec[2] * p_mat[10] + p_vec[4] * p_mat[14];
		m_data[3] = p_vec[0] * p_mat[3] + p_vec[1] * p_mat[7] + p_vec[2] * p_mat[11] + p_vec[4] * p_mat[15];
	} // vtable+0x8c

	// FUNCTION: LEGO1 0x10002ae0
	virtual void SetMatrixProduct(Vector4* p_a, float* p_b) { SetMatrixProduct(p_a->m_data, p_b); } // vtable+0x88

	inline virtual int NormalizeQuaternion();                            // vtable+90
	inline virtual void UnknownQuaternionOp(Vector4* p_a, Vector4* p_b); // vtable+94

	// Vector3 overrides

	// FUNCTION: LEGO1 0x10002870
	void AddImpl(float* p_value) override
	{
		m_data[0] += p_value[0];
		m_data[1] += p_value[1];
		m_data[2] += p_value[2];
		m_data[3] += p_value[3];
	} // vtable+0x04

	// FUNCTION: LEGO1 0x100028b0
	void AddImpl(float p_value) override
	{
		m_data[0] += p_value;
		m_data[1] += p_value;
		m_data[2] += p_value;
		m_data[3] += p_value;
	} // vtable+0x00

	// FUNCTION: LEGO1 0x100028f0
	void SubImpl(float* p_value) override
	{
		m_data[0] -= p_value[0];
		m_data[1] -= p_value[1];
		m_data[2] -= p_value[2];
		m_data[3] -= p_value[3];
	} // vtable+0x08

	// FUNCTION: LEGO1 0x10002970
	void MulScalarImpl(float* p_value) override
	{
		m_data[0] *= *p_value;
		m_data[1] *= *p_value;
		m_data[2] *= *p_value;
		m_data[3] *= *p_value;
	} // vtable+0x0c

	// FUNCTION: LEGO1 0x10002930
	void MulVectorImpl(float* p_value) override
	{
		m_data[0] *= p_value[0];
		m_data[1] *= p_value[1];
		m_data[2] *= p_value[2];
		m_data[3] *= p_value[3];
	} // vtable+0x10

	// FUNCTION: LEGO1 0x100029b0
	void DivScalarImpl(float* p_value) override
	{
		m_data[0] /= *p_value;
		m_data[1] /= *p_value;
		m_data[2] /= *p_value;
		m_data[3] /= *p_value;
	} // vtable+0x14

	// FUNCTION: LEGO1 0x100029f0
	float DotImpl(float* p_a, float* p_b) const override
	{
		return p_a[0] * p_b[0] + p_a[2] * p_b[2] + (p_a[1] * p_b[1] + p_a[3] * p_b[3]);
	} // vtable+0x18

	// FUNCTION: LEGO1 0x10002a20
	void EqualsImpl(float* p_data) override { memcpy(m_data, p_data, sizeof(float) * 4); } // vtable+0x20

	// FUNCTION: LEGO1 0x10002b00
	void Clear() override { memset(m_data, 0, sizeof(float) * 4); } // vtable+0x2c

	// FUNCTION: LEGO1 0x10002b20
	float LenSquared() const override
	{
		return m_data[1] * m_data[1] + m_data[0] * m_data[0] + m_data[2] * m_data[2] + m_data[3] * m_data[3];
	} // vtable+0x40

	// FUNCTION: LEGO1 0x10002b40
	void EqualsScalar(float* p_value) override
	{
		m_data[0] = *p_value;
		m_data[1] = *p_value;
		m_data[2] = *p_value;
		m_data[3] = *p_value;
	} // vtable+0x84
};

// Note close yet, included because I'm at least confident I know what operation
// it's trying to do.
// STUB: LEGO1 0x10002b70
inline int Vector4::NormalizeQuaternion()
{
	float* v = m_data;
	float magnitude = v[1] * v[1] + v[2] * v[2] + v[0] * v[0];
	if (magnitude > 0.0f) {
		float theta = v[3] * 0.5f;
		v[3] = cos(theta);
		float frac = sin(theta);
		magnitude = frac / sqrt(magnitude);
		v[0] *= magnitude;
		v[1] *= magnitude;
		v[2] *= magnitude;
		return 0;
	}
	return -1;
}

// FUNCTION: LEGO1 0x10002bf0
inline void Vector4::UnknownQuaternionOp(Vector4* p_a, Vector4* p_b)
{
	float* bDat = p_b->m_data;
	float* aDat = p_a->m_data;

	this->m_data[3] = aDat[3] * bDat[3] - (bDat[0] * aDat[0] + aDat[2] * bDat[2] + aDat[1] * aDat[1]);
	this->m_data[0] = bDat[2] * aDat[1] - bDat[1] * aDat[2];
	this->m_data[1] = aDat[2] * bDat[0] - bDat[2] * aDat[0];
	this->m_data[2] = bDat[1] * aDat[0] - aDat[1] * bDat[0];

	m_data[0] = p_b->m_data[3] * p_a->m_data[0] + p_a->m_data[3] * p_b->m_data[0] + m_data[0];
	m_data[1] = p_b->m_data[1] * p_a->m_data[3] + p_a->m_data[1] * p_b->m_data[3] + m_data[1];
	m_data[2] = p_b->m_data[2] * p_a->m_data[3] + p_a->m_data[2] * p_b->m_data[3] + m_data[2];
}

#endif // VECTOR_H
