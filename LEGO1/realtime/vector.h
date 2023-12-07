#ifndef VECTOR_H
#define VECTOR_H

#include <vec.h>

// TODO: Find proper compilation unit to put this
// FUNCTION: LEGO1 0x1000c0f0
// Vector2Impl::Vector2Impl

/*
 * A simple array of three floats that can be indexed into.
 */
class Vector3 {
public:
	float elements[3]; // storage is public for easy access

	Vector3() {}
	Vector3(float x, float y, float z)
	{
		elements[0] = x;
		elements[1] = y;
		elements[2] = z;
	}

	Vector3(const float v[3])
	{
		elements[0] = v[0];
		elements[1] = v[1];
		elements[2] = v[2];
	}

	const float& operator[](long i) const { return elements[i]; }
	float& operator[](long i) { return elements[i]; }
};

/*
 * A simple array of four floats that can be indexed into.
 */
struct Vector4 {
public:
	float elements[4]; // storage is public for easy access

	inline Vector4() {}
	Vector4(float x, float y, float z, float w)
	{
		elements[0] = x;
		elements[1] = y;
		elements[2] = z;
		elements[3] = w;
	}
	Vector4(const float v[4])
	{
		elements[0] = v[0];
		elements[1] = v[1];
		elements[2] = v[2];
		elements[3] = v[3];
	}

	const float& operator[](long i) const { return elements[i]; }
	float& operator[](long i) { return elements[i]; }
};

// VTABLE: LEGO1 0x100d4288
// SIZE 0x8
class Vector2Impl {
public:
	inline Vector2Impl(float* p_data) { m_data = p_data; }

	// FUNCTION: LEGO1 0x10001f80
	virtual void AddImpl(float* p_value)
	{
		m_data[0] += p_value[0];
		m_data[1] += p_value[1];
	}

	// FUNCTION: LEGO1 0x10001fa0
	virtual void AddImpl(float p_value)
	{
		m_data[0] += p_value;
		m_data[1] += p_value;
	}

	// FUNCTION: LEGO1 0x10001fc0
	virtual void SubImpl(float* p_value)
	{
		m_data[0] -= p_value[0];
		m_data[1] -= p_value[1];
	}

	// FUNCTION: LEGO1 0x10001fe0
	virtual void MulImpl(float* p_value)
	{
		m_data[0] *= p_value[0];
		m_data[1] *= p_value[1];
	}

	// FUNCTION: LEGO1 0x10002000
	virtual void MulImpl(float& p_value)
	{
		m_data[0] *= p_value;
		m_data[1] *= p_value;
	}

	// FUNCTION: LEGO1 0x10002020
	virtual void DivImpl(float* p_value)
	{
		m_data[0] /= *p_value;
		m_data[1] /= *p_value;
	}

	// FUNCTION: LEGO1 0x10002040
	virtual float DotImpl(float* p_a, float* p_b) const { return p_b[0] * p_a[0] + p_b[1] * p_a[1]; }

	// FUNCTION: LEGO1 0x10002060
	virtual void SetData(float* p_data) { this->m_data = p_data; }

	// FUNCTION: LEGO1 0x10002070
	virtual void EqualsImpl(float* p_data)
	{
		float* vec = m_data;
		vec[0] = p_data[0];
		vec[1] = p_data[1];
	}

	// FUNCTION: LEGO1 0x10002090
	virtual float* GetData() { return m_data; }

	// FUNCTION: LEGO1 0x100020a0
	virtual const float* GetData() const { return m_data; }

	// FUNCTION: LEGO1 0x100020b0
	virtual void Clear()
	{
		float* vec = m_data;
		vec[0] = 0.0f;
		vec[1] = 0.0f;
	}

	// FUNCTION: LEGO1 0x100020d0
	virtual float Dot(float* p_a, float* p_b) const { return DotImpl(p_a, p_b); }

	// FUNCTION: LEGO1 0x100020f0
	virtual float Dot(Vector2Impl* p_a, Vector2Impl* p_b) const { return DotImpl(p_a->m_data, p_b->m_data); }

	// FUNCTION: LEGO1 0x10002110
	virtual float Dot(float* p_a, Vector2Impl* p_b) const { return DotImpl(p_a, p_b->m_data); }

	// FUNCTION: LEGO1 0x10002130
	virtual float Dot(Vector2Impl* p_a, float* p_b) const { return DotImpl(p_a->m_data, p_b); }

	// FUNCTION: LEGO1 0x10002150
	virtual float LenSquared() { return NORMSQRD2(m_data); }

	// FUNCTION: LEGO1 0x10002160
	virtual int Normalize()
	{
		float sq = LenSquared();
		if (sq > 0.0f) {
			float root = sqrt(sq);
			if (root > 0) {
				Div(&root);
				return 0;
			}
		}
		return -1;
	}

	// FUNCTION: LEGO1 0x100021c0
	virtual void Add(float p_value) { AddImpl(p_value); }

	// FUNCTION: LEGO1 0x100021d0
	virtual void Add(float* p_other) { AddImpl(p_other); }

	// FUNCTION: LEGO1 0x100021e0
	virtual void Add(Vector2Impl* p_other) { AddImpl(p_other->m_data); }

	// FUNCTION: LEGO1 0x100021f0
	virtual void Sub(float* p_other) { SubImpl(p_other); }

	// FUNCTION: LEGO1 0x10002200
	virtual void Sub(Vector2Impl* p_other) { SubImpl(p_other->m_data); }

	// FUNCTION: LEGO1 0x10002210
	virtual void Mul(float* p_other) { MulImpl(p_other); }

	// FUNCTION: LEGO1 0x10002220
	virtual void Mul(Vector2Impl* p_other) { MulImpl(p_other->m_data); }

	// FUNCTION: LEGO1 0x10002230
	virtual void Mul(float& p_value) { MulImpl(p_value); }

	// FUNCTION: LEGO1 0x10002240
	virtual void Div(float* p_value) { DivImpl(p_value); }

	// FUNCTION: LEGO1 0x10002250
	virtual void SetVector(float* p_other) { EqualsImpl(p_other); }

	// FUNCTION: LEGO1 0x10002260
	virtual void SetVector(Vector2Impl* p_other) { EqualsImpl(p_other->m_data); }

	inline float& operator[](size_t idx) { return m_data[idx]; }
	inline const float& operator[](size_t idx) const { return m_data[idx]; }

protected:
	float* m_data;
};

// VTABLE: LEGO1 0x100d4518
// SIZE 0x8
class Vector3Impl : public Vector2Impl {
public:
	inline Vector3Impl(float* p_data) : Vector2Impl(p_data) {}
	// FUNCTION: LEGO1 0x10003a90
	virtual void AddImpl(float p_value)
	{
		m_data[0] += p_value;
		m_data[1] += p_value;
		m_data[2] += p_value;
	}

	// FUNCTION: LEGO1 0x10003a60
	virtual void AddImpl(float* p_value)
	{
		m_data[0] += p_value[0];
		m_data[1] += p_value[1];
		m_data[2] += p_value[2];
	}

	// FUNCTION: LEGO1 0x10003ac0
	virtual void SubImpl(float* p_value)
	{
		m_data[0] -= p_value[0];
		m_data[1] -= p_value[1];
		m_data[2] -= p_value[2];
	}

	// FUNCTION: LEGO1 0x10003b20
	virtual void MulImpl(float& p_value)
	{
		m_data[0] *= p_value;
		m_data[1] *= p_value;
		m_data[2] *= p_value;
	}

	// FUNCTION: LEGO1 0x10003af0
	virtual void MulImpl(float* p_value)
	{
		m_data[0] *= p_value[0];
		m_data[1] *= p_value[1];
		m_data[2] *= p_value[2];
	}

	// FUNCTION: LEGO1 0x10003b50
	virtual void DivImpl(float* p_value)
	{
		m_data[0] /= *p_value;
		m_data[1] /= *p_value;
		m_data[2] /= *p_value;
	}

	// FUNCTION: LEGO1 0x10003b80
	virtual float DotImpl(float* p_a, float* p_b) const { return p_a[0] * p_b[0] + p_a[2] * p_b[2] + p_a[1] * p_b[1]; }

	// FUNCTION: LEGO1 0x10003ba0
	virtual void EqualsImpl(float* p_data)
	{
		float* vec = m_data;
		vec[0] = p_data[0];
		vec[1] = p_data[1];
		vec[2] = p_data[2];
	}

	// FUNCTION: LEGO1 0x10003bc0
	virtual void Clear()
	{
		float* vec = m_data;
		vec[0] = 0.0f;
		vec[1] = 0.0f;
		vec[2] = 0.0f;
	}

	// FUNCTION: LEGO1 0x10003bd0
	virtual float LenSquared() const { return m_data[1] * m_data[1] + m_data[0] * m_data[0] + m_data[2] * m_data[2]; }

	// FUNCTION: LEGO1 0x10003bf0
	virtual void EqualsScalar(float* p_value)
	{
		m_data[0] = *p_value;
		m_data[1] = *p_value;
		m_data[2] = *p_value;
	}

	// vtable + 0x74
	// FUNCTION: LEGO1 0x10002270
	virtual void EqualsCrossImpl(float* p_a, float* p_b)
	{
		m_data[0] = p_a[1] * p_b[2] - p_a[2] * p_b[1];
		m_data[1] = p_a[2] * p_b[0] - p_a[0] * p_b[2];
		m_data[2] = p_a[0] * p_b[1] - p_a[1] * p_b[0];
	}

	// FUNCTION: LEGO1 0x10002300
	virtual void EqualsCross(float* p_a, Vector3Impl* p_b) { EqualsCrossImpl(p_a, p_b->m_data); }

	// FUNCTION: LEGO1 0x100022e0
	virtual void EqualsCross(Vector3Impl* p_a, float* p_b) { EqualsCrossImpl(p_a->m_data, p_b); }

	// FUNCTION: LEGO1 0x100022c0
	virtual void EqualsCross(Vector3Impl* p_a, Vector3Impl* p_b) { EqualsCrossImpl(p_a->m_data, p_b->m_data); }

	inline void Fill(float p_value) { EqualsScalar(&p_value); }
};

// VTABLE: LEGO1 0x100d45a0
// SIZE 0x8
class Vector4Impl : public Vector3Impl {
public:
	inline Vector4Impl(float* p_data) : Vector3Impl(p_data) {}

	// FUNCTION: LEGO1 0x10002870
	virtual void AddImpl(float* p_value)
	{
		m_data[0] += p_value[0];
		m_data[1] += p_value[1];
		m_data[2] += p_value[2];
		m_data[3] += p_value[3];
	}

	// FUNCTION: LEGO1 0x100028b0
	virtual void AddImpl(float p_value)
	{
		m_data[0] += p_value;
		m_data[1] += p_value;
		m_data[2] += p_value;
		m_data[3] += p_value;
	}

	// FUNCTION: LEGO1 0x100028f0
	virtual void SubImpl(float* p_value)
	{
		m_data[0] -= p_value[0];
		m_data[1] -= p_value[1];
		m_data[2] -= p_value[2];
		m_data[3] -= p_value[3];
	}

	// FUNCTION: LEGO1 0x10002930
	virtual void MulImpl(float* p_value)
	{
		m_data[0] *= p_value[0];
		m_data[1] *= p_value[1];
		m_data[2] *= p_value[2];
		m_data[3] *= p_value[3];
	}

	// FUNCTION: LEGO1 0x10002970
	virtual void MulImpl(float& p_value)
	{
		m_data[0] *= p_value;
		m_data[1] *= p_value;
		m_data[2] *= p_value;
		m_data[3] *= p_value;
	}

	// FUNCTION: LEGO1 0x100029b0
	virtual void DivImpl(float* p_value)
	{
		m_data[0] /= *p_value;
		m_data[1] /= *p_value;
		m_data[2] /= *p_value;
		m_data[3] /= *p_value;
	}

	// FUNCTION: LEGO1 0x100029f0
	virtual float DotImpl(float* p_a, float* p_b) const
	{
		return p_a[0] * p_b[0] + p_a[2] * p_b[2] + (p_a[1] * p_b[1] + p_a[3] * p_b[3]);
	}

	// FUNCTION: LEGO1 0x10002a20
	virtual void EqualsImpl(float* p_data)
	{
		float* vec = m_data;
		vec[0] = p_data[0];
		vec[1] = p_data[1];
		vec[2] = p_data[2];
		vec[3] = p_data[3];
	}

	// FUNCTION: LEGO1 0x10002a40
	virtual void SetMatrixProductImpl(float* p_vec, float* p_mat)
	{
		m_data[0] = p_vec[0] * p_mat[0] + p_vec[1] * p_mat[4] + p_vec[2] * p_mat[8] + p_vec[3] * p_mat[12];
		m_data[1] = p_vec[0] * p_mat[1] + p_vec[1] * p_mat[5] + p_vec[2] * p_mat[9] + p_vec[4] * p_mat[13];
		m_data[2] = p_vec[0] * p_mat[2] + p_vec[1] * p_mat[6] + p_vec[2] * p_mat[10] + p_vec[4] * p_mat[14];
		m_data[3] = p_vec[0] * p_mat[3] + p_vec[1] * p_mat[7] + p_vec[2] * p_mat[11] + p_vec[4] * p_mat[15];
	}

	// FUNCTION: LEGO1 0x10002ae0
	virtual void SetMatrixProduct(Vector4Impl* p_a, float* p_b) { SetMatrixProductImpl(p_a->m_data, p_b); }

	// FUNCTION: LEGO1 0x10002b00
	virtual void Clear()
	{
		float* vec = m_data;
		vec[0] = 0.0f;
		vec[1] = 0.0f;
		vec[2] = 0.0f;
		vec[3] = 0.0f;
	}

	// FUNCTION: LEGO1 0x10002b20
	virtual float LenSquared() const
	{
		return m_data[1] * m_data[1] + m_data[0] * m_data[0] + m_data[2] * m_data[2] + m_data[3] * m_data[3];
	}

	// FUNCTION: LEGO1 0x10002b40
	virtual void EqualsScalar(float* p_value)
	{
		m_data[0] = *p_value;
		m_data[1] = *p_value;
		m_data[2] = *p_value;
		m_data[3] = *p_value;
	}

	// Note close yet, included because I'm at least confident I know what operation
	// it's trying to do.
	// STUB: LEGO1 0x10002b70
	virtual int NormalizeQuaternion()
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
	virtual void UnknownQuaternionOp(Vector4Impl* p_a, Vector4Impl* p_b)
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
};

// VTABLE: LEGO1 0x100d4488
// SIZE 0x14
class Vector3Data : public Vector3Impl {
public:
	inline Vector3Data() : Vector3Impl(m_vector.elements) {}
	inline Vector3Data(float p_x, float p_y, float p_z) : Vector3Impl(m_vector.elements), m_vector(p_x, p_y, p_z) {}
	inline Vector3Data& operator=(Vector3Data& p_other)
	{
		EqualsImpl(p_other.m_data);
		SET3(m_vector, p_other.m_vector);
		return *this;
	}

	inline void CopyFrom(Vector3Data& p_other)
	{
		EqualsImpl(p_other.m_data);

		float* dest = m_vector.elements;
		float* src = p_other.m_vector.elements;
		for (; dest < (m_vector.elements + 3);)
			*dest++ = *src++;
	}

	inline void EqualsCross(Vector3Data& p_a, Vector3Data& p_b) { EqualsCrossImpl(p_a.m_data, p_b.m_data); }

private:
	Vector3 m_vector;
};

// VTABLE: LEGO1 0x100d41e8
// SIZE 0x18
class Vector4Data : public Vector4Impl {
public:
	inline Vector4Data() : Vector4Impl(m_vector.elements) {}
	// FUNCTION: LEGO1 0x10003200
	virtual void operator=(Vector4Data& p_other) { EqualsImpl(p_other.m_data); }

private:
	Vector4 m_vector;
};

#endif // VECTOR_H
