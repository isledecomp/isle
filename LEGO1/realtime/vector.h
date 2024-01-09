#ifndef VECTOR_H
#define VECTOR_H

#include <vec.h>

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
	// FUNCTION: LEGO1 0x1000c0f0
	inline Vector2Impl(float* p_data) { SetData(p_data); }

	// vtable + 0x00 (no virtual destructor)
	virtual void AddScalarImpl(float p_value) = 0;
	virtual void AddVectorImpl(float* p_value) = 0;
	virtual void SubVectorImpl(float* p_value) = 0;
	virtual void MullScalarImpl(float* p_value) = 0;

	// vtable + 0x10
	virtual void MullVectorImpl(float* p_value) = 0;
	virtual void DivScalarImpl(float* p_value) = 0;
	virtual float DotImpl(float* p_a, float* p_b) const = 0;
	// FUNCTION: LEGO1 0x10002060
	virtual void SetData(float* p_data) { m_data = p_data; }

	// vtable + 0x20
	virtual void EqualsImpl(float* p_data) = 0;
	virtual float* GetData();
	virtual const float* GetData() const;
	virtual void Clear() = 0;

	// vtable + 0x30
	virtual float Dot(Vector2Impl* p_a, float* p_b) const;
	virtual float Dot(float* p_a, Vector2Impl* p_b) const;
	virtual float Dot(Vector2Impl* p_a, Vector2Impl* p_b) const;
	virtual float Dot(float* p_a, float* p_b) const;

	// vtable + 0x40
	virtual float LenSquared() const = 0;
	virtual int Unitize();

	// vtable + 0x48
	virtual void Add(Vector2Impl* p_other);
	virtual void Add(float* p_other);
	virtual void Add(float p_value);

	// vtable + 0x54
	virtual void Sub(Vector2Impl* p_other);
	virtual void Sub(float* p_other);

	// vtable + 0x5C
	virtual void Mul(float* p_value);
	virtual void Mul(Vector2Impl* p_other);
	virtual void Mul(float& p_other);
	virtual void Div(float& p_value);

	// vtable + 0x6C
	virtual void SetVector(Vector2Impl* p_other);
	virtual void SetVector(float* p_other);

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

	void AddScalarImpl(float p_value);

	void AddVectorImpl(float* p_value);

	void SubVectorImpl(float* p_value);
	void MullScalarImpl(float* p_value);
	void MullVectorImpl(float* p_value);
	void DivScalarImpl(float* p_value);
	float DotImpl(float* p_a, float* p_b) const;

	void EqualsImpl(float* p_data);

	void Clear();

	float LenSquared() const;

	// vtable + 0x74
	virtual void EqualsCrossImpl(float* p_a, float* p_b);
	virtual void EqualsCross(float* p_a, Vector3Impl* p_b);
	virtual void EqualsCross(Vector3Impl* p_a, float* p_b);
	virtual void EqualsCross(Vector3Impl* p_a, Vector3Impl* p_b);
	virtual void EqualsScalar(float* p_value);

	inline void Fill(float p_value) { EqualsScalar(&p_value); }
};

// VTABLE: LEGO1 0x100d45a0
// SIZE 0x8
class Vector4Impl : public Vector3Impl {
public:
	inline Vector4Impl(float* p_data) : Vector3Impl(p_data) {}

	void AddScalarImpl(float p_value);

	void AddVectorImpl(float* p_value);

	void SubVectorImpl(float* p_value);
	void MullScalarImpl(float* p_value);
	void MullVectorImpl(float* p_value);
	void DivScalarImpl(float* p_value);
	float DotImpl(float* p_a, float* p_b) const;

	void EqualsImpl(float* p_data);

	void Clear();

	float LenSquared() const;

	void EqualsScalar(float* p_value);

	// vtable + 0x88
	virtual void SetMatrixProduct(Vector4Impl* p_a, float* p_b);
	virtual void SetMatrixProductImpl(float* p_vec, float* p_mat);
	virtual int NormalizeQuaternion();
	virtual void UnknownQuaternionOp(Vector4Impl* p_a, Vector4Impl* p_b);

	inline Vector4& GetVector() { return *((Vector4*) m_data); }
};

// VTABLE: LEGO1 0x100d4488
// SIZE 0x14
class Vector3Data : public Vector3Impl {
public:
	inline Vector3Data() : Vector3Impl(m_vector.elements) {}
	inline Vector3Data(float p_x, float p_y, float p_z) : Vector3Impl(m_vector.elements), m_vector(p_x, p_y, p_z) {}

	void CopyFrom(Vector3Data& p_other)
	{
		EqualsImpl(p_other.m_data);

		float* dest = m_vector.elements;
		float* src = p_other.m_vector.elements;
		for (size_t i = sizeof(m_vector) / sizeof(float); i > 0; --i)
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

private:
	Vector4 m_vector;
};

#endif // VECTOR_H
