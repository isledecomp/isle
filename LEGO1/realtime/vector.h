#ifndef VECTOR_H
#define VECTOR_H

#include "compat.h"

#include <math.h>
#include <memory.h>

// Note: virtual function overloads appear in the virtual table
// in reverse order of appearance.

// VTABLE: LEGO1 0x100d4288
// VTABLE: BETA10 0x101b8440
// SIZE 0x08
class Vector2 {
public:
	// FUNCTION: LEGO1 0x1000c0f0
	// FUNCTION: BETA10 0x100116a0
	Vector2(float* p_data) { SetData(p_data); }

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

public:
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
	inline virtual void SetVector(const float* p_other);                    // vtable+0x70
	inline virtual void SetVector(const Vector2& p_other);                  // vtable+0x6c

	// Note: it's unclear whether Vector3::operator= has been defined explicitly
	// with the same function body as Vector2& operator=. The BETA indicates that;
	// however, it makes LEGO1 0x10010be0 disappear and worsens matches in
	// at least these functions:
	// LEGO1 0x100109b0
	// LEGO1 0x10023130
	// LEGO1 0x1002de10
	// LEGO1 0x10050a80
	// LEGO1 0x10053980
	// LEGO1 0x100648f0
	// LEGO1 0x10064b50
	// LEGO1 0x10084030
	// LEGO1 0x100a9410
	// However, defining it as in the BETA improves at least these functions:
	// LEGO1 0x10042300

	// SYNTHETIC: LEGO1 0x10010be0
	// SYNTHETIC: BETA10 0x100121e0
	// Vector3::operator=

	// SYNTHETIC: BETA10 0x1004af40
	// Vector4::operator=

	Vector2& operator=(const Vector2& p_other)
	{
		Vector2::SetVector(p_other);
		return *this;
	}

	// FUNCTION: BETA10 0x1001d140
	float& operator[](int idx) { return m_data[idx]; }

	// FUNCTION: BETA10 0x1001d170
	const float& operator[](int idx) const { return m_data[idx]; }

protected:
	float* m_data; // 0x04
};

// VTABLE: LEGO1 0x100d4518
// VTABLE: BETA10 0x101b8398
// SIZE 0x08
class Vector3 : public Vector2 {
public:
	// FUNCTION: LEGO1 0x1001d150
	// FUNCTION: BETA10 0x10011660
	Vector3(float* p_data) : Vector2(p_data) {}

	// Hack: Some code initializes a Vector3 from a (most likely) const float* source.
	// Example: LegoCameraController::GetWorldUp
	// Vector3 however is a class that can mutate its underlying source, making
	// initialization with a const source fundamentally incompatible.

	// FUNCTION: BETA10 0x100109a0
	Vector3(const float* p_data) : Vector2((float*) p_data) {}

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
	inline void Clear() override;                                            // vtable+0x2c
	inline float LenSquared() const override;                                // vtable+0x40
	inline virtual void EqualsCross(const Vector3& p_a, const Vector3& p_b); // vtable+0x80
	inline virtual void EqualsCross(const Vector3& p_a, const float* p_b);   // vtable+0x7c
	inline virtual void EqualsCross(const float* p_a, const Vector3& p_b);   // vtable+0x78
	inline virtual void Fill(const float& p_value);                          // vtable+0x84

	friend class Mx3DPointFloat;
};

#include "vector2d.inl"
#include "vector3d.inl"

// VTABLE: LEGO1 0x100d45a0
// VTABLE: BETA10 0x101bac38
// SIZE 0x08
class Vector4 : public Vector3 {
public:
	// FUNCTION: BETA10 0x10048780
	inline Vector4(float* p_data) : Vector3(p_data) {}

	// Some code initializes a Vector4 from a `const float*` source.
	// Example: `LegoCarBuild::VTable0x6c`
	// Vector4 however is a class that can mutate its underlying source, making
	// initialization with a const source fundamentally incompatible.
	// BETA10 appears to have two separate constructors for Vector4 as well,
	// supporting the theory that this decompilation is correct.

	// FUNCTION: BETA10 0x100701b0
	inline Vector4(const float* p_data) : Vector3((float*) p_data) {}

	// Note: virtual function overloads appear in the virtual table
	// in reverse order of appearance.

	inline void AddImpl(const float* p_value) override;                      // vtable+0x04
	inline void AddImpl(float p_value) override;                             // vtable+0x00
	inline void SubImpl(const float* p_value) override;                      // vtable+0x08
	inline void MulImpl(const float* p_value) override;                      // vtable+0x10
	inline void MulImpl(const float& p_value) override;                      // vtable+0x0c
	inline void DivImpl(const float& p_value) override;                      // vtable+0x14
	inline float DotImpl(const float* p_a, const float* p_b) const override; // vtable+0x18
	inline void EqualsImpl(const float* p_data) override;                    // vtable+0x20

	inline void Clear() override;                    // vtable+0x2c
	inline float LenSquared() const override;        // vtable+0x40
	inline void Fill(const float& p_value) override; // vtable+0x84

	inline virtual void SetMatrixProduct(const float* p_vec, const float* p_mat);     // vtable+0x8c
	inline virtual void SetMatrixProduct(const Vector4& p_a, const float* p_b);       // vtable+0x88
	inline virtual int NormalizeQuaternion();                                         // vtable+0x90
	inline virtual int EqualsHamiltonProduct(const Vector4& p_a, const Vector4& p_b); // vtable+0x94

	float& operator[](int idx) { return m_data[idx]; }

	// FUNCTION: BETA10 0x10010890
	const float& operator[](int idx) const { return m_data[idx]; }

	friend class Mx4DPointFloat;
};

struct UnknownMatrixType {
	float m_data[4][4];
};

// VTABLE: LEGO1 0x100d4350
// VTABLE: BETA10 0x101b8340
// SIZE 0x08
class Matrix4 {
public:
	// FUNCTION: LEGO1 0x10004500
	// FUNCTION: BETA10 0x1000fc70
	Matrix4(float (*p_data)[4]) { SetData(p_data); }

	// Note: virtual function overloads appear in the virtual table
	// in reverse order of appearance.

	// FUNCTION: LEGO1 0x10002320
	// FUNCTION: BETA10 0x1000fcb0
	virtual void Equals(float (*p_data)[4]) { memcpy(m_data, p_data, sizeof(float) * 4 * 4); } // vtable+0x04

	// FUNCTION: LEGO1 0x10002340
	// FUNCTION: BETA10 0x1000fcf0
	virtual void Equals(const Matrix4& p_matrix)
	{
		memcpy(m_data, p_matrix.m_data, sizeof(float) * 4 * 4);
	} // vtable+0x00

	// FUNCTION: LEGO1 0x10002360
	// FUNCTION: BETA10 0x1000fd30
	virtual void SetData(float (*p_data)[4]) { m_data = p_data; } // vtable+0x0c

	// FUNCTION: LEGO1 0x10002370
	// FUNCTION: BETA10 0x1000fd60
	virtual void SetData(UnknownMatrixType& p_matrix) { m_data = p_matrix.m_data; } // vtable+0x08

	// FUNCTION: LEGO1 0x10002380
	// FUNCTION: BETA10 0x1000fd90
	virtual float (*GetData())[4] { return m_data; } // vtable+0x14

	// FUNCTION: LEGO1 0x10002390
	// FUNCTION: BETA10 0x1000fdc0
	virtual float (*GetData() const)[4] { return m_data; } // vtable+0x10

	// FUNCTION: LEGO1 0x100023a0
	// FUNCTION: BETA10 0x1000fdf0
	virtual float* Element(int p_row, int p_col) { return &m_data[p_row][p_col]; } // vtable+0x1c

	// FUNCTION: LEGO1 0x100023c0
	// FUNCTION: BETA10 0x1000fe30
	virtual const float* Element(int p_row, int p_col) const { return &m_data[p_row][p_col]; } // vtable+0x18

	// FUNCTION: LEGO1 0x100023e0
	// FUNCTION: BETA10 0x1000fe70
	virtual void Clear() { memset(m_data, 0, 16 * sizeof(float)); } // vtable+0x20

	// FUNCTION: LEGO1 0x100023f0
	// FUNCTION: BETA10 0x1000feb0
	virtual void SetIdentity()
	{
		Clear();
		m_data[0][0] = 1.0f;
		m_data[1][1] = 1.0f;
		m_data[2][2] = 1.0f;
		m_data[3][3] = 1.0f;
	} // vtable+0x24

	// FUNCTION: LEGO1 0x10002420
	// FUNCTION: BETA10 0x1000ff20
	virtual void operator=(const Matrix4& p_matrix) { Equals(p_matrix); } // vtable+0x28

	// FUNCTION: LEGO1 0x10002430
	// FUNCTION: BETA10 0x1000ff50
	virtual Matrix4& operator+=(float (*p_data)[4])
	{
		for (int i = 0; i < 16; i++) {
			((float*) m_data)[i] += ((float*) p_data)[i];
		}
		return *this;
	} // vtable+0x2c

	// FUNCTION: LEGO1 0x10002460
	// FUNCTION: BETA10 0x1000ffc0
	virtual void TranslateBy(const float& p_x, const float& p_y, const float& p_z)
	{
		m_data[3][0] += p_x;
		m_data[3][1] += p_y;
		m_data[3][2] += p_z;
	} // vtable+0x30

	// FUNCTION: LEGO1 0x100024a0
	// FUNCTION: BETA10 0x10010040
	virtual void SetTranslation(const float& p_x, const float& p_y, const float& p_z)
	{
		m_data[3][0] = p_x;
		m_data[3][1] = p_y;
		m_data[3][2] = p_z;
	} // vtable+0x34

	// FUNCTION: LEGO1 0x100024d0
	// FUNCTION: BETA10 0x100100a0
	virtual void Product(float (*p_a)[4], float (*p_b)[4])
	{
		float* cur = (float*) m_data;
		for (int row = 0; row < 4; row++) {
			for (int col = 0; col < 4; col++) {
				*cur = 0.0f;
				for (int k = 0; k < 4; k++) {
					*cur += p_a[row][k] * p_b[k][col];
				}
				cur++;
			}
		}
	} // vtable+0x3c

	// FUNCTION: LEGO1 0x10002530
	// FUNCTION: BETA10 0x10010180
	virtual void Product(const Matrix4& p_a, const Matrix4& p_b) { Product(p_a.m_data, p_b.m_data); } // vtable+0x38

	inline virtual void ToQuaternion(Vector3& p_resultQuat); // vtable+0x40
	inline virtual int FromQuaternion(const Vector3& p_vec); // vtable+0x44

	// FUNCTION: LEGO1 0x100a0ff0
	// FUNCTION: BETA10 0x1001fe60
	void Scale(const float& p_x, const float& p_y, const float& p_z)
	{
		for (int i = 0; i < 4; i++) {
			m_data[i][0] *= p_x;
			m_data[i][1] *= p_y;
			m_data[i][2] *= p_z;
		}
	}

	// FUNCTION: BETA10 0x1001c6a0
	void RotateX(const float& p_angle)
	{
		float s = sin(p_angle);
		float c = cos(p_angle);
		float matrix[4][4];
		memcpy(matrix, m_data, sizeof(float) * 16);
		for (int i = 0; i < 4; i++) {
			m_data[i][1] = matrix[i][1] * c - matrix[i][2] * s;
			m_data[i][2] = matrix[i][2] * c + matrix[i][1] * s;
		}
	}

	// FUNCTION: BETA10 0x1001fd60
	void RotateY(const float& p_angle)
	{
		float s = sin(p_angle);
		float c = cos(p_angle);
		float matrix[4][4];
		memcpy(matrix, m_data, sizeof(float) * 16);
		for (int i = 0; i < 4; i++) {
			m_data[i][0] = matrix[i][0] * c + matrix[i][2] * s;
			m_data[i][2] = matrix[i][2] * c - matrix[i][0] * s;
		}
	}

	// FUNCTION: BETA10 0x1006ab10
	void RotateZ(const float& p_angle)
	{
		float s = sin(p_angle);
		float c = cos(p_angle);
		float matrix[4][4];
		memcpy(matrix, m_data, sizeof(float) * 16);
		for (int i = 0; i < 4; i++) {
			m_data[i][0] = matrix[i][0] * c - matrix[i][1] * s;
			m_data[i][1] = matrix[i][1] * c + matrix[i][0] * s;
		}
	}

	inline int BETA_1005a590(Matrix4& p_mat);

	// FUNCTION: LEGO1 0x1006b500
	void Swap(int p_d1, int p_d2)
	{
		for (int i = 0; i < 4; i++) {
			float e = m_data[p_d1][i];
			m_data[p_d1][i] = m_data[p_d2][i];
			m_data[p_d2][i] = e;
		}
	}

	float* operator[](int idx) { return m_data[idx]; }
	const float* operator[](int idx) const { return m_data[idx]; }

protected:
	float (*m_data)[4];
};

// FUNCTION: LEGO1 0x10002550
// FUNCTION: BETA10 0x100101c0
inline void Matrix4::ToQuaternion(Vector3& p_outQuat)
{
	float trace;
	float localc = m_data[0][0] + m_data[1][1] + m_data[2][2];

	if (localc > 0) {
		trace = (float) sqrt(localc + 1.0);
		p_outQuat[3] = trace * 0.5f;
		trace = 0.5f / trace;
		p_outQuat[0] = (m_data[2][1] - m_data[1][2]) * trace;
		p_outQuat[1] = (m_data[0][2] - m_data[2][0]) * trace;
		p_outQuat[2] = (m_data[1][0] - m_data[0][1]) * trace;
	}
	else {
		// GLOBAL: LEGO1 0x100d4090
		static int rotateIndex[] = {1, 2, 0};

		// Largest element along the trace
		int largest = 0;
		if (m_data[0][0] < m_data[1][1]) {
			largest = 1;
		}
		if (*Element(largest, largest) < m_data[2][2]) {
			largest = 2;
		}

		int next = rotateIndex[largest];
		int nextNext = rotateIndex[next];

		trace = (float) sqrt(*Element(largest, largest) - (*Element(nextNext, nextNext) + *Element(next, next)) + 1.0);

		p_outQuat[largest] = trace * 0.5f;
		trace = 0.5f / trace;

		p_outQuat[3] = (*Element(nextNext, next) - *Element(next, nextNext)) * trace;
		p_outQuat[next] = (*Element(largest, next) + *Element(next, largest)) * trace;
		p_outQuat[nextNext] = (*Element(largest, nextNext) + *Element(nextNext, largest)) * trace;
	}
}

// FUNCTION: LEGO1 0x10002710
// FUNCTION: BETA10 0x10010550
inline int Matrix4::FromQuaternion(const Vector3& p_vec)
{
	float local14 = p_vec.LenSquared();

	if (local14 > 0.0f) {
		local14 = 2.0f / local14;

		float local24 = p_vec[0] * local14;
		float local34 = p_vec[1] * local14;
		float local10 = p_vec[2] * local14;

		float local28 = p_vec[3] * local24;
		float local2c = p_vec[3] * local34;
		float local30 = p_vec[3] * local10;

		float local38 = p_vec[0] * local24;
		float local8 = p_vec[0] * local34;
		float localc = p_vec[0] * local10;

		float local18 = p_vec[1] * local34;
		float local1c = p_vec[1] * local10;
		float local20 = p_vec[2] * local10;

		m_data[0][0] = 1.0f - (local18 + local20);
		m_data[1][0] = local8 + local30;
		m_data[2][0] = localc - local2c;

		m_data[0][1] = local8 - local30;
		m_data[1][1] = 1.0f - (local38 + local20);
		m_data[2][1] = local1c + local28;

		m_data[0][2] = local2c + localc;
		m_data[1][2] = local1c - local28;
		m_data[2][2] = 1.0f - (local18 + local38);

		m_data[3][0] = 0.0f;
		m_data[3][1] = 0.0f;
		m_data[3][2] = 0.0f;
		m_data[3][3] = 1.0f;

		m_data[0][3] = 0.0f;
		m_data[1][3] = 0.0f;
		m_data[2][3] = 0.0f;
		return 0;
	}
	else {
		return -1;
	}
}

// VTABLE: LEGO1 0x100d4300
// VTABLE: BETA10 0x101b82e0
// SIZE 0x48
class MxMatrix : public Matrix4 {
public:
	// FUNCTION: LEGO1 0x1006b120
	// FUNCTION: BETA10 0x10015370
	MxMatrix() : Matrix4(m_elements) {}

	// FUNCTION: LEGO1 0x10032770
	// FUNCTION: BETA10 0x1001ff30
	MxMatrix(const MxMatrix& p_matrix) : Matrix4(m_elements) { Equals(p_matrix); }

	// FUNCTION: BETA10 0x1000fc20
	MxMatrix(const Matrix4& p_matrix) : Matrix4(m_elements) { Equals(p_matrix); }

	// FUNCTION: BETA10 0x10010860
	float* operator[](int idx) { return m_data[idx]; }

	// FUNCTION: BETA10 0x1001c670
	const float* operator[](int idx) const { return m_data[idx]; }

	// FUNCTION: LEGO1 0x10002850
	void operator=(const Matrix4& p_matrix) override { Equals(p_matrix); } // vtable+0x28

	// FUNCTION: LEGO1 0x10002860
	virtual void operator=(const MxMatrix& p_matrix) { Equals(p_matrix); } // vtable+0x48

private:
	float m_elements[4][4]; // 0x08
};

// FUNCTION: LEGO1 0x10002870
void Vector4::AddImpl(const float* p_value)
{
	m_data[0] += p_value[0];
	m_data[1] += p_value[1];
	m_data[2] += p_value[2];
	m_data[3] += p_value[3];
}

// FUNCTION: LEGO1 0x100028b0
void Vector4::AddImpl(float p_value)
{
	m_data[0] += p_value;
	m_data[1] += p_value;
	m_data[2] += p_value;
	m_data[3] += p_value;
}

// FUNCTION: LEGO1 0x100028f0
void Vector4::SubImpl(const float* p_value)
{
	m_data[0] -= p_value[0];
	m_data[1] -= p_value[1];
	m_data[2] -= p_value[2];
	m_data[3] -= p_value[3];
}

// FUNCTION: LEGO1 0x10002930
void Vector4::MulImpl(const float* p_value)
{
	m_data[0] *= p_value[0];
	m_data[1] *= p_value[1];
	m_data[2] *= p_value[2];
	m_data[3] *= p_value[3];
}

// FUNCTION: LEGO1 0x10002970
void Vector4::MulImpl(const float& p_value)
{
	m_data[0] *= p_value;
	m_data[1] *= p_value;
	m_data[2] *= p_value;
	m_data[3] *= p_value;
}

// FUNCTION: LEGO1 0x100029b0
void Vector4::DivImpl(const float& p_value)
{
	m_data[0] /= p_value;
	m_data[1] /= p_value;
	m_data[2] /= p_value;
	m_data[3] /= p_value;
}

// FUNCTION: LEGO1 0x100029f0
float Vector4::DotImpl(const float* p_a, const float* p_b) const
{
	return p_a[0] * p_b[0] + p_a[2] * p_b[2] + (p_a[1] * p_b[1] + p_a[3] * p_b[3]);
}

// FUNCTION: LEGO1 0x10002a20
void Vector4::EqualsImpl(const float* p_data)
{
	memcpy(m_data, p_data, sizeof(float) * 4);
}

// FUNCTION: LEGO1 0x10002a40
void Vector4::SetMatrixProduct(const float* p_vec, const float* p_mat)
{
	m_data[0] = p_vec[0] * p_mat[0] + p_vec[1] * p_mat[4] + p_vec[2] * p_mat[8] + p_vec[3] * p_mat[12];
	m_data[1] = p_vec[0] * p_mat[1] + p_vec[1] * p_mat[5] + p_vec[2] * p_mat[9] + p_vec[4] * p_mat[13];
	m_data[2] = p_vec[0] * p_mat[2] + p_vec[1] * p_mat[6] + p_vec[2] * p_mat[10] + p_vec[4] * p_mat[14];
	m_data[3] = p_vec[0] * p_mat[3] + p_vec[1] * p_mat[7] + p_vec[2] * p_mat[11] + p_vec[4] * p_mat[15];
}

// FUNCTION: LEGO1 0x10002ae0
void Vector4::SetMatrixProduct(const Vector4& p_a, const float* p_b)
{
	SetMatrixProduct(p_a.m_data, p_b);
}

// FUNCTION: LEGO1 0x10002b00
void Vector4::Clear()
{
	memset(m_data, 0, sizeof(float) * 4);
}

// FUNCTION: LEGO1 0x10002b20
float Vector4::LenSquared() const
{
	return m_data[1] * m_data[1] + m_data[0] * m_data[0] + m_data[2] * m_data[2] + m_data[3] * m_data[3];
}

// FUNCTION: LEGO1 0x10002b40
void Vector4::Fill(const float& p_value)
{
	m_data[0] = p_value;
	m_data[1] = p_value;
	m_data[2] = p_value;
	m_data[3] = p_value;
}

// FUNCTION: BETA10 0x1005a590
inline int Matrix4::BETA_1005a590(Matrix4& p_mat)
{
	float local5c[4][4];
	Matrix4 localc(local5c);

	((Matrix4&) localc) = *this;
	p_mat.SetIdentity();

	for (int i = 0; i < 4; i++) {
		int local1c = i;
		int local10;

		for (local10 = i + 1; local10 < 4; local10++) {
			if (fabs(localc[local1c][i]) < fabs(localc[local10][i])) {
				local1c = local10;
			}
		}

		if (local1c != i) {
			localc.Swap(local1c, i);
			p_mat.Swap(local1c, i);
		}

		if (localc[i][i] < 0.001f && localc[i][i] > -0.001f) {
			return -1;
		}

		float local60 = localc[i][i];
		int local18;

		for (local18 = 0; local18 < 4; local18++) {
			p_mat[i][local18] /= local60;
		}

		for (local18 = 0; local18 < 4; local18++) {
			localc[i][local18] /= local60;
		}

		for (local10 = 0; local10 < 4; local10++) {
			if (i != local10) {
				float afStack70[4];

				for (local18 = 0; local18 < 4; local18++) {
					afStack70[local18] = p_mat[i][local18] * localc[local10][i];
				}

				for (local18 = 0; local18 < 4; local18++) {
					p_mat[local10][local18] -= afStack70[local18];
				}

				for (local18 = 0; local18 < 4; local18++) {
					afStack70[local18] = localc[i][local18] * localc[local10][i];
				}

				for (local18 = 0; local18 < 4; local18++) {
					localc[local10][local18] -= afStack70[local18];
				}
			}
		}
	}

	return 0;
}

// FUNCTION: LEGO1 0x10002b70
// FUNCTION: BETA10 0x10048ad0
inline int Vector4::NormalizeQuaternion()
{
	float length = m_data[0] * m_data[0] + m_data[1] * m_data[1] + m_data[2] * m_data[2];

	if (length > 0.0f) {
		float theta = m_data[3] * 0.5f;
		float magnitude = sin((double) theta);
		m_data[3] = cos((double) theta);

		magnitude = magnitude / (float) sqrt((double) length);
		m_data[0] *= magnitude;
		m_data[1] *= magnitude;
		m_data[2] *= magnitude;
		return 0;
	}
	else {
		return -1;
	}
}

// FUNCTION: LEGO1 0x10002bf0
// FUNCTION: BETA10 0x10048c20
inline int Vector4::EqualsHamiltonProduct(const Vector4& p_a, const Vector4& p_b)
{
	m_data[3] = p_a.m_data[3] * p_b.m_data[3] -
				(p_a.m_data[0] * p_b.m_data[0] + p_a.m_data[2] * p_b.m_data[2] + p_a.m_data[1] * p_b.m_data[1]);

	Vector3::EqualsCrossImpl(p_a.m_data, p_b.m_data);

	m_data[0] = p_b.m_data[3] * p_a.m_data[0] + p_a.m_data[3] * p_b.m_data[0] + m_data[0];
	m_data[1] = p_b.m_data[1] * p_a.m_data[3] + p_a.m_data[1] * p_b.m_data[3] + m_data[1];
	m_data[2] = p_b.m_data[2] * p_a.m_data[3] + p_a.m_data[2] * p_b.m_data[3] + m_data[2];
	return 0;
}

#endif // VECTOR_H
