#ifndef MATRIX_H
#define MATRIX_H

#include "vector.h"

/*
 * A simple array of four Vector4s that can be indexed into.
 */
class Matrix4 {
public:
	float rows[4][4]; // storage is public for easy access

	inline Matrix4() {}
	/*
	Matrix4(const Vector4& x_axis, const Vector4& y_axis, const Vector4& z_axis, const Vector4& position)
	{
		rows[0] = x_axis;
		rows[1] = y_axis;
		rows[2] = z_axis;
		rows[3] = position;
	}
	Matrix4(const float m[4][4])
	{
		rows[0] = m[0];
		rows[1] = m[1];
		rows[2] = m[2];
		rows[3] = m[3];
	}
	*/
	const float* operator[](long i) const { return rows[i]; }
	float* operator[](long i) { return rows[i]; }
};

// VTABLE: LEGO1 0x100d4350
// SIZE 0x8
class Matrix4Impl {
public:
	inline Matrix4Impl(Matrix4& p_data) { SetData(p_data); }

	// vtable + 0x00
	virtual void EqualsMatrixImpl(const Matrix4Impl* p_other);
	virtual void EqualsMatrixData(const Matrix4& p_matrix);
	// FUNCTION: LEGO1 0x10002370
	virtual void SetData(Matrix4& p_data) { m_data = &p_data; }
	virtual void AnotherSetData(Matrix4& p_data);

	// vtable + 0x10
	virtual Matrix4* GetData();
	virtual const Matrix4* GetData() const;
	virtual float* Element(int p_row, int p_col);
	virtual const float* Element(int p_row, int p_col) const;

	// vtable + 0x20
	virtual void Clear();
	virtual void SetIdentity();
	virtual void operator=(const Matrix4Impl& p_other);
	virtual Matrix4Impl* operator+=(const Matrix4& p_matrix);

	// vtable + 0x30
	virtual void TranslateBy(const float* p_x, const float* p_y, const float* p_z);
	virtual void SetTranslation(const float* p_x, const float* p_y, const float* p_z);
	virtual void EqualsMxProduct(const Matrix4Impl* p_a, const Matrix4Impl* p_b);
	virtual void EqualsDataProduct(const Matrix4& p_a, const Matrix4& p_b);

	// vtable + 0x40
	virtual void ToQuaternion(Vector4Impl* p_resultQuat);
	virtual int FromQuaternion(const Vector4Impl& p_vec);

	inline float& operator[](size_t idx) { return ((float*) m_data)[idx]; }

protected:
	// TODO: Currently unclear whether this class contains a Matrix4* or float*.
	Matrix4* m_data;
};

// VTABLE: LEGO1 0x100d4300
// SIZE 0x48
class Matrix4Data : public Matrix4Impl {
public:
	inline Matrix4Data() : Matrix4Impl(m_matrix) {}
	inline Matrix4Data(Matrix4Data& p_other) : Matrix4Impl(m_matrix) { m_matrix = *p_other.m_data; }
	inline Matrix4& GetMatrix() { return *m_data; }

	// No idea why there's another equals. Maybe to some other type like the
	// DirectX Retained Mode Matrix type which is also a float* alias?
	// vtable + 0x44
	virtual void operator=(const Matrix4Data& p_other);

	Matrix4 m_matrix;
};

#endif // MATRIX_H
