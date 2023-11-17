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

// VTABLE 0x100d4350
// SIZE 0x8
class MatrixImpl {
public:
	inline MatrixImpl(Matrix4& p_data) : m_data(&p_data) {}

	// vtable + 0x00
	virtual void EqualsMatrixImpl(const MatrixImpl* p_other);
	virtual void EqualsMatrixData(const Matrix4& p_matrix);
	virtual void SetData(Matrix4& p_data);
	virtual void AnotherSetData(Matrix4& p_data);

	// vtable + 0x10
	virtual Matrix4* GetData();
	virtual const Matrix4* GetData() const;
	virtual float* Element(int p_row, int p_col);
	virtual const float* Element(int p_row, int p_col) const;

	// vtable + 0x20
	virtual void Clear();
	virtual void SetIdentity();
	virtual void operator=(const MatrixImpl& p_other);
	virtual MatrixImpl* operator+=(const Matrix4& p_matrix);

	// vtable + 0x30
	virtual void TranslateBy(const float* p_x, const float* p_y, const float* p_z);
	virtual void SetTranslation(const float* p_x, const float* p_y, const float* p_z);
	virtual void EqualsMxProduct(const MatrixImpl* p_a, const MatrixImpl* p_b);
	virtual void EqualsDataProduct(const Matrix4& p_a, const Matrix4& p_b);

	// vtable + 0x40
	virtual void ToQuaternion(Vector4Impl* p_resultQuat);
	virtual int FUN_10002710(const Vector3Impl* p_vec);

	inline float& operator[](size_t idx) { return (*m_data)[idx >> 2][idx & 3]; }

protected:
	Matrix4* m_data;
};

// VTABLE 0x100d4300
// SIZE 0x48
class MatrixData : public MatrixImpl {
public:
	inline MatrixData() : MatrixImpl(m) {}
	inline MatrixData(MatrixData& p_other) : MatrixImpl(m) { m = *p_other.m_data; }
	inline Matrix4& GetMatrix() { return *m_data; }

	// No idea why there's another equals. Maybe to some other type like the
	// DirectX Retained Mode Matrix type which is also a float* alias?
	// vtable + 0x44
	virtual void operator=(const MatrixData& p_other);

	Matrix4 m;
};

#endif // MATRIX_H
