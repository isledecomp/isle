#ifndef MATRIX_H
#define MATRIX_H

#include "vector.h"

#include <math.h>
#include <memory.h>

// Note: virtual function overloads appear in the virtual table
// in reverse order of appearance.

struct UnknownMatrixType {
	float m_data[4][4];
};

// VTABLE: LEGO1 0x100d4350
// VTABLE: BETA10 0x101b8340
// SIZE 0x08
class Matrix4 {
protected:
	float (*m_data)[4];

public:
	// FUNCTION: LEGO1 0x10004500
	// FUNCTION: BETA10 0x1000fc70
	Matrix4(float (*p_data)[4]) { SetData(p_data); }

	// FUNCTION: LEGO1 0x10002320
	// FUNCTION: BETA10 0x1000fcb0
	virtual void CopyFrom(float (*p_data)[4])
	{
		memcpy(m_data, p_data, sizeof(float) * 4 * 4);
	}                                         // vtable+0x04
	// FUNCTION: LEGO1 0x10002340
	// FUNCTION: BETA10 0x1000fcf0
	virtual void CopyFrom(const Matrix4& p_matrix)
	{
		memcpy(m_data, p_matrix.m_data, sizeof(float) * 4 * 4);
	}                                    // vtable+0x00
	// FUNCTION: LEGO1 0x10002360
	// FUNCTION: BETA10 0x1000fd30
	virtual void SetData(float (*p_data)[4])
	{
		m_data = p_data;
	}                                          // vtable+0x0c
	// FUNCTION: LEGO1 0x10002370
	// FUNCTION: BETA10 0x1000fd60
	virtual void SetData(UnknownMatrixType& p_matrix)
	{
		m_data = p_matrix.m_data;
	}                                 // vtable+0x08
	// FUNCTION: LEGO1 0x10002380
	// FUNCTION: BETA10 0x1000fd90
	virtual float (*GetData())[4]
	{
		return m_data;
	}                                                     // vtable+0x14
	// FUNCTION: LEGO1 0x10002390
	// FUNCTION: BETA10 0x1000fdc0
	virtual float (*GetData() const)[4]
	{
		return m_data;
	}                                               // vtable+0x10
	// FUNCTION: LEGO1 0x100023a0
	// FUNCTION: BETA10 0x1000fdf0
	virtual float* Element(int p_row, int p_col)
	{
		return &m_data[p_row][p_col];
	}                                      // vtable+0x1c
	// FUNCTION: LEGO1 0x100023c0
	// FUNCTION: BETA10 0x1000fe30
	virtual const float* Element(int p_row, int p_col) const
	{
		return &m_data[p_row][p_col];
	}                          // vtable+0x18
	// FUNCTION: LEGO1 0x100023e0
	// FUNCTION: BETA10 0x1000fe70
	virtual void Clear()
	{
		memset(m_data, 0, 16 * sizeof(float));
	}                                                              // vtable+0x20
	// FUNCTION: LEGO1 0x100023f0
	// FUNCTION: BETA10 0x1000feb0
	virtual void SetIdentity()
	{
		Clear();
		m_data[0][0] = 1.0f;
		m_data[1][1] = 1.0f;
		m_data[2][2] = 1.0f;
		m_data[3][3] = 1.0f;
	}                                                        // vtable+0x24
	// FUNCTION: LEGO1 0x10002420
	// FUNCTION: BETA10 0x1000ff20
	virtual void operator=(const Matrix4& p_matrix)
	{
		CopyFrom(p_matrix);
	}                                   // vtable+0x28
	// FUNCTION: LEGO1 0x10002430
	// FUNCTION: BETA10 0x1000ff50
	virtual Matrix4& operator+=(float (*p_data)[4])
	{
		for (int i = 0; i < 16; i++) {
			((float*) m_data)[i] += ((float*) p_data)[i];
		}

		return *this;
	}                                   // vtable+0x2c
	// FUNCTION: LEGO1 0x10002460
	// FUNCTION: BETA10 0x1000ffc0
	virtual void TranslateBy(const float& p_x, const float& p_y, const float& p_z)
	{
		m_data[3][0] += p_x;
		m_data[3][1] += p_y;
		m_data[3][2] += p_z;
	}    // vtable+0x30
	inline virtual void SetTranslation(const float& p_x, const float& p_y, const float& p_z); // vtable+0x34
	inline virtual void Product(float (*p_a)[4], float (*p_b)[4]);                            // vtable+0x3c
	inline virtual void Product(const Matrix4& p_a, const Matrix4& p_b);                      // vtable+0x38
	inline virtual void ToQuaternion(Vector4& p_resultQuat);                                  // vtable+0x40
	inline virtual int FromQuaternion(const Vector4& p_vec);                                  // vtable+0x44

	inline void Scale(const float& p_x, const float& p_y, const float& p_z);
	inline void RotateX(const float& p_angle);
	inline void RotateY(const float& p_angle);
	inline void RotateZ(const float& p_angle);
	inline int Invert(Matrix4& p_mat);
	inline void Swap(int p_d1, int p_d2);

	// FUNCTION: BETA10 0x1001c670
	float* operator[](int idx) { return m_data[idx]; }

	// FUNCTION: BETA10 0x10017780
	const float* operator[](int idx) const { return m_data[idx]; }
};

#ifdef COMPAT_MODE
#include "matrix4d.inl.h"
#endif

#endif // MATRIX_H
