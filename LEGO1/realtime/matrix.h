#ifndef MATRIX_H
#define MATRIX_H

#include "vector.h"

#include <memory.h>

struct UnknownMatrixType {
	float m_data[4][4];
};

// Note: Many functions most likely take const references/pointers instead of non-const.
// The class needs to undergo a very careful refactoring to fix that (no matches should break).

// VTABLE: LEGO1 0x100d4350
// SIZE 0x08
class Matrix4 {
public:
	inline Matrix4(float (*p_data)[4]) { SetData(p_data); }

	// Note: virtual function overloads appear in the virtual table
	// in reverse order of appearance.

	// FUNCTION: LEGO1 0x10002320
	virtual void Equals(float (*p_data)[4]) { memcpy(m_data, p_data, sizeof(float) * 4 * 4); } // vtable+0x04

	// FUNCTION: LEGO1 0x10002340
	virtual void Equals(const Matrix4& p_matrix)
	{
		memcpy(m_data, p_matrix.m_data, sizeof(float) * 4 * 4);
	} // vtable+0x00

	// FUNCTION: LEGO1 0x10002360
	virtual void SetData(float (*p_data)[4]) { m_data = p_data; } // vtable+0x0c

	// FUNCTION: LEGO1 0x10002370
	virtual void SetData(UnknownMatrixType& p_matrix) { m_data = p_matrix.m_data; } // vtable+0x08

	// FUNCTION: LEGO1 0x10002380
	virtual float (*GetData())[4] { return m_data; } // vtable+0x14

	// FUNCTION: LEGO1 0x10002390
	virtual float (*GetData() const)[4] { return m_data; } // vtable+0x10

	// FUNCTION: LEGO1 0x100023a0
	virtual float* Element(int p_row, int p_col) { return &m_data[p_row][p_col]; } // vtable+0x1c

	// FUNCTION: LEGO1 0x100023c0
	virtual const float* Element(int p_row, int p_col) const { return &m_data[p_row][p_col]; } // vtable+0x18

	// FUNCTION: LEGO1 0x100023e0
	virtual void Clear() { memset(m_data, 0, 16 * sizeof(float)); } // vtable+0x20

	// FUNCTION: LEGO1 0x100023f0
	virtual void SetIdentity()
	{
		Clear();
		m_data[0][0] = 1.0f;
		m_data[1][1] = 1.0f;
		m_data[2][2] = 1.0f;
		m_data[3][3] = 1.0f;
	} // vtable+0x24

	// FUNCTION: LEGO1 0x10002420
	virtual void operator=(const Matrix4& p_matrix) { Equals(p_matrix); } // vtable+0x28

	// FUNCTION: LEGO1 0x10002430
	virtual Matrix4& operator+=(float (*p_data)[4])
	{
		for (int i = 0; i < 16; i++) {
			((float*) m_data)[i] += ((float*) p_data)[i];
		}
		return *this;
	} // vtable+0x2c

	// FUNCTION: LEGO1 0x10002460
	virtual void TranslateBy(const float& p_x, const float& p_y, const float& p_z)
	{
		m_data[3][0] += p_x;
		m_data[3][1] += p_y;
		m_data[3][2] += p_z;
	} // vtable+0x30

	// FUNCTION: LEGO1 0x100024a0
	virtual void SetTranslation(const float& p_x, const float& p_y, const float& p_z)
	{
		m_data[3][0] = p_x;
		m_data[3][1] = p_y;
		m_data[3][2] = p_z;
	} // vtable+0x34

	// FUNCTION: LEGO1 0x100024d0
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
	virtual void Product(const Matrix4& p_a, const Matrix4& p_b) { Product(p_a.m_data, p_b.m_data); } // vtable+0x38

	// FUNCTION: LEGO1 0x100a0ff0
	inline void Scale(const float& p_x, const float& p_y, const float& p_z)
	{
		for (int i = 0; i < 4; i++) {
			m_data[i][0] *= p_x;
			m_data[i][1] *= p_y;
			m_data[i][2] *= p_z;
		}
	}

	inline void RotateX(const float& p_angle)
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

	inline void RotateZ(const float& p_angle)
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

	inline virtual void ToQuaternion(Vector4& p_resultQuat); // vtable+0x40
	inline virtual int FromQuaternion(const Vector4& p_vec); // vtable+0x44

	float* operator[](int idx) { return m_data[idx]; }
	const float* operator[](int idx) const { return m_data[idx]; }

protected:
	float (*m_data)[4];
};

// FUNCTION: LEGO1 0x10002550
inline void Matrix4::ToQuaternion(Vector4& p_outQuat)
{
	float trace = m_data[0][0] + m_data[1][1] + m_data[2][2];
	if (trace > 0) {
		trace = sqrt(trace + 1.0);
		p_outQuat[3] = trace * 0.5f;
		trace = 0.5f / trace;
		p_outQuat[0] = (m_data[2][1] - m_data[1][2]) * trace;
		p_outQuat[1] = (m_data[0][2] - m_data[2][0]) * trace;
		p_outQuat[2] = (m_data[1][0] - m_data[0][1]) * trace;
		return;
	}

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

	trace = *Element(nextNext, nextNext);
	trace += *Element(next, next);
	trace = *Element(largest, largest) - trace;
	trace += 1.0f;
	trace = sqrt(trace);

	p_outQuat[largest] = trace * 0.5f;
	trace = 0.5f / trace;

	p_outQuat[3] = (*Element(nextNext, next) - *Element(next, nextNext)) * trace;
	p_outQuat[next] = (*Element(largest, next) + *Element(next, largest)) * trace;
	p_outQuat[nextNext] = (*Element(largest, nextNext) + *Element(nextNext, largest)) * trace;
}

// FUNCTION: LEGO1 0x10002710
inline int Matrix4::FromQuaternion(const Vector4& p_vec)
{
	float len = p_vec.LenSquared();

	if (len > 0.0f) {
		float v7 = 2.0f / len;

		float v9 = p_vec[0] * v7;
		float v11 = p_vec[1] * v7;
		float v12 = p_vec[2] * v7;

		float v13 = p_vec[3] * v9;
		float v14 = p_vec[3] * v11;
		float v16 = p_vec[3] * v12;

		float v17 = p_vec[0] * v9;
		float v22 = p_vec[0] * v11;
		float v23 = p_vec[0] * v12;

		float v18 = p_vec[1] * v11;
		float v24 = p_vec[1] * v12;
		float v19 = p_vec[2] * v12;

		m_data[0][0] = 1.0f - (v18 + v19);
		m_data[1][0] = v22 + v16;
		m_data[2][0] = v23 - v14;

		m_data[0][1] = v22 - v16;
		m_data[1][1] = 1.0f - (v17 + v19);
		m_data[2][1] = v24 + v13;

		m_data[0][2] = v14 + v23;
		m_data[1][2] = v24 - v13;
		m_data[2][2] = 1.0f - (v18 + v17);

		m_data[3][0] = 0;
		m_data[3][1] = 0;
		m_data[3][2] = 0;
		m_data[3][3] = 1.0f;

		m_data[0][3] = 0;
		m_data[1][3] = 0;
		m_data[2][3] = 0;
		return 0;
	}

	return -1;
}

#endif // MATRIX_H
