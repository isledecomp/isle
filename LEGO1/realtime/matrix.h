#ifndef MATRIX_H
#define MATRIX_H

#include "vector.h"

#include <memory.h>

struct UnknownMatrixType {
	float m_data[4][4];
};

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
	virtual void TranslateBy(const float* p_x, const float* p_y, const float* p_z)
	{
		m_data[3][0] += *p_x;
		m_data[3][1] += *p_y;
		m_data[3][2] += *p_z;
	} // vtable+0x30

	// FUNCTION: LEGO1 0x100024a0
	virtual void SetTranslation(const float* p_x, const float* p_y, const float* p_z)
	{
		m_data[3][0] = *p_x;
		m_data[3][1] = *p_y;
		m_data[3][2] = *p_z;
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

	inline virtual void ToQuaternion(Vector4& p_resultQuat); // vtable+0x40
	inline virtual int FromQuaternion(const Vector4& p_vec); // vtable+0x44

	float* operator[](size_t idx) { return m_data[idx]; }
	const float* operator[](size_t idx) const { return m_data[idx]; }

protected:
	float (*m_data)[4];
};

// Not close, Ghidra struggles understinging this method so it will have to
// be manually worked out. Included since I at least figured out what it was
// doing with rotateIndex and what overall operation it's trying to do.
// STUB: LEGO1 0x10002550
inline void Matrix4::ToQuaternion(Vector4& p_outQuat)
{
	/*
	float trace = m_data[0] + m_data[5] + m_data[10];
	if (trace > 0) {
		trace = sqrt(trace + 1.0);
		p_outQuat->GetData()[3] = trace * 0.5f;
		p_outQuat->GetData()[0] = (m_data[9] - m_data[6]) * trace;
		p_outQuat->GetData()[1] = (m_data[2] - m_data[8]) * trace;
		p_outQuat->GetData()[2] = (m_data[4] - m_data[1]) * trace;
		return;
	}

	// ~GLOBAL: LEGO1 0x100d4090
	static int rotateIndex[] = {1, 2, 0};

	// Largest element along the trace
	int largest = m_data[0] < m_data[5];
	if (*Element(largest, largest) < m_data[10])
		largest = 2;

	int next = rotateIndex[largest];
	int nextNext = rotateIndex[next];
	float valueA = *Element(nextNext, nextNext);
	float valueB = *Element(next, next);
	float valueC = *Element(largest, largest);

	// Above is somewhat decomped, below is pure speculation since the automatic
	// decomp becomes very garbled.
	float traceValue = sqrt(valueA - valueB - valueC + 1.0);

	p_outQuat->GetData()[largest] = traceValue * 0.5f;
	traceValue = 0.5f / traceValue;

	p_outQuat->GetData()[3] = (m_data[next + 4 * nextNext] - m_data[nextNext + 4 * next]) * traceValue;
	p_outQuat->GetData()[next] = (m_data[next + 4 * largest] + m_data[largest + 4 * next]) * traceValue;
	p_outQuat->GetData()[nextNext] = (m_data[nextNext + 4 * largest] + m_data[largest + 4 * nextNext]) * traceValue;
	*/
}

// No idea what this function is doing and it will be hard to tell until
// we have a confirmed usage site.
// STUB: LEGO1 0x10002710
inline int Matrix4::FromQuaternion(const Vector4& p_vec)
{
	return -1;
}

#endif // MATRIX_H
