#ifndef MXMATRIX_H
#define MXMATRIX_H

#include "realtime/matrix.h"

// VTABLE: LEGO1 0x100d4300
// SIZE 0x48
class MxMatrix : public Matrix4 {
public:
	// FUNCTION: LEGO1 0x1006b120
	inline MxMatrix() : Matrix4(m_elements) {}

	// FUNCTION: LEGO1 0x10032770
	inline MxMatrix(const MxMatrix& p_matrix) : Matrix4(m_elements) { Equals(p_matrix); }

	inline MxMatrix(const Matrix4& p_matrix) : Matrix4(m_elements) { Equals(p_matrix); }

	float* operator[](int idx) { return m_data[idx]; }
	const float* operator[](int idx) const { return m_data[idx]; }

	inline void SetX(float p_x) { m_data[3][0] = p_x; }
	inline void SetY(float p_y) { m_data[3][1] = p_y; }
	inline void SetZ(float p_z) { m_data[3][2] = p_z; }

	// FUNCTION: LEGO1 0x10002850
	void operator=(const Matrix4& p_matrix) override { Equals(p_matrix); } // vtable+0x28

	// No idea why there's another equals. Maybe to some other type like the
	// DirectX Retained Mode Matrix type which is also a float* alias?
	// FUNCTION: LEGO1 0x10002860
	virtual void operator=(const MxMatrix& p_matrix) { Equals(p_matrix); } // vtable+0x48

private:
	float m_elements[4][4]; // 0x08
};

#endif // MXMATRIX_H
