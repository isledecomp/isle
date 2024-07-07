#ifndef MXMATRIX_H
#define MXMATRIX_H

#include "realtime/matrix.h"

// VTABLE: LEGO1 0x100d4300
// VTABLE: BETA10 0x101b82e0
// SIZE 0x48
class MxMatrix : public Matrix4 {
public:
	// FUNCTION: LEGO1 0x1006b120
	MxMatrix() : Matrix4(m_elements) {}

	// FUNCTION: LEGO1 0x10032770
	MxMatrix(const MxMatrix& p_matrix) : Matrix4(m_elements) { Equals(p_matrix); }

	MxMatrix(const Matrix4& p_matrix) : Matrix4(m_elements) { Equals(p_matrix); }

	float* operator[](int idx) { return m_data[idx]; }
	const float* operator[](int idx) const { return m_data[idx]; }

	// FUNCTION: LEGO1 0x10002850
	void operator=(const Matrix4& p_matrix) override { Equals(p_matrix); } // vtable+0x28

	// FUNCTION: LEGO1 0x10002860
	virtual void operator=(const MxMatrix& p_matrix) { Equals(p_matrix); } // vtable+0x48

private:
	float m_elements[4][4]; // 0x08
};

#endif // MXMATRIX_H
