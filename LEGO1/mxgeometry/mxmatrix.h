#ifndef MXMATRIX_H
#define MXMATRIX_H

#include "realtime/matrix.h"

// VTABLE: LEGO1 0x100d4300
// SIZE 0x48
class MxMatrix : public Matrix4 {
public:
	inline MxMatrix() : Matrix4(m_elements) {}
	inline MxMatrix(const MxMatrix& p_matrix) : Matrix4(m_elements) { Equals(p_matrix); }

	// No idea why there's another equals. Maybe to some other type like the
	// DirectX Retained Mode Matrix type which is also a float* alias?
	// FUNCTION: LEGO1 0x10002860
	virtual void operator=(const MxMatrix& p_matrix) { Equals(p_matrix); } // vtable+0x48

private:
	float m_elements[4][4];
};

#endif // MXMATRIX_H
