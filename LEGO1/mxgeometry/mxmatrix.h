#ifndef MXMATRIX_H
#define MXMATRIX_H

#include "realtime/matrix4d.inl.h"

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

	const float* operator[](int idx) const { return m_data[idx]; }

	// FUNCTION: LEGO1 0x10002850
	void operator=(const Matrix4& p_matrix) override { Equals(p_matrix); } // vtable+0x28

	// FUNCTION: LEGO1 0x10002860
	virtual void operator=(const MxMatrix& p_matrix) { Equals(p_matrix); } // vtable+0x48

private:
	float m_elements[4][4]; // 0x08
};

// Must be included here (not before MxMatrix) for correct ordering in binary.
// FromQuaternion and ToQuaternion in Matrix4 depend on Vector4.
// There's a chance they included mxgeometry4d.h after including this somewhere.
#include "realtime/vector4d.inl.h"

#endif // MXMATRIX_H
