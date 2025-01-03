#ifndef MXGEOMETRY4D_H
#define MXGEOMETRY4D_H

#include "decomp.h"
#include "realtime/matrix.h"
#include "realtime/matrix4d.h"
#include "realtime/vector4d.h"

// VTABLE: LEGO1 0x100d41e8
// VTABLE: BETA10 0x101bab78
// SIZE 0x18
class Mx4DPointFloat : public Vector4 {
public:
	// FUNCTION: LEGO1 0x10048290
	// FUNCTION: BETA10 0x100484c0
	Mx4DPointFloat() : Vector4(m_elements) {}

	// FUNCTION: BETA10 0x10073bb0
	Mx4DPointFloat(float p_x, float p_y, float p_z, float p_a) : Vector4(m_elements)
	{
		m_elements[0] = p_x;
		m_elements[1] = p_y;
		m_elements[2] = p_z;
		m_elements[3] = p_a;
	}

	Mx4DPointFloat(const Mx4DPointFloat& p_other) : Vector4(m_elements) { EqualsImpl(p_other.m_data); }

	// FUNCTION: LEGO1 0x10003200
	virtual void operator=(const Vector4& p_impl) { EqualsImpl(p_impl.m_data); } // vtable+0x98

	// FUNCTION: BETA10 0x1004af10
	float& operator[](int idx) { return m_data[idx]; }

	// According to the PDB, BETA10 will not link this one if it is never used
	// const float& operator[](int idx) const { return m_data[idx]; }

	// only used by a couple of BETA10 functions for some unknown reason
	// FUNCTION: BETA10 0x1001c950
	float& index_operator(int idx) { return m_data[idx]; }

	// SYNTHETIC: LEGO1 0x10064b20
	// SYNTHETIC: BETA10 0x10070420
	// ??4Mx4DPointFloat@@QAEAAV0@ABV0@@Z

private:
	float m_elements[4]; // 0x08
};

#endif // MXGEOMETRY4D_H
