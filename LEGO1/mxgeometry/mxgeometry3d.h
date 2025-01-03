#ifndef MXGEOMETRY3D_H
#define MXGEOMETRY3D_H

#include "decomp.h"
#include "realtime/vector.h"
#include "realtime/vector2d.inl.h"
#include "realtime/vector3d.inl.h"

// VTABLE: LEGO1 0x100d4488
// VTABLE: BETA10 0x101b84d0
// SIZE 0x14
class Mx3DPointFloat : public Vector3 {
public:
	// FUNCTION: LEGO1 0x1001d170
	// FUNCTION: BETA10 0x10011990
	Mx3DPointFloat() : Vector3(m_elements) {}

	// FUNCTION: BETA10 0x10011870
	Mx3DPointFloat(float p_x, float p_y, float p_z) : Vector3(m_elements)
	{
		m_elements[0] = p_x;
		m_elements[1] = p_y;
		m_elements[2] = p_z;
	}

	// FUNCTION: LEGO1 0x100343a0
	// FUNCTION: BETA10 0x10011600
	Mx3DPointFloat(const Mx3DPointFloat& p_other) : Vector3(m_elements) { EqualsImpl(p_other.m_data); }

	// FUNCTION: LEGO1 0x10048ed0
	// FUNCTION: BETA10 0x100151e0
	Mx3DPointFloat(const Vector3& p_other) : Vector3(m_elements) { EqualsImpl(p_other.m_data); }

	// FUNCTION: LEGO1 0x10003c10
	virtual void operator=(const Vector3& p_impl) { EqualsImpl(p_impl.m_data); } // vtable+0x88

	// FUNCTION: BETA10 0x10015240
	// ??4Mx3DPointFloat@@QAEAAV0@ABV0@@Z

	// FUNCTION: BETA10 0x10013460
	float& operator[](int idx) { return m_data[idx]; }

	// According to the PDB, BETA10 will not link this one if it is never used
	// const float& operator[](int idx) const { return m_data[idx]; }

	// only used by LegoUnknown100db7f4::FUN_1002ddc0() for some unknown reason
	// FUNCTION: BETA10 0x100373c0
	float& index_operator(int idx) { return m_data[idx]; }

	// SYNTHETIC: LEGO1 0x10010c00
	// ??4Mx3DPointFloat@@QAEAAV0@ABV0@@Z

private:
	float m_elements[3]; // 0x08
};

#endif // MXGEOMETRY3D_H
