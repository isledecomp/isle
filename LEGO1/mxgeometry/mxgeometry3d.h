#ifndef MXGEOMETRY3D_H
#define MXGEOMETRY3D_H

#include "realtime/vector.h"

// VTABLE: LEGO1 0x100d4488
// SIZE 0x14
class Mx3DPointFloat : public Vector3 {
public:
	inline Mx3DPointFloat() : Vector3(m_elements) {}
	inline Mx3DPointFloat(float p_x, float p_y, float p_z) : Vector3(m_elements)
	{
		m_elements[0] = p_x;
		m_elements[1] = p_y;
		m_elements[2] = p_z;
	}

	// FUNCTION: LEGO1 0x100343a0
	inline Mx3DPointFloat(const Mx3DPointFloat& p_other) : Vector3(m_elements) { EqualsImpl(p_other.m_data); }

	// SYNTHETIC: LEGO1 0x1001d170
	// Mx3DPointFloat::Mx3DPointFloat

	// FUNCTION: LEGO1 0x10003c10
	virtual void operator=(const Vector3& p_impl) { EqualsImpl(p_impl.m_data); } // vtable+0x88

	inline void CopyFrom(const Mx3DPointFloat& p_other)
	{
		// ALPHA: 0x10010860, multiple indirections to this call
		EqualsImpl(p_other.m_data);

		float* dest = m_elements;
		const float* src = p_other.m_elements;
		for (size_t i = sizeof(m_elements) / sizeof(float); i > 0; --i) {
			*dest++ = *src++;
		}
	}

	inline void EqualsCross(Mx3DPointFloat& p_a, Mx3DPointFloat& p_b) { EqualsCrossImpl(p_a.m_data, p_b.m_data); }

private:
	float m_elements[3];
};

// VTABLE: LEGO1 0x100d41e8
// SIZE 0x18
class Mx4DPointFloat : public Vector4 {
public:
	inline Mx4DPointFloat() : Vector4(m_elements) {}

private:
	float m_elements[4];
};

#endif // MXGEOMETRY3D_H
