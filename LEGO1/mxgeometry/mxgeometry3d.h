#ifndef MXGEOMETRY3D_H
#define MXGEOMETRY3D_H

#include "decomp.h"
#include "realtime/matrix.h"
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

	inline Mx3DPointFloat(const Vector3& p_other) : Vector3(m_elements) { EqualsImpl(p_other.m_data); }

	// SYNTHETIC: LEGO1 0x1001d170
	// Mx3DPointFloat::Mx3DPointFloat

	// FUNCTION: LEGO1 0x10003c10
	virtual void operator=(const Vector3& p_impl) { EqualsImpl(p_impl.m_data); } // vtable+0x88

	inline float GetX() { return m_data[0]; }
	inline float GetY() { return m_data[1]; }
	inline float GetZ() { return m_data[2]; }

	inline float& operator[](int idx) { return m_data[idx]; }
	inline const float& operator[](int idx) const { return m_data[idx]; }

	// SYNTHETIC: LEGO1 0x10010c00
	// Mx3DPointFloat::operator=

private:
	float m_elements[3]; // 0x08
};

// VTABLE: LEGO1 0x100d41e8
// SIZE 0x18
class Mx4DPointFloat : public Vector4 {
public:
	inline Mx4DPointFloat() : Vector4(m_elements) {}
	inline Mx4DPointFloat(float p_x, float p_y, float p_z, float p_a) : Vector4(m_elements)
	{
		m_elements[0] = p_x;
		m_elements[1] = p_y;
		m_elements[2] = p_z;
		m_elements[3] = p_a;
	}

	// FUNCTION: LEGO1 0x10003200
	virtual void operator=(const Vector4& p_impl) { EqualsImpl(p_impl.m_data); } // vtable+0x98

	inline float& operator[](int idx) { return m_data[idx]; }
	inline const float& operator[](int idx) const { return m_data[idx]; }

private:
	float m_elements[4]; // 0x08
};

// SIZE 0x34
class UnknownMx4DPointFloat {
public:
	enum {
		c_bit1 = 0x01,
		c_bit2 = 0x02
	};

	UnknownMx4DPointFloat() : m_unk0x30(0) {}

	inline void Unknown1(Vector4& p_v)
	{
		m_unk0x00 = p_v;
		m_unk0x30 |= c_bit1;
	}

	inline void Unknown2(Vector4& p_v)
	{
		m_unk0x18 = p_v;
		m_unk0x30 |= c_bit2;
	}

	inline int Unknown_100040a0(Matrix4& p_matrix, float p_f);
	inline int FUN_100040a0(Vector4& p_v, float p_f);

private:
	Mx4DPointFloat m_unk0x00; // 0x00
	Mx4DPointFloat m_unk0x18; // 0x18
	undefined4 m_unk0x30;     // 0x30
};

int UnknownMx4DPointFloat::Unknown_100040a0(Matrix4& p_matrix, float p_f)
{
	float data[4];
	Vector4 v(data);

	if (FUN_100040a0(v, p_f) == 0) {
		return p_matrix.FromQuaternion(v);
	}
	else {
		return -1;
	}
}

// FUNCTION: LEGO1 0x100040a0
inline int UnknownMx4DPointFloat::FUN_100040a0(Vector4& p_v, float p_f)
{
	undefined4 state = m_unk0x30;

	if (state == 1) {
		p_v = m_unk0x00;
		p_v[3] = (1.0 - p_f) * acos(p_v[3]) * 2.0;
		return p_v.NormalizeQuaternion();
	}
	else if (state == 2) {
		p_v = m_unk0x18;
		p_v[3] = p_f * acos(p_v[3]) * 2.0;
		return p_v.NormalizeQuaternion();
	}
	else if (state == 3) {
		double d1 = p_v.Dot(&m_unk0x00, &m_unk0x18);
		double d2;

		if (d1 + 1.0 > 0.00001) {
			if (1.0 - d1 > 0.00001) {
				double d = acos(d1);
				sin(d);
				d1 = sin((1 - p_f) * d) / sin(d);
				d2 = sin(p_f * d) / sin(d);
			}
			else {
				d1 = 1.0 - p_f;
				d2 = p_f;
			}

			for (int i = 0; i < 4; i++) {
				p_v[i] = m_unk0x18[i] * d2 + m_unk0x00[i] * d1;
			}
		}
		else {
			p_v[0] = -m_unk0x00[1];
			p_v[1] = m_unk0x00[1];
			p_v[2] = -m_unk0x00[3];
			p_v[3] = m_unk0x00[2];
			d1 = sin((1.0 - p_f) * 1.570796326794895);
			d2 = sin(p_f * 1.570796326794895);

			for (int i = 0; i < 3; i++) {
				p_v[i] = m_unk0x00[i] * d1 + p_v[i] * d2;
			}
		}

		return 0;
	}
	else {
		return -1;
	}
}

#endif // MXGEOMETRY3D_H
