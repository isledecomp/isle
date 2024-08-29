#ifndef MXGEOMETRY3D_H
#define MXGEOMETRY3D_H

#include "decomp.h"
#include "realtime/matrix.h"
#include "realtime/vector.h"

// VTABLE: LEGO1 0x100d4488
// SIZE 0x14
class Mx3DPointFloat : public Vector3 {
public:
	Mx3DPointFloat() : Vector3(m_elements) {}
	Mx3DPointFloat(float p_x, float p_y, float p_z) : Vector3(m_elements)
	{
		m_elements[0] = p_x;
		m_elements[1] = p_y;
		m_elements[2] = p_z;
	}

	// FUNCTION: LEGO1 0x100343a0
	// FUNCTION: BETA10 0x10011600
	Mx3DPointFloat(const Mx3DPointFloat& p_other) : Vector3(m_elements) { EqualsImpl(p_other.m_data); }

	// FUNCTION: BETA10 0x100151e0
	Mx3DPointFloat(const Vector3& p_other) : Vector3(m_elements) { EqualsImpl(p_other.m_data); }

	// SYNTHETIC: LEGO1 0x1001d170
	// Mx3DPointFloat::Mx3DPointFloat

	// FUNCTION: LEGO1 0x10003c10
	virtual void operator=(const Vector3& p_impl) { EqualsImpl(p_impl.m_data); } // vtable+0x88

	float GetX() { return m_data[0]; }
	float GetY() { return m_data[1]; }
	float GetZ() { return m_data[2]; }

	float& operator[](int idx) { return m_data[idx]; }
	const float& operator[](int idx) const { return m_data[idx]; }

	// SYNTHETIC: LEGO1 0x10010c00
	// Mx3DPointFloat::operator=

private:
	float m_elements[3]; // 0x08
};

// VTABLE: LEGO1 0x100d41e8
// VTABLE: BETA10 0x101bab78
// SIZE 0x18
class Mx4DPointFloat : public Vector4 {
public:
	// FUNCTION: LEGO1 0x10048290
	Mx4DPointFloat() : Vector4(m_elements) {}

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

	const float& operator[](int idx) const { return m_data[idx]; }

	// SYNTHETIC: LEGO1 0x10064b20
	// Mx4DPointFloat::operator=

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

	// FUNCTION: BETA10 0x1004a9b0
	void Unknown1(Matrix4& p_m1, Matrix4& p_m2)
	{
		Unknown2(p_m1);
		Unknown3(p_m2);
	}

	// FUNCTION: BETA10 0x1004a9f0
	void Unknown2(Matrix4& p_m)
	{
		p_m.ToQuaternion(m_unk0x00);
		m_unk0x30 |= c_bit1;
	}

	// FUNCTION: BETA10 0x1004aa30
	void Unknown3(Matrix4& p_m)
	{
		p_m.ToQuaternion(m_unk0x18);
		m_unk0x30 |= c_bit2;
	}

	// FUNCTION: BETA10 0x10180b80
	void Unknown4(Vector4& p_v)
	{
		m_unk0x00 = p_v;
		m_unk0x30 |= c_bit1;
	}

	// FUNCTION: BETA10 0x10180bc0
	void Unknown5(Vector4& p_v)
	{
		m_unk0x18 = p_v;
		m_unk0x30 |= c_bit2;
	}

	inline int Unknown6(Matrix4& p_matrix, float p_f);
	inline void Unknown7();

private:
	inline int FUN_100040a0(Vector4& p_v, float p_f);

	Mx4DPointFloat m_unk0x00; // 0x00
	Mx4DPointFloat m_unk0x18; // 0x18
	undefined4 m_unk0x30;     // 0x30
};

// FUNCTION: BETA10 0x1004aaa0
int UnknownMx4DPointFloat::Unknown6(Matrix4& p_matrix, float p_f)
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

inline void UnknownMx4DPointFloat::Unknown7()
{
	if (m_unk0x30) {
		Mx4DPointFloat v1;
		Mx4DPointFloat v2;

		v1 = m_unk0x00;
		((Vector4&) v1).Add(m_unk0x18);

		v2 = m_unk0x00;
		((Vector4&) v2).Sub(m_unk0x18);

		if (v1.Dot(&v1, &v1) < v2.Dot(&v2, &v2)) {
			((Vector4&) m_unk0x18).Mul(-1.0f);
		}
	}
}

// FUNCTION: LEGO1 0x100040a0
// FUNCTION: BETA10 0x1004ab10
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
				double s = sin(d);
				d1 = sin((1.0 - p_f) * d) / s;
				d2 = sin(p_f * d) / s;
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
			p_v[1] = m_unk0x00[0];
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
