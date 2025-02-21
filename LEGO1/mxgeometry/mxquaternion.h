#ifndef MXQUATERNION_H
#define MXQUATERNION_H

#include "mxgeometry4d.h"

// SIZE 0x34
class MxQuaternionTransformer {
public:
	enum {
		c_startSet = 0x01,
		c_endSet = 0x02
	};

	MxQuaternionTransformer() : m_flags(0) {}

	inline long NormalizeDirection();
	inline void SetStartEnd(Matrix4& p_m1, Matrix4& p_m2);
	inline void SetStart(Matrix4& p_m);
	inline void SetEnd(Matrix4& p_m);
	inline void SetStart(Vector4& p_v);
	inline void SetEnd(Vector4& p_v);
	inline int InterpolateToMatrix(Matrix4& p_matrix, float p_f);

	void GetQuat(Vector4& p_startQuat, Vector4& p_endQuat) const
	{
		p_startQuat = m_startQuat;
		p_endQuat = m_endQuat;
	}

	undefined4 GetFlags() const { return m_flags; }

private:
	inline int Interpolate(Vector4& p_v, float p_f);

	Mx4DPointFloat m_startQuat; // 0x00
	Mx4DPointFloat m_endQuat;   // 0x18
	MxU32 m_flags;              // 0x30
};

// FUNCTION: LEGO1 0x10004520
long MxQuaternionTransformer::NormalizeDirection()
{
	if (!m_flags) {
		return -1;
	}

	Mx4DPointFloat v1;
	Mx4DPointFloat v2;

	v1 = m_startQuat;
	v1 += m_endQuat;

	v2 = m_startQuat;
	v2 -= m_endQuat;

	if (v1.Dot(v1, v1) < v2.Dot(v2, v2)) {
		m_endQuat *= -1.0f;
	}

	return 0;
}

// FUNCTION: BETA10 0x1004a9b0
void MxQuaternionTransformer::SetStartEnd(Matrix4& p_m1, Matrix4& p_m2)
{
	SetStart(p_m1);
	SetEnd(p_m2);
}

// FUNCTION: BETA10 0x1004a9f0
void MxQuaternionTransformer::SetStart(Matrix4& p_m)
{
	p_m.ToQuaternion(m_startQuat);
	m_flags |= c_startSet;
}

// FUNCTION: LEGO1 0x10004620
// FUNCTION: BETA10 0x1004aa30
void MxQuaternionTransformer::SetEnd(Matrix4& p_m)
{
	p_m.ToQuaternion(m_endQuat);
	m_flags |= c_endSet;
}

// FUNCTION: BETA10 0x10180b80
void MxQuaternionTransformer::SetStart(Vector4& p_v)
{
	m_startQuat = p_v;
	m_flags |= c_startSet;
}

// FUNCTION: BETA10 0x10180bc0
void MxQuaternionTransformer::SetEnd(Vector4& p_v)
{
	m_endQuat = p_v;
	m_flags |= c_endSet;
}

// FUNCTION: BETA10 0x1004aaa0
int MxQuaternionTransformer::InterpolateToMatrix(Matrix4& p_matrix, float p_f)
{
	float data[4];
	Vector4 v(data);

	if (Interpolate(v, p_f) == 0) {
		return p_matrix.FromQuaternion(v);
	}

	return -1;
}

// FUNCTION: LEGO1 0x100040a0
// FUNCTION: BETA10 0x1004ab10
int MxQuaternionTransformer::Interpolate(Vector4& p_v, float p_f)
{
	if (m_flags == c_startSet) {
		p_v = m_startQuat;
		p_v[3] = (float) ((1.0 - p_f) * acos((double) p_v[3]) * 2.0);
		return p_v.NormalizeQuaternion();
	}

	if (m_flags == c_endSet) {
		p_v = m_endQuat;
		p_v[3] = (float) (p_f * acos((double) p_v[3]) * 2.0);
		return p_v.NormalizeQuaternion();
	}

	if (m_flags == (c_startSet | c_endSet)) {
		int i;
		double d1 = p_v.Dot(m_startQuat, m_endQuat);
		double a;
		double b;

		if (d1 + 1.0 > 0.00001) {
			if (1.0 - d1 > 0.00001) {
				double d2 = acos(d1);
				double denominator = sin(d2);
				a = sin((1.0 - p_f) * d2) / denominator;
				b = sin(p_f * d2) / denominator;
			}
			else {
				a = 1.0 - p_f;
				b = p_f;
			}

			for (i = 0; i < 4; i++) {
				p_v[i] = (float) (m_startQuat[i] * a + m_endQuat[i] * b);
			}
		}
		else {
			p_v[0] = -m_startQuat[1];
			p_v[1] = m_startQuat[0];
			p_v[2] = -m_startQuat[3];
			p_v[3] = m_startQuat[2];
			a = sin((1.0 - p_f) * 1.570796326794895);
			b = sin(p_f * 1.570796326794895);

			for (i = 0; i < 3; i++) {
				p_v[i] = (float) (m_startQuat[i] * a + p_v[i] * b);
			}
		}

		return 0;
	}

	return -1;
}

#endif // MXQUATERNION_H
