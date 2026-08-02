#ifndef VECTOR4D_H
#define VECTOR4D_H

#include "vector.h"

#include <math.h>
#include <memory.h>

// FUNCTION: LEGO1 0x10002870
// FUNCTION: BETA10 0x10048500
void Vector4::AddImpl(const float* p_value)
{
	Vector3::AddImpl(p_value);
	m_data[3] += p_value[3];
}

// FUNCTION: LEGO1 0x100028b0
// FUNCTION: BETA10 0x10048550
void Vector4::AddImpl(float p_value)
{
	m_data[0] += p_value;
	m_data[1] += p_value;
	m_data[2] += p_value;
	m_data[3] += p_value;
}

// FUNCTION: LEGO1 0x100028f0
// FUNCTION: BETA10 0x100485e0
void Vector4::SubImpl(const float* p_value)
{
	Vector3::SubImpl(p_value);
	m_data[3] -= p_value[3];
}

// FUNCTION: LEGO1 0x10002930
// FUNCTION: BETA10 0x10048630
void Vector4::MulImpl(const float* p_value)
{
	Vector3::MulImpl(p_value);
	m_data[3] *= p_value[3];
}

// FUNCTION: LEGO1 0x10002970
// FUNCTION: BETA10 0x10048680
void Vector4::MulImpl(const float& p_value)
{
	Vector3::MulImpl(p_value);
	m_data[3] *= p_value;
}

// FUNCTION: LEGO1 0x100029b0
// FUNCTION: BETA10 0x100486d0
void Vector4::DivImpl(const float& p_value)
{
	Vector3::DivImpl(p_value);
	m_data[3] /= p_value;
}

// FUNCTION: LEGO1 0x100029f0
// FUNCTION: BETA10 0x10048720
float Vector4::DotImpl(const float* p_a, const float* p_b) const
{
	return p_a[0] * p_b[0] + p_a[2] * p_b[2] + (p_a[1] * p_b[1] + p_a[3] * p_b[3]);
}

// FUNCTION: LEGO1 0x10002a20
// FUNCTION: BETA10 0x100487c0
void Vector4::EqualsImpl(const float* p_data)
{
	memcpy(m_data, p_data, sizeof(float) * 4);
}

class MxUnkRecordZ0500;
class MxUnkRecordZ0501;
class MxUnkRecordZ0502;
class MxUnkRecordZ0503;
class MxUnkRecordZ0504;
class MxUnkRecordZ0505;
class MxUnkRecordZ0506;
class MxUnkRecordZ0507;
class MxUnkRecordZ0508;
class MxUnkRecordZ0509;
class MxUnkRecordZ0510;
class MxUnkRecordZ0511;
class MxUnkRecordZ0512;

// FUNCTION: LEGO1 0x10002a40
// FUNCTION: BETA10 0x10048800
void Vector4::SetMatrixProduct(const float* p_vec, const float* p_mat)
{
	m_data[0] = p_vec[0] * p_mat[0] + p_vec[1] * p_mat[4] + p_vec[2] * p_mat[8] + p_vec[3] * p_mat[12];
	m_data[1] = p_vec[0] * p_mat[1] + p_vec[1] * p_mat[5] + p_vec[2] * p_mat[9] + p_vec[3] * p_mat[13];
	m_data[2] = p_vec[0] * p_mat[2] + p_vec[1] * p_mat[6] + p_vec[2] * p_mat[10] + p_vec[3] * p_mat[14];
	m_data[3] = p_vec[0] * p_mat[3] + p_vec[1] * p_mat[7] + p_vec[2] * p_mat[11] + p_vec[3] * p_mat[15];
}

// FUNCTION: LEGO1 0x10002ae0
// FUNCTION: BETA10 0x10048960
void Vector4::SetMatrixProduct(const Vector4& p_a, const float* p_b)
{
	SetMatrixProduct(p_a.m_data, p_b);
}

// FUNCTION: LEGO1 0x10002b00
// FUNCTION: BETA10 0x100489a0
void Vector4::Clear()
{
	memset(m_data, 0, sizeof(float) * 4);
}

// FUNCTION: LEGO1 0x10002b20
// FUNCTION: BETA10 0x100489e0
float Vector4::LenSquared() const
{
	return m_data[1] * m_data[1] + m_data[0] * m_data[0] + m_data[2] * m_data[2] + m_data[3] * m_data[3];
}

// FUNCTION: LEGO1 0x10002b40
// FUNCTION: BETA10 0x10048a60
void Vector4::Fill(const float& p_value)
{
	m_data[0] = p_value;
	m_data[1] = p_value;
	m_data[2] = p_value;
	m_data[3] = p_value;
}

// FUNCTION: LEGO1 0x10002b70
// FUNCTION: BETA10 0x10048ad0
int Vector4::NormalizeQuaternion()
{
	float length = m_data[0] * m_data[0] + m_data[1] * m_data[1] + m_data[2] * m_data[2];

	if (length > 0.0f) {
		float theta = m_data[3] * 0.5f;
		float magnitude = sin((double) theta);
		m_data[3] = cos((double) theta);

		magnitude = magnitude / (float) sqrt((double) length);
		m_data[0] *= magnitude;
		m_data[1] *= magnitude;
		m_data[2] *= magnitude;
		return 0;
	}
	else {
		return -1;
	}
}

#include "vector3dtail.inl.h"

class MxUnkRecordZ0300;
class MxUnkRecordZ0301;
class MxUnkRecordZ0302;
class MxUnkRecordZ0303;
class MxUnkRecordZ0304;
class MxUnkRecordZ0305;
class MxUnkRecordZ0306;
class MxUnkRecordZ0307;
class MxUnkRecordZ0308;
class MxUnkRecordZ0309;
class MxUnkRecordZ0310;
class MxUnkRecordZ0311;
class MxUnkRecordZ0312;
class MxUnkRecordZ0313;
class MxUnkRecordZ0314;
class MxUnkRecordZ0315;
class MxUnkRecordZ0316;

// FUNCTION: LEGO1 0x10002bf0
// FUNCTION: BETA10 0x10048c20
int Vector4::EqualsHamiltonProduct(const Vector4& p_a, const Vector4& p_b)
{
	m_data[3] = p_b.m_data[3] * p_a.m_data[3] -
				(p_b.m_data[1] * p_a.m_data[1] + p_b.m_data[2] * p_a.m_data[2] + p_b.m_data[0] * p_a.m_data[0]);

	Vector3::EqualsCrossImpl(p_a.m_data, p_b.m_data);

	m_data[0] = p_b.m_data[3] * p_a.m_data[0] + p_a.m_data[3] * p_b.m_data[0] + m_data[0];
	m_data[1] = p_a.m_data[1] * p_b.m_data[3] + p_b.m_data[1] * p_a.m_data[3] + m_data[1];
	m_data[2] = p_a.m_data[2] * p_b.m_data[3] + p_b.m_data[2] * p_a.m_data[3] + m_data[2];
	return 0;
}

#endif // VECTOR4D_H
