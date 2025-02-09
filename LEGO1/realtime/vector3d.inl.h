#ifndef VECTOR3D_H
#define VECTOR3D_H

#include "vector2d.inl.h"

// FUNCTION: LEGO1 0x10002270
// FUNCTION: BETA10 0x10011350
void Vector3::EqualsCrossImpl(const float* p_a, const float* p_b)
{
	m_data[0] = p_a[1] * p_b[2] - p_a[2] * p_b[1];
	m_data[1] = p_a[2] * p_b[0] - p_a[0] * p_b[2];
	m_data[2] = p_a[0] * p_b[1] - p_a[1] * p_b[0];
}

// FUNCTION: LEGO1 0x100022c0
// FUNCTION: BETA10 0x10011430
void Vector3::EqualsCross(const Vector3& p_a, const Vector3& p_b)
{
	EqualsCrossImpl(p_a.m_data, p_b.m_data);
}

// FUNCTION: LEGO1 0x100022e0
// FUNCTION: BETA10 0x10011470
void Vector3::EqualsCross(const Vector3& p_a, const float* p_b)
{
	EqualsCrossImpl(p_a.m_data, p_b);
}

// FUNCTION: LEGO1 0x10002300
// FUNCTION: BETA10 0x100114b0
void Vector3::EqualsCross(const float* p_a, const Vector3& p_b)
{
	EqualsCrossImpl(p_a, p_b.m_data);
}

// FUNCTION: LEGO1 0x10003a60
// FUNCTION: BETA10 0x10011100
void Vector3::AddImpl(const float* p_value)
{
	m_data[0] += p_value[0];
	m_data[1] += p_value[1];
	m_data[2] += p_value[2];
}

// FUNCTION: LEGO1 0x10003a90
// FUNCTION: BETA10 0x10011150
void Vector3::AddImpl(float p_value)
{
	m_data[0] += p_value;
	m_data[1] += p_value;
	m_data[2] += p_value;
}

// FUNCTION: LEGO1 0x10003ac0
// FUNCTION: BETA10 0x100111c0
void Vector3::SubImpl(const float* p_value)
{
	m_data[0] -= p_value[0];
	m_data[1] -= p_value[1];
	m_data[2] -= p_value[2];
}

// FUNCTION: LEGO1 0x10003af0
// FUNCTION: BETA10 0x10011210
void Vector3::MulImpl(const float* p_value)
{
	m_data[0] *= p_value[0];
	m_data[1] *= p_value[1];
	m_data[2] *= p_value[2];
}

// FUNCTION: LEGO1 0x10003b20
// FUNCTION: BETA10 0x10011260
void Vector3::MulImpl(const float& p_value)
{
	m_data[0] *= p_value;
	m_data[1] *= p_value;
	m_data[2] *= p_value;
}

// FUNCTION: LEGO1 0x10003b50
// FUNCTION: BETA10 0x100112b0
void Vector3::DivImpl(const float& p_value)
{
	m_data[0] /= p_value;
	m_data[1] /= p_value;
	m_data[2] /= p_value;
}

// FUNCTION: LEGO1 0x10003b80
// FUNCTION: BETA10 0x10011300
float Vector3::DotImpl(const float* p_a, const float* p_b) const
{
	return p_a[0] * p_b[0] + p_a[2] * p_b[2] + p_a[1] * p_b[1];
}

// FUNCTION: LEGO1 0x10003ba0
// FUNCTION: BETA10 0x100113f0
void Vector3::EqualsImpl(const float* p_data)
{
	memcpy(m_data, p_data, sizeof(float) * 3);
}

// FUNCTION: LEGO1 0x10003bc0
// FUNCTION: BETA10 0x100114f0
void Vector3::Clear()
{
	memset(m_data, 0, sizeof(float) * 3);
}

// FUNCTION: LEGO1 0x10003bd0
// FUNCTION: BETA10 0x10011530
float Vector3::LenSquared() const
{
	return m_data[0] * m_data[0] + m_data[1] * m_data[1] + m_data[2] * m_data[2];
}

// FUNCTION: LEGO1 0x10003bf0
// FUNCTION: BETA10 0x100115a0
void Vector3::Fill(const float& p_value)
{
	m_data[0] = p_value;
	m_data[1] = p_value;
	m_data[2] = p_value;
}

#endif // VECTOR3D_H
