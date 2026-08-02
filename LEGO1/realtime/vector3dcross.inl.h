#ifndef VECTOR3DCROSS_H
#define VECTOR3DCROSS_H

#include "vector.h"

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

#endif // VECTOR3DCROSS_H
