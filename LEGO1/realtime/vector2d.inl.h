#ifndef VECTOR2D_H
#define VECTOR2D_H

#include "vector.h"

#include <math.h>
#include <memory.h>

// FUNCTION: LEGO1 0x10001f80
// FUNCTION: BETA10 0x10010a20
void Vector2::AddImpl(const float* p_value)
{
	m_data[0] += p_value[0];
	m_data[1] += p_value[1];
}

// FUNCTION: LEGO1 0x10001fa0
// FUNCTION: BETA10 0x10010a80
void Vector2::AddImpl(float p_value)
{
	m_data[0] += p_value;
	m_data[1] += p_value;
}

// FUNCTION: LEGO1 0x10001fc0
// FUNCTION: BETA10 0x10010ad0
void Vector2::SubImpl(const float* p_value)
{
	m_data[0] -= p_value[0];
	m_data[1] -= p_value[1];
}

// FUNCTION: LEGO1 0x10001fe0
// FUNCTION: BETA10 0x10010b30
void Vector2::MulImpl(const float* p_value)
{
	m_data[0] *= p_value[0];
	m_data[1] *= p_value[1];
}

// FUNCTION: LEGO1 0x10002000
// FUNCTION: BETA10 0x10010b90
void Vector2::MulImpl(const float& p_value)
{
	m_data[0] *= p_value;
	m_data[1] *= p_value;
}

// FUNCTION: LEGO1 0x10002020
// FUNCTION: BETA10 0x10010bf0
void Vector2::DivImpl(const float& p_value)
{
	m_data[0] /= p_value;
	m_data[1] /= p_value;
}

// FUNCTION: LEGO1 0x10002040
// FUNCTION: BETA10 0x10010c50
float Vector2::DotImpl(const float* p_a, const float* p_b) const
{
	return p_b[0] * p_a[0] + p_b[1] * p_a[1];
}

// FUNCTION: LEGO1 0x10002060
// FUNCTION: BETA10 0x10010c90
void Vector2::SetData(float* p_data)
{
	m_data = p_data;
}

// FUNCTION: LEGO1 0x10002070
// FUNCTION: BETA10 0x10010cc0
void Vector2::EqualsImpl(const float* p_data)
{
	memcpy(m_data, p_data, sizeof(float) * 2);
}

// FUNCTION: LEGO1 0x10002090
// FUNCTION: BETA10 0x10010d00
float* Vector2::GetData()
{
	return m_data;
}

// FUNCTION: LEGO1 0x100020a0
// FUNCTION: BETA10 0x10010d30
const float* Vector2::GetData() const
{
	return m_data;
}

// FUNCTION: LEGO1 0x100020b0
// FUNCTION: BETA10 0x10010d60
void Vector2::Clear()
{
	memset(m_data, 0, sizeof(float) * 2);
}

// FUNCTION: LEGO1 0x100020d0
// FUNCTION: BETA10 0x10010da0
float Vector2::Dot(const float* p_a, const float* p_b) const
{
	return DotImpl(p_a, p_b);
}

// FUNCTION: LEGO1 0x100020f0
// FUNCTION: BETA10 0x100108c0
float Vector2::Dot(const Vector2& p_a, const Vector2& p_b) const
{
	return DotImpl(p_a.m_data, p_b.m_data);
}

// FUNCTION: LEGO1 0x10002110
// FUNCTION: BETA10 0x10010de0
float Vector2::Dot(const float* p_a, const Vector2& p_b) const
{
	return DotImpl(p_a, p_b.m_data);
}

// FUNCTION: LEGO1 0x10002130
// FUNCTION: BETA10 0x10010e20
float Vector2::Dot(const Vector2& p_a, const float* p_b) const
{
	return DotImpl(p_a.m_data, p_b);
}

// FUNCTION: LEGO1 0x10002150
// FUNCTION: BETA10 0x10010e60
float Vector2::LenSquared() const
{
	return m_data[0] * m_data[0] + m_data[1] * m_data[1];
}

// FUNCTION: LEGO1 0x10002160
// FUNCTION: BETA10 0x10010900
int Vector2::Unitize()
{
	float sq = LenSquared();

	if (sq > 0.0f) {
		float root = sqrt(sq);
		if (root > 0.0f) {
			DivImpl(root);
			return 0;
		}
	}

	return -1;
}

// FUNCTION: LEGO1 0x100021c0
// FUNCTION: BETA10 0x10010eb0
void Vector2::operator+=(float p_value)
{
	AddImpl(p_value);
}

// FUNCTION: LEGO1 0x100021d0
// FUNCTION: BETA10 0x10010ee0
void Vector2::operator+=(const float* p_other)
{
	AddImpl(p_other);
}

// FUNCTION: LEGO1 0x100021e0
// FUNCTION: BETA10 0x10010f10
void Vector2::operator+=(const Vector2& p_other)
{
	AddImpl(p_other.m_data);
}

// FUNCTION: LEGO1 0x100021f0
// FUNCTION: BETA10 0x10010f50
void Vector2::operator-=(const float* p_other)
{
	SubImpl(p_other);
}

// FUNCTION: LEGO1 0x10002200
// FUNCTION: BETA10 0x10010f80
void Vector2::operator-=(const Vector2& p_other)
{
	SubImpl(p_other.m_data);
}

// FUNCTION: LEGO1 0x10002210
// FUNCTION: BETA10 0x10010fc0
void Vector2::operator*=(const float* p_other)
{
	MulImpl(p_other);
}

// FUNCTION: LEGO1 0x10002220
// FUNCTION: BETA10 0x10010ff0
void Vector2::operator*=(const Vector2& p_other)
{
	MulImpl(p_other.m_data);
}

// FUNCTION: LEGO1 0x10002230
// FUNCTION: BETA10 0x10011030
void Vector2::operator*=(const float& p_value)
{
	MulImpl(p_value);
}

// FUNCTION: LEGO1 0x10002240
// FUNCTION: BETA10 0x10011060
void Vector2::operator/=(const float& p_value)
{
	DivImpl(p_value);
}

// FUNCTION: LEGO1 0x10002250
// FUNCTION: BETA10 0x10011090
void Vector2::operator=(const float* p_other)
{
	EqualsImpl(p_other);
}

// FUNCTION: LEGO1 0x10002260
// FUNCTION: BETA10 0x100110c0
void Vector2::operator=(const Vector2& p_other)
{
	EqualsImpl(p_other.m_data);
}

#endif // VECTOR2D_H
