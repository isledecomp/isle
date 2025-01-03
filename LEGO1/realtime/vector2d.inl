
#include "vector.h"

// FUNCTION: LEGO1 0x10001f80
void Vector2::AddImpl(const float* p_value)
{
	m_data[0] += p_value[0];
	m_data[1] += p_value[1];
}

// FUNCTION: LEGO1 0x10001fa0
void Vector2::AddImpl(float p_value)
{
	m_data[0] += p_value;
	m_data[1] += p_value;
}

// FUNCTION: LEGO1 0x10001fc0
void Vector2::SubImpl(const float* p_value)
{
	m_data[0] -= p_value[0];
	m_data[1] -= p_value[1];
}

// FUNCTION: LEGO1 0x10001fe0
void Vector2::MulImpl(const float* p_value)
{
	m_data[0] *= p_value[0];
	m_data[1] *= p_value[1];
}

// FUNCTION: LEGO1 0x10002000
void Vector2::MulImpl(const float& p_value)
{
	m_data[0] *= p_value;
	m_data[1] *= p_value;
}

// FUNCTION: LEGO1 0x10002020
void Vector2::DivImpl(const float& p_value)
{
	m_data[0] /= p_value;
	m_data[1] /= p_value;
}

// FUNCTION: LEGO1 0x10002040
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
void Vector2::EqualsImpl(const float* p_data)
{
	memcpy(m_data, p_data, sizeof(float) * 2);
}

// FUNCTION: LEGO1 0x10002090
float* Vector2::GetData()
{
	return m_data;
}

// FUNCTION: LEGO1 0x100020a0
const float* Vector2::GetData() const
{
	return m_data;
}

// FUNCTION: LEGO1 0x100020b0
void Vector2::Clear()
{
	memset(m_data, 0, sizeof(float) * 2);
}

// FUNCTION: LEGO1 0x100020d0
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
float Vector2::Dot(const float* p_a, const Vector2& p_b) const
{
	return DotImpl(p_a, p_b.m_data);
}

// FUNCTION: LEGO1 0x10002130
float Vector2::Dot(const Vector2& p_a, const float* p_b) const
{
	return DotImpl(p_a.m_data, p_b);
}

// FUNCTION: LEGO1 0x10002150
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
void Vector2::operator+=(float p_value)
{
	AddImpl(p_value);
}

// FUNCTION: LEGO1 0x100021d0
void Vector2::operator+=(const float* p_other)
{
	AddImpl(p_other);
}

// FUNCTION: LEGO1 0x100021e0
void Vector2::operator+=(const Vector2& p_other)
{
	AddImpl(p_other.m_data);
}

// FUNCTION: LEGO1 0x100021f0
void Vector2::operator-=(const float* p_other)
{
	SubImpl(p_other);
}

// FUNCTION: LEGO1 0x10002200
void Vector2::operator-=(const Vector2& p_other)
{
	SubImpl(p_other.m_data);
}

// FUNCTION: LEGO1 0x10002210
void Vector2::operator*=(const float* p_other)
{
	MulImpl(p_other);
}

// FUNCTION: LEGO1 0x10002220
void Vector2::operator*=(const Vector2& p_other)
{
	MulImpl(p_other.m_data);
}

// FUNCTION: LEGO1 0x10002230
void Vector2::operator*=(const float& p_value)
{
	MulImpl(p_value);
}

// FUNCTION: LEGO1 0x10002240
void Vector2::operator/=(const float& p_value)
{
	DivImpl(p_value);
}

// FUNCTION: LEGO1 0x10002250
void Vector2::SetVector(const float* p_other)
{
	EqualsImpl(p_other);
}

// FUNCTION: LEGO1 0x10002260
// FUNCTION: BETA10 0x100110c0
void Vector2::SetVector(const Vector2& p_other)
{
	EqualsImpl(p_other.m_data);
}
