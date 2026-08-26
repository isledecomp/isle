#ifndef VECTOR3DTAIL_H
#define VECTOR3DTAIL_H

#include "vector4d.inl.h"

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

// FUNCTION: LEGO1 0x10003bd0
// FUNCTION: BETA10 0x10011530
float Vector3::LenSquared() const
{
	return m_data[0] * m_data[0] + m_data[1] * m_data[1] + m_data[2] * m_data[2];
}

#endif
