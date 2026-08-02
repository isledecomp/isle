#ifndef VECTOR3DTAIL_H
#define VECTOR3DTAIL_H

#include "vector.h"

class MxUnkRecordZ0400;
class MxUnkRecordZ0401;

// FUNCTION: LEGO1 0x10003bd0
// FUNCTION: BETA10 0x10011530
float Vector3::LenSquared() const
{
	return m_data[0] * m_data[0] + m_data[1] * m_data[1] + m_data[2] * m_data[2];
}

#endif // VECTOR3DTAIL_H
