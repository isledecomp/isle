#include "legounknown.h"

DECOMP_SIZE_ASSERT(LegoUnknown, 0x50)

// FUNCTION: LEGO1 0x1009a0f0
LegoUnknown::LegoUnknown()
{
	for (LegoS32 i = 0; i < _countof(m_unk0x00); i++) {
		m_unk0x00[i].Clear();
	}
}

// FUNCTION: LEGO1 0x1009a130
LegoUnknown::~LegoUnknown()
{
}

// FUNCTION: LEGO1 0x1009a140
void LegoUnknown::FUN_1009a140(Vector3& p_point1, Vector3& p_point2, Vector3& p_point3, Vector3& p_point4)
{
	m_unk0x00[0] = p_point1;
	m_unk0x00[1] = p_point2;

	for (LegoS32 i = 0; i < 3; i++) {
		m_unk0x00[2][i] = (p_point3[i] - p_point1[i]) * 3.0f - p_point2[i] * 2.0f - p_point4[i];
		m_unk0x00[3][i] = (p_point1[i] - p_point3[i]) * 2.0f + p_point4[i] + p_point2[i];
	}
}
