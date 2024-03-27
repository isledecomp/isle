#include "legoextraactor.h"

DECOMP_SIZE_ASSERT(LegoExtraActor, 0x1dc)

// FUNCTION: LEGO1 0x1002a500
LegoExtraActor::LegoExtraActor()
{
	m_unk0x70 = 0.0f;
	m_unk0x08 = 0;
	m_unk0x0c = 0;
	m_unk0x0e = 0;
	m_unk0x14 = 0;
	m_unk0x60 = NULL;
	m_unk0x64 = NULL;
	m_unk0x15 = 0;
}

// FUNCTION: LEGO1 0x1002a6b0
LegoExtraActor::~LegoExtraActor()
{
	delete m_unk0x60;
	delete m_unk0x64;
}

// STUB: LEGO1 0x1002a720
MxS32 LegoExtraActor::VTable0x90()
{
	return 0;
}

// STUB: LEGO1 0x1002aa90
void LegoExtraActor::VTable0xa4()
{
}

// STUB: LEGO1 0x1002aae0
MxResult LegoExtraActor::FUN_1002aae0()
{
	// TODO
	VTable0x9c();
	return SUCCESS;
}

// STUB: LEGO1 0x1002aba0
MxS32 LegoExtraActor::VTable0x94()
{
	return 0;
}

// STUB: LEGO1 0x1002b290
void LegoExtraActor::VTable0x9c()
{
	// TODO
}

// STUB: LEGO1 0x1002b440
void LegoExtraActor::VTable0x70(float)
{
	// TODO
}

// FUNCTION: LEGO1 0x1002b5d0
void LegoExtraActor::VTable0x74(Matrix4& p_transform)
{
	if (m_unk0x14 == 0) {
		LegoAnimActor::VTable0x74(p_transform);
	}
}

// FUNCTION: LEGO1 0x1002b5f0
void LegoExtraActor::SetWorldSpeed(MxFloat p_worldSpeed)
{
	if (m_curAnim == 0 && p_worldSpeed > 0) {
		VTable0xc4();
	}
	LegoAnimActor::SetWorldSpeed(p_worldSpeed);
}

// STUB: LEGO1 0x1002b630
void LegoExtraActor::VTable0xc4()
{
}

// FUNCTION: LEGO1 0x1002b6f0
void LegoExtraActor::VTable0x68(Mx3DPointFloat& p_point1, Mx3DPointFloat& p_point2, Mx3DPointFloat& p_point3)
{
	LegoPathActor::VTable0x68(p_point1, p_point2, p_point3);
}

// STUB: LEGO1 0x1002b980
void LegoExtraActor::VTable0x6c()
{
}
