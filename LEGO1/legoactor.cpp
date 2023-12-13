#include "legoactor.h"

DECOMP_SIZE_ASSERT(LegoActor, 0x78)

// Probably in header
// FUNCTION: LEGO1 0x10002cc0
MxFloat LegoActor::VTable0x50()
{
	return m_unk0x68;
}

// FUNCTION: LEGO1 0x10002cd0
void LegoActor::VTable0x54(MxFloat p_unk0x68)
{
	m_unk0x68 = p_unk0x68;
}

// FUNCTION: LEGO1 0x10002ce0
void LegoActor::VTable0x58(MxFloat p_unk0x70)
{
	m_unk0x70 = p_unk0x70;
}

// FUNCTION: LEGO1 0x10002cf0
MxFloat LegoActor::VTable0x5c()
{
	return m_unk0x70;
}

// FUNCTION: LEGO1 0x10002d00
undefined LegoActor::VTable0x60()
{
	return m_unk0x74;
}

// FUNCTION: LEGO1 0x10002d10
void LegoActor::VTable0x64(undefined p_unk0x74)
{
	m_unk0x74 = p_unk0x74;
}
// End header

// FUNCTION: LEGO1 0x1002d110
LegoActor::LegoActor()
{
	m_unk0x68 = 0.0f;
	m_unk0x6c = 0;
	m_unk0x70 = 0.0f;
	m_unk0x10 = 0;
	m_unk0x74 = 0;
}
