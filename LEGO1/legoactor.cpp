#include "legoactor.h"

DECOMP_SIZE_ASSERT(LegoActor, 0x78)

// Probably in header
// OFFSET: LEGO1 0x10002cc0
float LegoActor::VTable0x50()
{
	return m_unk68;
}

// OFFSET: LEGO1 0x10002cd0
void LegoActor::VTable0x54(float p_unk)
{
	m_unk68 = p_unk;
}

// OFFSET: LEGO1 0x10002ce0
void LegoActor::VTable0x58(float p_unk)
{
	m_unk70 = p_unk;
}

// OFFSET: LEGO1 0x10002cf0
float LegoActor::VTable0x5c()
{
	return m_unk70;
}

// OFFSET: LEGO1 0x10002d00
undefined LegoActor::VTable0x60()
{
	return m_unk74;
}

// OFFSET: LEGO1 0x10002d10
void LegoActor::VTable0x64(undefined p_unk)
{
	m_unk74 = p_unk;
}
// End header

// OFFSET: LEGO1 0x1002d110
LegoActor::LegoActor()
{
	m_unk68 = 0.0f;
	m_unk6c = 0;
	m_unk70 = 0.0f;
	m_unk10 = 0;
	m_unk74 = 0;
}
