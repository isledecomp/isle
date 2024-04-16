#include "legophoneme.h"

DECOMP_SIZE_ASSERT(LegoPhoneme, 0x20)

// FUNCTION: LEGO1 0x10044e50
LegoPhoneme::~LegoPhoneme()
{
}

// FUNCTION: LEGO1 0x10044eb0
undefined4 LegoPhoneme::VTable0x00()
{
	return m_unk0x14;
}

// FUNCTION: LEGO1 0x10044ec0
void LegoPhoneme::VTable0x04(undefined4 p_unk0x14)
{
	m_unk0x14 = p_unk0x14;
}

// FUNCTION: LEGO1 0x10044ed0
LegoTextureInfo* LegoPhoneme::VTable0x08()
{
	return m_unk0x18;
}

// FUNCTION: LEGO1 0x10044ee0
void LegoPhoneme::VTable0x0c(LegoTextureInfo* p_unk0x18)
{
	m_unk0x18 = p_unk0x18;
}

// FUNCTION: LEGO1 0x10044ef0
LegoTextureInfo* LegoPhoneme::VTable0x10()
{
	return m_unk0x1c;
}

// FUNCTION: LEGO1 0x10044f00
void LegoPhoneme::VTable0x14(LegoTextureInfo* p_unk0x1c)
{
	m_unk0x1c = p_unk0x1c;
}

// FUNCTION: LEGO1 0x10044f10
void LegoPhoneme::VTable0x18()
{
}

// FUNCTION: LEGO1 0x10044f20
void LegoPhoneme::Init()
{
	m_unk0x14 = 0;
	m_unk0x18 = NULL;
	m_unk0x1c = NULL;
}

// FUNCTION: LEGO1 0x10044f30
void LegoPhoneme::VTable0x20(undefined4)
{
}
