#include "legophoneme.h"

DECOMP_SIZE_ASSERT(LegoPhoneme, 0x20)

// FUNCTION: LEGO1 0x10044e50
LegoPhoneme::~LegoPhoneme()
{
}

// FUNCTION: LEGO1 0x10044eb0
MxU32 LegoPhoneme::GetCount()
{
	return m_count;
}

// FUNCTION: LEGO1 0x10044ec0
void LegoPhoneme::SetCount(MxU32 p_count)
{
	m_count = p_count;
}

// FUNCTION: LEGO1 0x10044ed0
LegoTextureInfo* LegoPhoneme::GetTextureInfo()
{
	return m_textureInfo;
}

// FUNCTION: LEGO1 0x10044ee0
void LegoPhoneme::SetTextureInfo(LegoTextureInfo* p_textureInfo)
{
	m_textureInfo = p_textureInfo;
}

// FUNCTION: LEGO1 0x10044ef0
LegoTextureInfo* LegoPhoneme::GetCachedTextureInfo()
{
	return m_cachedTextureInfo;
}

// FUNCTION: LEGO1 0x10044f00
void LegoPhoneme::SetCachedTextureInfo(LegoTextureInfo* p_cachedTextureInfo)
{
	m_cachedTextureInfo = p_cachedTextureInfo;
}

// FUNCTION: LEGO1 0x10044f10
void LegoPhoneme::VTable0x18()
{
}

// FUNCTION: LEGO1 0x10044f20
void LegoPhoneme::Init()
{
	m_count = 0;
	m_textureInfo = NULL;
	m_cachedTextureInfo = NULL;
}

// FUNCTION: LEGO1 0x10044f30
void LegoPhoneme::VTable0x20(undefined4)
{
}
