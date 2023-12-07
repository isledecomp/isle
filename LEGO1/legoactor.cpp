#include "legoactor.h"

DECOMP_SIZE_ASSERT(LegoActor, 0x78)

// FUNCTION: LEGO1 0x1002d110
LegoActor::LegoActor()
{
	m_unk68 = 0.0f;
	m_unk6c = 0;
	m_unk70 = 0.0f;
	m_unk10 = 0;
	m_unk74 = 0;
}

// FUNCTION: LEGO1 0x1002d210
inline const char* LegoActor::ClassName() const
{
	// GLOBAL: LEGO1 0x100f0124
	return "LegoActor";
}

// FUNCTION: LEGO1 0x1002d220
inline MxBool LegoActor::IsA(const char* name) const
{
	return !strcmp(name, LegoActor::ClassName()) || LegoEntity::IsA(name);
}
