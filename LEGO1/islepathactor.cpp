#include "islepathactor.h"

DECOMP_SIZE_ASSERT(IslePathActor, 0x160)

// FUNCTION: LEGO1 0x1001a200
IslePathActor::IslePathActor()
{
	this->m_LegoWorld = NULL;
	this->m_unk13c = 6.0;
	this->m_unk15c = 1.0;
	this->m_unk158 = 0;
}

// FUNCTION: LEGO1 0x1001a280
MxResult IslePathActor::Create(MxDSObject& p_dsObject)
{
	return MxEntity::Create(p_dsObject);
}

// STUB: LEGO1 0x1001a350
void IslePathActor::VTable0xe0()
{
	// TODO
}

// STUB: LEGO1 0x1001a3f0
void IslePathActor::VTable0xe4()
{
	// TODO
}

// STUB: LEGO1 0x1001b2a0
void IslePathActor::VTable0xe8(MxU32 p_1, MxBool p_2, MxU8 p_3)
{
	// TODO
}

// STUB: LEGO1 0x1001b5b0
void IslePathActor::VTable0xec()
{
	// TODO
}
