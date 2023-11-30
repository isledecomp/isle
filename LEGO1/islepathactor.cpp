#include "islepathactor.h"

DECOMP_SIZE_ASSERT(IslePathActor, 0x160)

// Probably in header
// STUB: LEGO1 0x10002df0
void IslePathActor::VTable0xd0()
{
	// TODO
}

// STUB: LEGO1 0x10002e00
void IslePathActor::VTable0xdc()
{
	// TODO
}

// STUB: LEGO1 0x10002e70
void IslePathActor::VTable0xcc()
{
	// TODO
}

// STUB: LEGO1 0x10002e80
void IslePathActor::VTable0xd4()
{
	// TODO
}

// STUB: LEGO1 0x10002e90
void IslePathActor::VTable0xd8()
{
	// TODO
}
// End header

// FUNCTION: LEGO1 0x1001a200
IslePathActor::IslePathActor()
{
	this->m_pLegoWorld = NULL;
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
