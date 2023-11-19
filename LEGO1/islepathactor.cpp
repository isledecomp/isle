#include "islepathactor.h"

DECOMP_SIZE_ASSERT(IslePathActor, 0x160)

// Probably in header
// OFFSET: LEGO1 0x10002df0 STUB
void IslePathActor::VTable0xd0()
{
	// TODO
}

// OFFSET: LEGO1 0x10002e00 STUB
void IslePathActor::VTable0xdc()
{
	// TODO
}

// OFFSET: LEGO1 0x10002e70 STUB
void IslePathActor::VTable0xcc()
{
	// TODO
}

// OFFSET: LEGO1 0x10002e80 STUB
void IslePathActor::VTable0xd4()
{
	// TODO
}

// OFFSET: LEGO1 0x10002e90 STUB
void IslePathActor::VTable0xd8()
{
	// TODO
}
// End header

// OFFSET: LEGO1 0x1001a200
IslePathActor::IslePathActor()
{
	this->m_pLegoWorld = NULL;
	this->m_unk13c = 6.0;
	this->m_unk15c = 1.0;
	this->m_unk158 = 0;
}

// OFFSET: LEGO1 0x1001a280
MxResult IslePathActor::Create(MxDSObject& p_dsObject)
{
	return MxEntity::Create(p_dsObject);
}

// OFFSET: LEGO1 0x1001a350 STUB
void IslePathActor::VTable0xe0()
{
	// TODO
}

// OFFSET: LEGO1 0x1001a3f0 STUB
void IslePathActor::VTable0xe4()
{
	// TODO
}

// OFFSET: LEGO1 0x1001b2a0 STUB
void IslePathActor::VTable0xe8(MxU32 p_1, MxBool p_2, MxU8 p_3)
{
	// TODO
}

// OFFSET: LEGO1 0x1001b5b0 STUB
void IslePathActor::VTable0xec()
{
	// TODO
}
