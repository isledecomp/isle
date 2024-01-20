#include "bike.h"

DECOMP_SIZE_ASSERT(Bike, 0x164);

// FUNCTION: LEGO1 0x10076670
Bike::Bike()
{
	this->m_unk0x13c = 20.0;
	this->m_unk0x150 = 3.0;
	this->m_unk0x148 = 1;
}

// STUB: LEGO1 0x100768f0
MxResult Bike::Create(MxDSAction& p_dsAction)
{
	// TODO
	return SUCCESS;
}

// STUB: LEGO1 0x10076920
void Bike::VTable0xe4()
{
	// TODO
}

// STUB: LEGO1 0x100769a0
MxU32 Bike::VTable0xcc()
{
	// TODO
	return 0;
}

// STUB: LEGO1 0x10076aa0
MxU32 Bike::VTable0xd4(MxType17NotificationParam& p_param)
{
	// TODO
	return 0;
}
