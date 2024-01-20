#include "motocycle.h"

DECOMP_SIZE_ASSERT(Motocycle, 0x16c);

// FUNCTION: LEGO1 0x100357b0
Motocycle::Motocycle()
{
	this->m_unk0x13c = 40.0;
	this->m_unk0x150 = 1.75;
	this->m_unk0x148 = 1;
	this->m_unk0x164 = 1.0;
}

// STUB: LEGO1 0x10035a40
MxResult Motocycle::Create(MxDSAction& p_dsAction)
{
	// TODO
	return SUCCESS;
}

// STUB: LEGO1 0x10035ad0
void Motocycle::VTable0x70(float p_float)
{
	// TODO
}

// STUB: LEGO1 0x10035bc0
void Motocycle::VTable0xe4()
{
	// TODO
}

// STUB: LEGO1 0x10035c50
MxU32 Motocycle::VTable0xcc()
{
	// TODO
	return 0;
}

// STUB: LEGO1 0x10035d70
MxU32 Motocycle::VTable0xd4(MxType17NotificationParam& p_param)
{
	// TODO
	return 0;
}

// STUB: LEGO1 0x10035df0
MxU32 Motocycle::VTable0xdc(MxType19NotificationParam& p_param)
{
	// TODO
	return 0;
}
