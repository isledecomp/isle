#include "jetski.h"

DECOMP_SIZE_ASSERT(Jetski, 0x164);

// FUNCTION: LEGO1 0x1007e3b0
Jetski::Jetski()
{
	this->m_unk0x13c = 25.0;
	this->m_unk0x150 = 2.0;
	this->m_unk0x148 = 1;
}

// STUB: LEGO1 0x1007e630
MxResult Jetski::Create(MxDSAction& p_dsAction)
{
	// TODO
	return SUCCESS;
}

// STUB: LEGO1 0x1007e680
void Jetski::VTable0x70(float p_float)
{
	// TODO
}

// STUB: LEGO1 0x1007e6f0
void Jetski::VTable0xe4()
{
	// TODO
}

// STUB: LEGO1 0x1007e750
MxU32 Jetski::VTable0xcc()
{
	// TODO
	return 0;
}

// STUB: LEGO1 0x1007e8e0
MxU32 Jetski::VTable0xd4(LegoControlManagerEvent& p_param)
{
	// TODO
	return 0;
}
