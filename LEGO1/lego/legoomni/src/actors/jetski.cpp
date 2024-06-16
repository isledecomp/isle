#include "jetski.h"

DECOMP_SIZE_ASSERT(Jetski, 0x164)

// FUNCTION: LEGO1 0x1007e3b0
Jetski::Jetski()
{
	this->m_maxLinearVel = 25.0;
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
void Jetski::Exit()
{
	// TODO
}

// STUB: LEGO1 0x1007e750
MxLong Jetski::HandleClick()
{
	// TODO
	return 0;
}

// STUB: LEGO1 0x1007e8e0
MxLong Jetski::HandleControl(LegoControlManagerNotificationParam& p_param)
{
	// TODO
	return 0;
}

// STUB: LEGO1 0x1007e990
void Jetski::FUN_1007e990()
{
	// TODO
}
