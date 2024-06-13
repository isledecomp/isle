#include "motocycle.h"

DECOMP_SIZE_ASSERT(Motocycle, 0x16c)

// FUNCTION: LEGO1 0x100357b0
Motocycle::Motocycle()
{
	this->m_maxLinearVel = 40.0;
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
void Motocycle::Exit()
{
	// TODO
}

// STUB: LEGO1 0x10035c50
MxLong Motocycle::HandleClick()
{
	// TODO
	return 0;
}

// STUB: LEGO1 0x10035d70
MxLong Motocycle::HandleControl(LegoControlManagerEvent& p_param)
{
	// TODO
	return 0;
}

// STUB: LEGO1 0x10035df0
MxLong Motocycle::HandlePathStruct(LegoPathStructEvent& p_param)
{
	// TODO
	return 0;
}

// STUB: LEGO1 0x10035e10
void Motocycle::FUN_10035e10()
{
	// TODO
}
