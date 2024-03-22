#include "ambulance.h"

#include "decomp.h"

DECOMP_SIZE_ASSERT(Ambulance, 0x184)

// FUNCTION: LEGO1 0x10035ee0
Ambulance::Ambulance()
{
	this->m_unk0x168 = 0;
	this->m_unk0x16a = -1;
	this->m_unk0x164 = 0;
	this->m_unk0x16c = 0;
	this->m_unk0x174 = -1;
	this->m_unk0x16e = 0;
	this->m_unk0x178 = -1;
	this->m_unk0x170 = 0;
	this->m_unk0x172 = 0;
	this->m_unk0x13c = 40.0;
	this->m_unk0x17c = 1.0;
}

// STUB: LEGO1 0x10035f90
void Ambulance::Destroy(MxBool p_fromDestructor)
{
	// TODO
}

// STUB: LEGO1 0x100361d0
MxResult Ambulance::Create(MxDSAction& p_dsAction)
{
	// TODO
	return SUCCESS;
}

// STUB: LEGO1 0x10036300
void Ambulance::VTable0x70(float p_float)
{
	// TODO
}

// STUB: LEGO1 0x10036420
MxLong Ambulance::Notify(MxParam& p_param)
{
	// TODO
	return 0;
}

// STUB: LEGO1 0x10036860
MxU32 Ambulance::VTable0xdc(MxType19NotificationParam& p_param)
{
	// TODO
	return 0;
}

// STUB: LEGO1 0x10036ce0
MxU32 Ambulance::VTable0xcc()
{
	// TODO
	return 0;
}

// STUB: LEGO1 0x10036e60
void Ambulance::FUN_10036e60()
{
	// TODO
}

// STUB: LEGO1 0x10036e90
void Ambulance::VTable0xe4()
{
	// TODO
}

// STUB: LEGO1 0x10036f90
MxU32 Ambulance::VTable0xd4(LegoControlManagerEvent& p_param)
{
	// TODO
	return 0;
}

// STUB: LEGO1 0x10037060
void Ambulance::FUN_10037060()
{
	// TODO
}

// STUB: LEGO1 0x10037160
MxResult Ambulance::Tickle()
{
	// TODO
	return SUCCESS;
}
