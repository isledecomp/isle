#include "legorace.h"

#include "mxnotificationmanager.h"

DECOMP_SIZE_ASSERT(LegoRace, 0x144)

// FUNCTION: LEGO1 0x1000dab0
undefined4 LegoRace::VTable0x78(undefined4)
{
	return 0;
}

// STUB: LEGO1 0x1000dac0
void LegoRace::VTable0x7c(undefined4, undefined4)
{
	// TODO
}

// FUNCTION: LEGO1 0x1000dae0
MxBool LegoRace::VTable0x5c()
{
	return TRUE;
}

// FUNCTION: LEGO1 0x10015aa0
LegoRace::LegoRace()
{
	this->m_unk0xf8 = 0;
	this->m_unk0xfc = 0;
	this->m_unk0x100 = 0;
	this->m_unk0x104 = 0;
	this->m_unk0x108 = 0;
	this->m_unk0x10c = 0;
	this->m_unk0x140 = 0;
	this->m_unk0x110 = 0;
	this->m_unk0x114 = 0;
	this->m_unk0x118 = 0;
	this->m_unk0x128 = 0;
	this->m_unk0x12c = 0;
	this->m_unk0x120 = 0;
	this->m_unk0x124 = 0;
	this->m_unk0x11c = 0;
	NotificationManager()->Register(this);
}

// FUNCTION: LEGO1 0x10015b70
undefined4 LegoRace::VTable0x70(undefined4)
{
	return 0;
}

// FUNCTION: LEGO1 0x10015b80
undefined4 LegoRace::VTable0x74(undefined4)
{
	return 0;
}

// FUNCTION: LEGO1 0x10015b90
MxBool LegoRace::VTable0x64()
{
	return FALSE;
}

// STUB: LEGO1 0x10015ce0
MxResult LegoRace::Create(MxDSObject& p_dsObject)
{
	// TODO
	return SUCCESS;
}

// STUB: LEGO1 0x10015d40
LegoRace::~LegoRace()
{
	// TODO
}

// STUB: LEGO1 0x10015e00
MxLong LegoRace::Notify(MxParam& p_param)
{
	// TODO
	return 0;
}

// STUB: LEGO1 0x10015ed0
void LegoRace::VTable0x68(MxBool p_add)
{
	// TODO
}
