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
	this->m_unkf8 = 0;
	this->m_unkfc = 0;
	this->m_unk100 = 0;
	this->m_unk104 = 0;
	this->m_unk108 = 0;
	this->m_unk10c = 0;
	this->m_unk140 = 0;
	this->m_unk110 = 0;
	this->m_unk114 = 0;
	this->m_unk118 = 0;
	this->m_unk128 = 0;
	this->m_unk12c = 0;
	this->m_unk120 = 0;
	this->m_unk124 = 0;
	this->m_unk11c = 0;
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
MxLong LegoRace::Notify(MxParam& p)
{
	// TODO
	return 0;
}

// STUB: LEGO1 0x10015ed0
void LegoRace::VTable0x68(MxBool p_add)
{
	// TODO
}
