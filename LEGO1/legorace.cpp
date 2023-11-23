#include "legorace.h"

DECOMP_SIZE_ASSERT(LegoRace, 0x144)

#include "mxnotificationmanager.h"
#include "mxomni.h"

// OFFSET: LEGO1 0x1000dab0
undefined4 LegoRace::vtable0x78(void)
{
	return 0;
}

// OFFSET: LEGO1 0x1000dac0 STUB
void LegoRace::vtable0x7c()
{
	// TODO
	return;
}

// OFFSET: LEGO1 0x1000dae0
MxBool LegoRace::vtable0x5c()
{
	return TRUE;
}

// OFFSET: LEGO1 0x10015aa0
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

// OFFSET: LEGO1 0x10015d40 STUB
LegoRace::~LegoRace()
{
	// TODO
}

// OFFSET: LEGO1 0x10015e00 STUB
MxLong LegoRace::Notify(MxParam& p)
{
	// TODO

	return 0;
}

// OFFSET: LEGO1 0x10015b70
undefined4 LegoRace::vtable0x70()
{
	return 0;
}

// OFFSET: LEGO1 0x10015b80
undefined4 LegoRace::vtable0x74()
{
	return 0;
}

// OFFSET: LEGO1 0x10015b90
MxBool LegoRace::vtable0x64()
{
	return FALSE;
}

// OFFSET: LEGO1 0x10015ed0 STUB
void LegoRace::vtable0x68(MxBool p_add)
{
	// TODO
	return;
}
