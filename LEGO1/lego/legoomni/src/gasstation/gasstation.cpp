#include "gasstation.h"

#include "mxnotificationmanager.h"

// FUNCTION: LEGO1 0x100046a0
GasStation::GasStation()
{
	m_unk0xf8 = 0;
	m_unk0x100 = 0;
	m_unk0xfc = 0;
	m_unk0x108 = 0;
	m_unk0x104 = 0;
	m_unk0x114 = 0;
	m_unk0x106 = 0;
	m_unk0x10c = 0;
	m_unk0x115 = 0;
	m_unk0x110 = 0;

	NotificationManager()->Register(this);
}

// FUNCTION: LEGO1 0x10004770
MxBool GasStation::VTable0x5c()
{
	return TRUE;
}

// STUB: LEGO1 0x100048c0
GasStation::~GasStation()
{
	// TODO
}

// STUB: LEGO1 0x10004990
MxResult GasStation::Create(MxDSAction& p_dsAction)
{
	// TODO
	return SUCCESS;
}

// STUB: LEGO1 0x10004a60
MxLong GasStation::Notify(MxParam& p_param)
{
	// TODO

	return 0;
}

// STUB: LEGO1 0x10004b30
void GasStation::ReadyWorld()
{
	// TODO
}

// STUB: LEGO1 0x10005c40
void GasStation::Enable(MxBool p_enable)
{
	// TODO
}

// STUB: LEGO1 0x10005c90
MxResult GasStation::Tickle()
{
	// TODO

	return 0;
}

// STUB: LEGO1 0x10005e70
MxBool GasStation::VTable0x64()
{
	// TODO
	return FALSE;
}
