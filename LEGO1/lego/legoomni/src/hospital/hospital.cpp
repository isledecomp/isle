#include "hospital.h"

#include "mxnotificationmanager.h"
#include "mxomni.h"

DECOMP_SIZE_ASSERT(Hospital, 0x12c)

// FUNCTION: LEGO1 0x100745e0
Hospital::Hospital()
{
	this->m_unk0xf8 = 0;
	this->m_unk0x100 = 0;
	this->m_unk0x104 = 0;
	this->m_unk0x108 = 0;
	this->m_unk0xfc = 0;
	this->m_unk0x10c = 0;
	this->m_unk0x110 = 0;
	this->m_unk0x114 = 0;
	this->m_unk0x118 = 0;
	this->m_unk0x11c = 0;
	this->m_unk0x120 = 0;
	this->m_unk0x128 = 0;
	NotificationManager()->Register(this);
}

// STUB: LEGO1 0x100746a0
MxBool Hospital::VTable0x5c()
{
	// TODO
	return FALSE;
}

// STUB: LEGO1 0x100747f0
Hospital::~Hospital()
{
	// TODO
}

// STUB: LEGO1 0x100748c0
MxResult Hospital::Create(MxDSAction& p_dsAction)
{
	// TODO
	return SUCCESS;
}

// STUB: LEGO1 0x10074990
MxLong Hospital::Notify(MxParam& p_param)
{
	// TODO

	return 0;
}

// STUB: LEGO1 0x10074a60
void Hospital::VTable0x50()
{
	// TODO
}

// STUB: LEGO1 0x10076220
void Hospital::VTable0x68(MxBool p_add)
{
	// TODO
}

// STUB: LEGO1 0x10076270
MxResult Hospital::Tickle()
{
	// TODO
	return SUCCESS;
}

// STUB: LEGO1 0x10076330
MxBool Hospital::VTable0x64()
{
	// TODO
	return FALSE;
}
