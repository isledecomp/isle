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

// STUB: LEGO1 0x100747f0
Hospital::~Hospital()
{
	// TODO
}

// STUB: LEGO1 0x10074990
MxLong Hospital::Notify(MxParam& p_param)
{
	// TODO

	return 0;
}
