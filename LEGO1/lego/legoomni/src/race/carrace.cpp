#include "carrace.h"

#include "mxactionnotificationparam.h"

DECOMP_SIZE_ASSERT(CarRace, 0x154)

// FUNCTION: LEGO1 0x10016a90
CarRace::CarRace()
{
	this->m_skeleton = NULL;
	this->m_unk0x130 = MxRect32(0x16c, 0x154, 0x1ec, 0x15e);
}

// STUB: LEGO1 0x10016ce0
MxResult CarRace::Create(MxDSAction& p_dsAction)
{
	// TODO
	return SUCCESS;
}

// STUB: LEGO1 0x10016dd0
void CarRace::ReadyWorld()
{
	// TODO
}

// STUB: LEGO1 0x10016f60
MxLong CarRace::HandleEndAction(MxEndActionNotificationParam&)
{
	// TODO
	return 0;
}

// STUB: LEGO1 0x100170e0
MxLong CarRace::HandlePathStruct(LegoPathStructNotificationParam&)
{
	// TODO
	return 0;
}

// STUB: LEGO1 0x10017650
MxLong CarRace::HandleClick(LegoEventNotificationParam&)
{
	// TODO
	return 0;
}

// STUB: LEGO1 0x100177e0
MxLong CarRace::HandleType0Notification(MxNotificationParam&)
{
	// TODO
	return 0;
}

// STUB: LEGO1 0x10017900
MxBool CarRace::Escape()
{
	// TODO
	return FALSE;
}
