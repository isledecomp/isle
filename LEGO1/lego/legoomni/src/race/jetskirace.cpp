#include "jetskirace.h"

DECOMP_SIZE_ASSERT(JetskiRace, 0x144)

// STUB: LEGO1 0x100162c0
MxResult JetskiRace::Create(MxDSAction& p_dsAction)
{
	return SUCCESS;
}

// STUB: LEGO1 0x100163b0
void JetskiRace::ReadyWorld()
{
}

// STUB: LEGO1 0x10016520
MxLong JetskiRace::HandleEndAction(MxEndActionNotificationParam&)
{
	return 0;
}

// STUB: LEGO1 0x100165a0
MxLong JetskiRace::HandleClick(LegoEventNotificationParam&)
{
	return 0;
}

// STUB: LEGO1 0x100166a0
MxLong JetskiRace::HandlePathStruct(LegoPathStructNotificationParam&)
{
	return 0;
}

// STUB: LEGO1 0x10016a10
MxBool JetskiRace::Escape()
{
	return TRUE;
}
