#include "islepathactor.h"

#include "mxnotificationparam.h"

DECOMP_SIZE_ASSERT(IslePathActor, 0x160)

// FUNCTION: LEGO1 0x1001a200
IslePathActor::IslePathActor()
{
	m_world = NULL;
	m_unk0x13c = 6.0;
	m_unk0x15c = 1.0;
	m_unk0x158 = 0;
}

// FUNCTION: LEGO1 0x1001a280
MxResult IslePathActor::Create(MxDSAction& p_dsAction)
{
	return MxEntity::Create(p_dsAction);
}

// FUNCTION: LEGO1 0x1001a2a0
void IslePathActor::Destroy(MxBool p_fromDestructor)
{
	if (!p_fromDestructor) {
		LegoPathActor::Destroy(FALSE);
	}
}

// FUNCTION: LEGO1 0x1001a2c0
MxLong IslePathActor::Notify(MxParam& p_param)
{
	MxLong ret = 0;

	switch (((MxNotificationParam&) p_param).GetType()) {
	case c_notificationType0:
		ret = VTable0xd0();
		break;
	case c_notificationType11:
		ret = VTable0xcc();
		break;
	case c_notificationClick:
		ret = VTable0xd4((LegoControlManagerEvent&) p_param);
		break;
	case c_notificationType18:
		ret = VTable0xd8((MxType18NotificationParam&) p_param);
		break;
	case c_notificationType19:
		ret = VTable0xdc((MxType19NotificationParam&) p_param);
		break;
	}

	return ret;
}

// STUB: LEGO1 0x1001a350
void IslePathActor::VTable0xe0()
{
	// TODO
}

// STUB: LEGO1 0x1001a3f0
void IslePathActor::VTable0xe4()
{
	// TODO
}

// STUB: LEGO1 0x1001b2a0
void IslePathActor::VTable0xe8(LegoGameState::Area, MxBool, MxU8)
{
	// TODO
}

// STUB: LEGO1 0x1001b5b0
void IslePathActor::VTable0xec(MxMatrix, MxU32, MxBool)
{
	// TODO
}
