#include "legojetski.h"

#include "mxmisc.h"
#include "mxnotificationmanager.h"

DECOMP_SIZE_ASSERT(LegoJetski, 0x1dc)

// FUNCTION: LEGO1 0x100136f0
void LegoJetski::FUN_100136f0(float p_worldSpeed)
{
	if (p_worldSpeed < 0) {
		LegoCarRaceActor::m_unk0x0c = 2;
		m_unk0x13c = 0;
		SetWorldSpeed(0);
	}
	else {
		m_unk0x13c = p_worldSpeed;
	}
}

// FUNCTION: LEGO1 0x10013820
LegoJetski::LegoJetski()
{
	NotificationManager()->Register(this);
}

// STUB: LEGO1 0x10013e70
MxLong LegoJetski::Notify(MxParam& p_param)
{
	// TODO
	return 0;
}

// STUB: LEGO1 0x10014110
void LegoJetski::ParseAction(char*)
{
	// TODO
}

// STUB: LEGO1 0x10014120
void LegoJetski::SetWorldSpeed(MxFloat p_worldSpeed)
{
	// TODO
}

// STUB: LEGO1 0x10014140
MxU32 LegoJetski::VTable0x6c(
	LegoPathBoundary* p_boundary,
	Vector3& p_v1,
	Vector3& p_v2,
	float p_f1,
	float p_f2,
	Vector3& p_v3
)
{
	// TODO
	return 0;
}

// STUB: LEGO1 0x10014180
void LegoJetski::VTable0x70(float p_float)
{
	// TODO
}

// STUB: LEGO1 0x100141b0
MxResult LegoJetski::VTable0x94(LegoPathActor* p_actor, MxBool p_bool)
{
	// TODO
	return 0;
}

// STUB: LEGO1 0x100141c0
void LegoJetski::VTable0x98()
{
	// TODO
}

// STUB: LEGO1 0x10014200
MxResult LegoJetski::WaitForAnimation()
{
	// TODO
	return SUCCESS;
}
