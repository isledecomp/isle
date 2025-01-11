#include "legojetski.h"

#include "mxmisc.h"
#include "mxnotificationmanager.h"

DECOMP_SIZE_ASSERT(LegoJetski, 0x1dc)

// STUB: LEGO1 0x100136a0
void LegoJetski::SetWorldSpeed(MxFloat p_worldSpeed)
{
	// TODO
}

// FUNCTION: LEGO1 0x100136f0
void LegoJetski::FUN_100136f0(float p_worldSpeed)
{
	if (p_worldSpeed < 0) {
		LegoCarRaceActor::m_unk0x0c = 2;
		m_maxLinearVel = 0;
		SetWorldSpeed(0);
	}
	else {
		m_maxLinearVel = p_worldSpeed;
	}
}

// STUB: LEGO1 0x10013740
void LegoJetski::VTable0x70(float p_float)
{
	// TODO
}

// FUNCTION: LEGO1 0x10013820
LegoJetski::LegoJetski()
{
	NotificationManager()->Register(this);
}

// FUNCTION: LEGO1 0x10013aa0
LegoJetski::~LegoJetski()
{
	NotificationManager()->Unregister(this);
}

// STUB: LEGO1 0x10013bb0
void LegoJetski::ParseAction(char*)
{
	// TODO
}

// STUB: LEGO1 0x10013c30
MxLong LegoJetski::Notify(MxParam& p_param)
{
	// TODO
	return 0;
}

// STUB: LEGO1 0x10013c40
MxResult LegoJetski::VTable0x94(LegoPathActor* p_actor, MxBool p_bool)
{
	// TODO
	return 0;
}

// STUB: LEGO1 0x10014150
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

// STUB: LEGO1 0x100141d0
void LegoJetski::SwitchBoundary(LegoPathBoundary*& p_boundary, LegoUnknown100db7f4*& p_edge, float& p_unk0xe4)
{
	// TODO
}

// STUB: LEGO1 0x10014210
MxResult LegoJetski::VTable0x9c()
{
	// TODO
	return SUCCESS;
}
