#include "legoracecar.h"

#include "mxmisc.h"
#include "mxnotificationmanager.h"

DECOMP_SIZE_ASSERT(LegoRaceCar, 0x200)

// FUNCTION: LEGO1 0x10012950
LegoRaceCar::LegoRaceCar()
{
	m_unk0x54 = 0;
	m_unk0x70 = 0;
	m_unk0x74 = 0;
	m_unk0x5c.Clear();
	m_unk0x58 = 0;
	m_unk0x78 = 0;
	m_unk0x7c = 0;
	NotificationManager()->Register(this);
}

// STUB: LEGO1 0x10012c80
LegoRaceCar::~LegoRaceCar()
{
	// TODO
}

// STUB: LEGO1 0x10012d90
MxLong LegoRaceCar::Notify(MxParam& p_param)
{
	// TODO
	return 0;
}

// STUB: LEGO1 0x10012e60
void LegoRaceCar::SetWorldSpeed(MxFloat p_worldSpeed)
{
	// TODO
}

// FUNCTION: LEGO1 0x10012ea0
void LegoRaceCar::FUN_10012ea0(float p_worldSpeed)
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

// STUB: LEGO1 0x10012ef0
void LegoRaceCar::ParseAction(char*)
{
	// TODO
}

// STUB: LEGO1 0x10012ff0
void LegoRaceCar::FUN_10012ff0(float)
{
	// TODO
}

// STUB: LEGO1 0x10013130
MxBool LegoRaceCar::FUN_10013130(float)
{
	// TODO
	return TRUE;
}

// STUB: LEGO1 0x100131f0
void LegoRaceCar::VTable0x70(float p_float)
{
	// TODO
}

// STUB: LEGO1 0x100133c0
MxResult LegoRaceCar::VTable0x94(LegoPathActor* p_actor, MxBool p_bool)
{
	// TODO
	return 0;
}

// STUB: LEGO1 0x10013600
MxResult LegoRaceCar::VTable0x9c()
{
	// TODO
	return SUCCESS;
}

// STUB: LEGO1 0x10014500
MxU32 LegoRaceCar::VTable0x6c(
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

// STUB: LEGO1 0x10014560
void LegoRaceCar::SwitchBoundary(LegoPathBoundary*& p_boundary, LegoUnknown100db7f4*& p_edge, float& p_unk0xe4)
{
	// TODO
}
