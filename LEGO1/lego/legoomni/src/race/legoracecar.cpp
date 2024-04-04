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

// FUNCTION: LEGO1 0x10012ea0
void LegoRaceCar::FUN_10012ea0(float p_worldSpeed)
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

// STUB: LEGO1 0x10014280
MxLong LegoRaceCar::Notify(MxParam& p_param)
{
	// TODO
	return 0;
}

// STUB: LEGO1 0x100144d0
void LegoRaceCar::ParseAction(char*)
{
	// TODO
}

// STUB: LEGO1 0x100144e0
void LegoRaceCar::SetWorldSpeed(MxFloat p_worldSpeed)
{
	// TODO
}

// STUB: LEGO1 0x100144f0
void LegoRaceCar::VTable0x6c()
{
	// TODO
}

// STUB: LEGO1 0x10014530
void LegoRaceCar::VTable0x70(float p_float)
{
	// TODO
}

// STUB: LEGO1 0x10014540
MxResult LegoRaceCar::VTable0x94(LegoPathActor* p_actor, MxBool p_bool)
{
	// TODO
	return 0;
}

// STUB: LEGO1 0x10014550
void LegoRaceCar::VTable0x98()
{
	// TODO
}

// STUB: LEGO1 0x10014580
MxResult LegoRaceCar::WaitForAnimation()
{
	// TODO
	return SUCCESS;
}
