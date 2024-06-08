#include "legocarraceactor.h"

#include "mxmisc.h"
#include "mxvariabletable.h"

DECOMP_SIZE_ASSERT(LegoCarRaceActor, 0x1a0)

// GLOBAL: LEGO1 0x100f7af0
// STRING: LEGO1 0x100f7ae4
const char* g_fuel = "FUEL";

// STUB: LEGO1 0x100141a0
MxU32 LegoCarRaceActor::VTable0x90(float, Matrix4&)
{
	// TODO
	return 0;
}

// STUB: LEGO1 0x1005d650
MxResult LegoCarRaceActor::VTable0x94(LegoPathActor* p_actor, MxBool p_bool)
{
	// TODO
	return 0;
}

// FUNCTION: LEGO1 0x10080350
LegoCarRaceActor::LegoCarRaceActor()
{
	m_unk0x08 = 1.0f;
	m_unk0x70 = 0.0f;
	m_unk0x0c = 0;
	m_maxLinearVel = 0.0f;
	m_frequencyFactor = 1.0f;
	m_unk0x1c = 0;
	m_unk0x10 = 0.65f;
	m_unk0x14 = 0.03f;
	m_unk0x18 = 0.6f;
	m_unk0x140 = 0.1f;
	m_unk0x150 = -5.0f;
	m_unk0x148 = 1;
	VariableTable()->SetVariable(g_fuel, "0.8");
}

// STUB: LEGO1 0x10080590
void LegoCarRaceActor::FUN_10080590()
{
}

// STUB: LEGO1 0x10080740
void LegoCarRaceActor::VTable0x1c()
{
}

// STUB: LEGO1 0x10081830
MxU32 LegoCarRaceActor::VTable0x6c(
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

// STUB: LEGO1 0x10081d10
void LegoCarRaceActor::VTable0x70(float p_float)
{
	// TODO
}

// STUB: LEGO1 0x10081d20
void LegoCarRaceActor::SwitchBoundary(LegoPathBoundary*& p_boundary, LegoUnknown100db7f4*& p_edge, float& p_unk0xe4)
{
	// TODO
}

// STUB: LEGO1 0x10081d30
MxResult LegoCarRaceActor::VTable0x9c()
{
	// TODO
	return SUCCESS;
}
