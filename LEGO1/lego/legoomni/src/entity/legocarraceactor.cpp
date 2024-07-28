#include "legocarraceactor.h"

#include "geom/legounkown100db7f4.h"
#include "legopathboundary.h"
#include "misc.h"
#include "mxmisc.h"
#include "mxvariabletable.h"

DECOMP_SIZE_ASSERT(LegoCarRaceActor, 0x1a0)

// GLOBAL: LEGO1 0x100f7af0
// STRING: LEGO1 0x100f7ae4
const char* g_fuel = "FUEL";

// FUNCTION: LEGO1 0x10080350
// FUNCTION: BETA10 0x100cd6b0
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

// FUNCTION: LEGO1 0x10080590
// FUNCTION: BETA10 0x100cd8cf
void LegoCarRaceActor::FUN_10080590(float p_float)
{
	MxFloat maxSpeed = m_maxLinearVel;
	Mx3DPointFloat destEdgeUnknownVector = Mx3DPointFloat();
	Mx3DPointFloat worldDirection = Mx3DPointFloat(m_roi->GetWorldDirection());

	m_destEdge->FUN_1002ddc0(*m_boundary, destEdgeUnknownVector);

	if (abs(destEdgeUnknownVector.Dot(destEdgeUnknownVector.GetData(), worldDirection.GetData())) > 0.5) {
		maxSpeed *= m_unk0x10;
	}

	MxS32 deltaUnk0x70;
	LegoPathActor* userActor = UserActor();

	if (userActor) {
		deltaUnk0x70 = m_unk0x70 - userActor->GetUnk0x70();
	}
	else {
		deltaUnk0x70 = 0;
	}

	if (deltaUnk0x70 > 1) {
		if (deltaUnk0x70 > 3) {
			deltaUnk0x70 = 3;
		}

		maxSpeed *= (m_unk0x18 * (--deltaUnk0x70) * -0.25f + 1.0f);
	}
	else if (deltaUnk0x70 < -1) {
		maxSpeed *= 1.3;
	}

	MxFloat deltaSpeed = maxSpeed - m_worldSpeed;
	MxFloat changeInSpeed = (p_float - m_unk0x1c) * m_unk0x14;
	m_unk0x1c = p_float;

	if (deltaSpeed < 0.0f) {
		changeInSpeed = -changeInSpeed;
	}

	MxFloat newWorldSpeed = changeInSpeed + m_worldSpeed;

	if (newWorldSpeed > maxSpeed) {
		newWorldSpeed = maxSpeed;
	}

	SetWorldSpeed(newWorldSpeed);
}

// STUB: LEGO1 0x10080740
void LegoCarRaceActor::VTable0x1c()
{
}

// FUNCTION: LEGO1 0x10080b40
// FUNCTION: BETA10 0x100cdb3c
void LegoCarRaceActor::SwitchBoundary(LegoPathBoundary*& p_boundary, LegoUnknown100db7f4*& p_edge, float& p_unk0xe4)
{
	LegoPathActor::SwitchBoundary(m_boundary, m_destEdge, m_unk0xe4);
}

// STUB: LEGO1 0x10080b70
void LegoCarRaceActor::VTable0x70(float p_float)
{
	// TODO
}

// STUB: LEGO1 0x10080be0
MxResult LegoCarRaceActor::VTable0x9c()
{
	// TODO
	return SUCCESS;
}

// STUB: LEGO1 0x10081840
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
