#include "legoracespecial.h"

#include "geom/legounkown100db7f4.h"
#include "legonavcontroller.h"
#include "legopathboundary.h"
#include "legopathcontroller.h"
#include "misc.h"
#include "mxmisc.h"
#include "mxvariabletable.h"

// File name verified by BETA10 0x100cedf7

DECOMP_SIZE_ASSERT(LegoCarRaceActor, 0x1a0)

// GLOBAL: LEGO1 0x100f0c68
// STRING: LEGO1 0x100f0c5c
const char* g_raceState = "RACE_STATE";

// GLOBAL: LEGO1 0x100f7af0
// STRING: LEGO1 0x100f7ae4
const char* g_fuel = "FUEL";

// GLOBAL: LEGO1 0x100f0c6c
// STRING: LEGO1 0x100f0c54
const char* g_racing = "RACING";

// GLOBAL: LEGO1 0x100f7aec
MxFloat LegoCarRaceActor::g_unk0x100f7aec = 8.0f;

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
	Mx3DPointFloat destEdgeUnknownVector;
	Mx3DPointFloat worldDirection = Mx3DPointFloat(m_roi->GetWorldDirection());

	m_destEdge->FUN_1002ddc0(*m_boundary, destEdgeUnknownVector);

	if (abs(destEdgeUnknownVector.Dot(destEdgeUnknownVector.GetData(), worldDirection.GetData())) > 0.5) {
		maxSpeed *= m_unk0x10;
	}

	MxS32 deltaUnk0x70;
	LegoPathActor* userActor = UserActor();

	if (userActor) {
		// All known implementations of LegoPathActor->VTable0x5c() return LegoPathActor::m_unk0x70
		deltaUnk0x70 = m_unk0x70 - userActor->VTable0x5c();
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

// FUNCTION: LEGO1 0x10080740
// FUNCTION: BETA10 0x100cece0
MxS32 LegoCarRaceActor::VTable0x1c(LegoPathBoundary* p_boundary, LegoEdge* p_edge)
{
	Mx3DPointFloat pointUnknown;
	Mx3DPointFloat destEdgeUnknownVector;
	Mx3DPointFloat crossProduct;

	if (m_state == 1) {
		m_boundary = NULL;

		// Not sure where the upper bound of 11 comes from, the underlying array has a size of 16
		for (MxS32 i = 0; i < 11; i += 2) {
			if (LegoPathController::GetControlEdgeA(i + 1) == m_destEdge) {
				m_boundary = LegoPathController::GetControlBoundaryA(i + 1);
				break;
			}
		}

		assert(m_boundary);

		m_state = 0;
		m_unk0x7c = 0;

		if (m_userNavFlag) {
			NavController()->SetLinearVel(m_worldSpeed);
			return 0;
		}
		else {
			return 1;
		}
	}
	else {
		for (MxS32 i = 0; i < 11; i += 2) {
			if (LegoPathController::GetControlEdgeA(i) == p_edge) {
				m_state = 1;

				if (m_worldSpeed < g_unk0x100f7aec) {
					m_worldSpeed = g_unk0x100f7aec;
				}

				m_destEdge = LegoPathController::GetControlEdgeA(i + 1);
				m_boundary = LegoPathController::GetControlBoundaryA(i + 1);
				break;
			}
		}

		if (m_state == 1) {
			if (m_userNavFlag) {
				m_unk0xe4 = 0.5f;
			}

			// variable names verified by BETA10
			Vector3* v1 = m_destEdge->CCWVertex(*m_boundary);
			Vector3* v2 = m_destEdge->CWVertex(*m_boundary);
			assert(v1 && v2);

			pointUnknown[0] = (*v1)[0] + ((*v2)[0] - (*v1)[0]) * m_unk0xe4;
			pointUnknown[1] = (*v1)[1] + ((*v2)[1] - (*v1)[1]) * m_unk0xe4;
			pointUnknown[2] = (*v1)[2] + ((*v2)[2] - (*v1)[2]) * m_unk0xe4;

			m_destEdge->FUN_1002ddc0(*m_boundary, destEdgeUnknownVector);

			crossProduct.EqualsCross(m_boundary->GetUnknown0x14(), &destEdgeUnknownVector);
			crossProduct.Unitize();

			Mx3DPointFloat worldDirection(Vector3(m_roi->GetWorldDirection()));

			if (!m_userNavFlag) {
				((Vector3*) &worldDirection)->Mul(-1.0f);
			}

			((Vector3*) &worldDirection)->Mul(5.0f);
			((Vector3*) &crossProduct)->Mul(5.0f);

			MxResult callResult =
				VTable0x80(Vector3(m_roi->GetWorldPosition()), worldDirection, pointUnknown, crossProduct);

			if (callResult) {
				m_unk0x7c = 0;
				return 0;
			}
			else {
				m_unk0x7c = 0;
				assert(0);
				return 0; // BETA10 returns -1 here
			}
		}
		else {
			// This `for` loop does not exist in BETA10
			for (MxS32 i = 0; i < 10; i++) {
				if (LegoPathController::GetControlEdgeB(i) == p_edge &&
					LegoPathController::GetControlBoundaryB(i) == m_boundary) {
					return 0;
				}
			}

			return 1;
		}
	}
}

// FUNCTION: LEGO1 0x10080b40
// FUNCTION: BETA10 0x100cdb3c
void LegoCarRaceActor::SwitchBoundary(LegoPathBoundary*& p_boundary, LegoUnknown100db7f4*& p_edge, float& p_unk0xe4)
{
	LegoPathActor::SwitchBoundary(m_boundary, m_destEdge, m_unk0xe4);
}

// FUNCTION: LEGO1 0x10080b70
// FUNCTION: BETA10 0x1000366b
void LegoCarRaceActor::VTable0x70(float p_float)
{
	// m_unk0x0c is not an MxBool, there are places where it is set to 2 or higher
	if (m_unk0x0c == 0) {
		const char* value = VariableTable()->GetVariable(g_raceState);

		if (strcmpi(value, g_racing) == 0) {
			m_unk0x0c = 1;
			m_lastTime = p_float - 1.0f;
			m_unk0x1c = p_float;
		}
	}

	if (m_unk0x0c == 1) {
		LegoAnimActor::VTable0x70(p_float);
	}
}

// FUNCTION: LEGO1 0x10080be0
// FUNCTION: BETA10 0x100cdc54
MxResult LegoCarRaceActor::VTable0x9c()
{
	MxS32 iVar4 = VTable0x1c(m_boundary, m_destEdge);

	if (iVar4) {
		SwitchBoundary(m_boundary, m_destEdge, m_unk0xe4);
		assert(m_boundary && m_destEdge);

		// variable names verified by BETA10
		Vector3* v1 = m_destEdge->CWVertex(*m_boundary);
		Vector3* v2 = m_destEdge->CCWVertex(*m_boundary);
		assert(v1 && v2);

		Mx3DPointFloat point1;
		point1[0] = (*v1)[0] + ((*v2)[0] - (*v1)[0]) * m_unk0xe4;
		point1[1] = (*v1)[1] + ((*v2)[1] - (*v1)[1]) * m_unk0xe4;
		point1[2] = (*v1)[2] + ((*v2)[2] - (*v1)[2]) * m_unk0xe4;

		Mx3DPointFloat point2;
		Mx3DPointFloat point3;
		Mx3DPointFloat point4;
		Mx3DPointFloat point5;

		m_destEdge->FUN_1002ddc0(*m_boundary, point2);
		m_destEdge->FUN_1002ddc0(*m_boundary, point3);

		point4.EqualsCross(&point2, m_boundary->GetUnknown0x14());
		point5.EqualsCross(m_boundary->GetUnknown0x14(), &point3);

		point4.Unitize();
		point5.Unitize();

		((Vector3*) &point4)->Mul(5.0f);
		((Vector3*) &point5)->Mul(5.0f);

		MxResult res = VTable0x80(Vector3(m_roi->GetWorldPosition()), point4, point1, point5);

#ifndef NDEBUG // BETA10 only
		if (res) {
			assert(0);
			return -1;
		}
#endif

		m_unk0x7c = 0;
	}


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
