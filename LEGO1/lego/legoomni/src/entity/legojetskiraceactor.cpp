#include "legojetskiraceactor.h"

#include "legonavcontroller.h"
#include "legopathcontroller.h"
#include "misc.h"
#include "mxmisc.h"
#include "mxvariabletable.h"

DECOMP_SIZE_ASSERT(LegoJetskiRaceActor, 0x1a8)

// GLOBAL: LEGO1 0x100da044
// GLOBAL: BETA10 0x101be9fc
const MxFloat g_eight = 8.0f;

// FUNCTION: LEGO1 0x10080ef0
// FUNCTION: BETA10 0x100a8990
LegoJetskiRaceActor::LegoJetskiRaceActor()
{
	m_unk0x10 = 0.95f;
	m_unk0x14 = 0.04f;
	m_unk0x18 = 0.5f;
	m_unk0x150 = 1.5f;
}

// FUNCTION: LEGO1 0x10081120
// FUNCTION: BETA10 0x100ce19f
MxS32 LegoJetskiRaceActor::VTable0x1c(LegoPathBoundary* p_boundary, LegoEdge* p_edge)
{
	// These are almost certainly not the correct names, but they produce the correct BETA10 stack
	Mx3DPointFloat a;
	Mx3DPointFloat bbb;
	Mx3DPointFloat c;

	// These names are verified by an assertion below
	Vector3* v1 = NULL;
	Vector3* v2 = NULL;

	if (m_state == 1) {
		if (m_destEdge == LegoPathController::GetControlEdgeA(13)) {
			m_boundary = (LegoPathBoundary*) m_destEdge->OtherFace(LegoPathController::GetControlBoundaryA(13));
		}
		else if (m_destEdge == LegoPathController::GetControlEdgeA(15)) {
			m_boundary = (LegoPathBoundary*) m_destEdge->OtherFace(LegoPathController::GetControlBoundaryA(15));
		}

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
		if (p_edge == LegoPathController::GetControlEdgeA(12)) {
			m_state = 1;

			if (m_worldSpeed < g_eight) {
				m_worldSpeed = g_eight;
			}

			m_destEdge = LegoPathController::GetControlEdgeA(13);
			m_boundary = LegoPathController::GetControlBoundaryA(13);
		}
		else if (p_edge == LegoPathController::GetControlEdgeA(14)) {
			m_state = 1;

			if (m_worldSpeed < g_eight) {
				m_worldSpeed = g_eight;
			}

			m_destEdge = LegoPathController::GetControlEdgeA(15);
			m_boundary = LegoPathController::GetControlBoundaryA(15);
		}

		if (m_state == 1) {
			if (m_userNavFlag) {
				m_unk0xe4 = 0.5f;
			}

			v1 = m_destEdge->CCWVertex(*m_boundary);
			v2 = m_destEdge->CWVertex(*m_boundary);
			assert(v1 && v2);

			a[0] = (*v1)[0] + ((*v2)[0] - (*v1)[0]) * m_unk0xe4;
			a[1] = (*v1)[1] + ((*v2)[1] - (*v1)[1]) * m_unk0xe4;
			a[2] = (*v1)[2] + ((*v2)[2] - (*v1)[2]) * m_unk0xe4;

			m_destEdge->FUN_1002ddc0(*m_boundary, bbb);
			c.EqualsCross(&bbb, m_boundary->GetUnknown0x14());
			c.Unitize();

			Mx3DPointFloat worldDirection(m_roi->GetWorldDirection());

			if (!m_userNavFlag) {
				((Vector2*) &worldDirection)->Mul(-1.0f);
			}

			if (VTable0x80(m_roi->GetWorldPosition(), worldDirection, a, c)) {
#ifdef NDEBUG
				m_unk0x7c = 0;
				return 0;
#else
				assert(0);
				return -1;
#endif
			}

			m_unk0x7c = 0;
			return 0;
		}
		else {
			return 1;
		}
	}
}

// FUNCTION: LEGO1 0x10081550
void LegoJetskiRaceActor::VTable0x70(float p_float)
{
	if (m_unk0x0c == 0) {
		const LegoChar* raceState = VariableTable()->GetVariable(g_raceState);
		if (stricmp(raceState, g_racing) == 0x0) {
			m_unk0x0c = 1;
			m_lastTime = p_float - 1.0f;
			m_unk0x1c = p_float;
		}
		else if (!m_userNavFlag) {
			LegoAnimActor::VTable0x70(m_lastTime + 1.0f);
		}
	}

	if (m_unk0x0c == 1) {
		LegoAnimActor::VTable0x70(p_float);
	}
}

// STUB: LEGO1 0x10081fd0
MxU32 LegoJetskiRaceActor::VTable0x6c(
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
