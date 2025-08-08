#include "legoracespecial.h"

#include "geom/legoorientededge.h"
#include "legonavcontroller.h"
#include "legopathboundary.h"
#include "legopathcontroller.h"
#include "misc.h"
#include "mxmisc.h"
#include "mxvariabletable.h"

#include <vec.h>

// File name verified by BETA10 0x100cedf7

DECOMP_SIZE_ASSERT(LegoCarRaceActor, 0x1a0)
DECOMP_SIZE_ASSERT(LegoJetskiRaceActor, 0x1a8)

// GLOBAL: LEGO1 0x100f0c68
// STRING: LEGO1 0x100f0c5c
// GLOBAL: BETA10 0x101f5b04
// STRING: BETA10 0x101f5b14
const char* g_raceState = "RACE_STATE";

// GLOBAL: LEGO1 0x100f7af0
// STRING: LEGO1 0x100f7ae4
const char* g_fuel = "FUEL";

// GLOBAL: LEGO1 0x100f0c6c
// STRING: LEGO1 0x100f0c54
// GLOBAL: BETA10 0x101f5b08
// STRING: BETA10 0x101f5b20
const char* g_racing = "RACING";

// GLOBAL: LEGO1 0x100f7aec
MxFloat LegoCarRaceActor::g_maxSpeed = 8.0f;

// GLOBAL: LEGO1 0x100da044
// GLOBAL: BETA10 0x101be9fc
MxFloat g_maxWorldSpeed = 8.0f;

// FUNCTION: LEGO1 0x10080350
// FUNCTION: BETA10 0x100cd6b0
LegoCarRaceActor::LegoCarRaceActor()
{
	m_unk0x08 = 1.0f;
	m_lastPathStruct = 0.0f;
	m_animState = 0;
	m_maxLinearVel = 0.0f;
	m_frequencyFactor = 1.0f;
	m_lastAcceleration = 0;
	m_curveSpeedFactor = 0.65f;
	m_acceleration = 0.03f;
	m_rubberBandFactor = 0.6f;
	m_wallHitDirectionFactor = 0.1f;
	m_linearRotationRatio = -5.0f;
	m_canRotate = 1;
	VariableTable()->SetVariable(g_fuel, "0.8");
}

// FUNCTION: LEGO1 0x10080590
// FUNCTION: BETA10 0x100cd8cf
void LegoCarRaceActor::UpdateWorldSpeed(float p_time)
{
	MxFloat maxSpeed = m_maxLinearVel;
	Mx3DPointFloat edgeNormal;
	Mx3DPointFloat worldDirection = Mx3DPointFloat(m_roi->GetWorldDirection());

	m_destEdge->GetFaceNormal(*m_boundary, edgeNormal);

	if (abs(edgeNormal.Dot(edgeNormal.GetData(), worldDirection.GetData())) > 0.5) {
		maxSpeed *= m_curveSpeedFactor;
	}

	MxS32 deltaPathStructs;
	LegoPathActor* userActor = UserActor();

	if (userActor) {
		// All known implementations of LegoPathActor->GetLastPathStruct() return LegoPathActor::m_lastPathStruct
		deltaPathStructs = m_lastPathStruct - userActor->GetLastPathStruct();
	}
	else {
		deltaPathStructs = 0;
	}

	if (deltaPathStructs > 1) {
		if (deltaPathStructs > 3) {
			deltaPathStructs = 3;
		}

		maxSpeed *= (m_rubberBandFactor * (--deltaPathStructs) * -0.25f + 1.0f);
	}
	else if (deltaPathStructs < -1) {
		maxSpeed *= 1.3;
	}

	MxFloat deltaSpeed = maxSpeed - m_worldSpeed;
	MxFloat changeInSpeed = (p_time - m_lastAcceleration) * m_acceleration;
	m_lastAcceleration = p_time;

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
MxS32 LegoCarRaceActor::HandleJump(LegoPathBoundary* p_boundary, LegoEdge* p_edge)
{
	Mx3DPointFloat targetPosition;
	Mx3DPointFloat destEdgeUnknownVector;
	Mx3DPointFloat targetDirection;

	if (m_actorState == c_ready) {
		m_boundary = NULL;

		// The first 12 elements are used for the car race, the other 4 for jetski
		// As it increments by 2, counting to 10 or 11 is the same.
		for (MxS32 i = 0; i < 11; i += 2) {
			if (LegoPathController::GetControlEdgeA(i + 1) == m_destEdge) {
				m_boundary = LegoPathController::GetControlBoundaryA(i + 1);
				break;
			}
		}

		assert(m_boundary);

		m_actorState = c_initial;
		m_traveledDistance = 0;

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
				m_actorState = c_ready;

				if (m_worldSpeed < g_maxSpeed) {
					m_worldSpeed = g_maxSpeed;
				}

				m_destEdge = LegoPathController::GetControlEdgeA(i + 1);
				m_boundary = LegoPathController::GetControlBoundaryA(i + 1);
				break;
			}
		}

		if (m_actorState == c_ready) {
			if (m_userNavFlag) {
				m_destScale = 0.5f;
			}

			// variable names verified by BETA10
			Vector3* v1 = m_destEdge->CCWVertex(*m_boundary);
			Vector3* v2 = m_destEdge->CWVertex(*m_boundary);
			assert(v1 && v2);

			LERP3(targetPosition, *v1, *v2, m_destScale);

			m_destEdge->GetFaceNormal(*m_boundary, destEdgeUnknownVector);

			targetDirection.EqualsCross(*m_boundary->GetUp(), destEdgeUnknownVector);
			targetDirection.Unitize();

			Mx3DPointFloat worldDirection(Vector3(m_roi->GetWorldDirection()));

			if (!m_userNavFlag) {
				worldDirection *= -1.0f;
			}

			worldDirection *= 5.0f;
			targetDirection *= 5.0f;

			MxResult callResult =
				SetSpline(Vector3(m_roi->GetWorldPosition()), worldDirection, targetPosition, targetDirection);

			if (callResult) {
				m_traveledDistance = 0;
				return 0;
			}
			else {
				m_traveledDistance = 0;
#ifdef BETA10
				assert(0);
#endif
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
void LegoCarRaceActor::SwitchBoundary(LegoPathBoundary*& p_boundary, LegoOrientedEdge*& p_edge, float& p_unk0xe4)
{
	LegoPathActor::SwitchBoundary(m_boundary, m_destEdge, m_destScale);
}

// FUNCTION: LEGO1 0x10080b70
// FUNCTION: BETA10 0x100cdbae
void LegoCarRaceActor::Animate(float p_time)
{
	// m_animState is not an MxBool, there are places where it is set to 2 or higher
	if (m_animState == 0) {
		const char* value = VariableTable()->GetVariable(g_raceState);

		if (strcmpi(value, g_racing) == 0) {
			m_animState = 1;
			m_transformTime = p_time - 1.0f;
			m_lastAcceleration = p_time;
		}
	}

	if (m_animState == 1) {
		LegoAnimActor::Animate(p_time);
	}
}

// FUNCTION: LEGO1 0x10080be0
// FUNCTION: BETA10 0x100cdc54
MxResult LegoCarRaceActor::CalculateSpline()
{
	LegoOrientedEdge* d = m_destEdge;

	if (HandleJump(m_boundary, m_destEdge)) {
		LegoPathBoundary* b = m_boundary;

		SwitchBoundary(m_boundary, m_destEdge, m_destScale);
		assert(m_boundary && m_destEdge);

		// variable names verified by BETA10
		Vector3* v1 = m_destEdge->CWVertex(*m_boundary);
		Vector3* v2 = m_destEdge->CCWVertex(*m_boundary);
		assert(v1 && v2);

		Mx3DPointFloat end;
		LERP3(end, *v1, *v2, m_destScale);

		Mx3DPointFloat startEdgeNormal;
		Mx3DPointFloat endEdgeNormal;
		Mx3DPointFloat startDirection;
		Mx3DPointFloat endDirection;

		d->GetFaceNormal(*b, startEdgeNormal);
		m_destEdge->GetFaceNormal(*m_boundary, endEdgeNormal);

		startDirection.EqualsCross(startEdgeNormal, *m_boundary->GetUp());
		endDirection.EqualsCross(*m_boundary->GetUp(), endEdgeNormal);

		startDirection.Unitize();
		endDirection.Unitize();

		startDirection *= 5.0f;
		endDirection *= 5.0f;

		MxResult res = SetSpline(m_roi->GetWorldPosition(), startDirection, end, endDirection);

#ifdef BETA10
		if (res) {
			assert(0);
			return -1;
		}
#endif

		m_traveledDistance = 0;
	}

	return SUCCESS;
}

// FUNCTION: LEGO1 0x10080ef0
// FUNCTION: BETA10 0x100a8990
LegoJetskiRaceActor::LegoJetskiRaceActor()
{
	m_curveSpeedFactor = 0.95f;
	m_acceleration = 0.04f;
	m_rubberBandFactor = 0.5f;
	m_linearRotationRatio = 1.5f;
}

// FUNCTION: LEGO1 0x10081120
// FUNCTION: BETA10 0x100ce19f
MxS32 LegoJetskiRaceActor::HandleJump(LegoPathBoundary* p_boundary, LegoEdge* p_edge)
{
	// These are almost certainly not the correct names, but they produce the correct BETA10 stack
	Mx3DPointFloat a;
	Mx3DPointFloat bbb;
	Mx3DPointFloat c;

	// These names are verified by an assertion below
	Vector3* v1 = NULL;
	Vector3* v2 = NULL;

	if (m_actorState == c_ready) {
		if (m_destEdge == LegoPathController::GetControlEdgeA(13)) {
			m_boundary = (LegoPathBoundary*) m_destEdge->OtherFace(LegoPathController::GetControlBoundaryA(13));
		}
		else if (m_destEdge == LegoPathController::GetControlEdgeA(15)) {
			m_boundary = (LegoPathBoundary*) m_destEdge->OtherFace(LegoPathController::GetControlBoundaryA(15));
		}

		m_actorState = c_initial;
		m_traveledDistance = 0;

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
			m_actorState = c_ready;

			if (m_worldSpeed < g_maxWorldSpeed) {
				m_worldSpeed = g_maxWorldSpeed;
			}

			m_destEdge = LegoPathController::GetControlEdgeA(13);
			m_boundary = LegoPathController::GetControlBoundaryA(13);
		}
		else if (p_edge == LegoPathController::GetControlEdgeA(14)) {
			m_actorState = c_ready;

			if (m_worldSpeed < g_maxWorldSpeed) {
				m_worldSpeed = g_maxWorldSpeed;
			}

			m_destEdge = LegoPathController::GetControlEdgeA(15);
			m_boundary = LegoPathController::GetControlBoundaryA(15);
		}

		if (m_actorState == c_ready) {
			if (m_userNavFlag) {
				m_destScale = 0.5f;
			}

			v1 = m_destEdge->CCWVertex(*m_boundary);
			v2 = m_destEdge->CWVertex(*m_boundary);
			assert(v1 && v2);

			LERP3(a, *v1, *v2, m_destScale);

			m_destEdge->GetFaceNormal(*m_boundary, bbb);
			c.EqualsCross(bbb, *m_boundary->GetUp());
			c.Unitize();

			Mx3DPointFloat worldDirection(m_roi->GetWorldDirection());

			if (!m_userNavFlag) {
				worldDirection *= -1.0f;
			}

			if (SetSpline(m_roi->GetWorldPosition(), worldDirection, a, c)) {
#ifndef BETA10
				m_traveledDistance = 0;
				return 0;
#else
				assert(0);
				return -1;
#endif
			}

			m_traveledDistance = 0;
			return 0;
		}
		else {
			return 1;
		}
	}
}

// FUNCTION: LEGO1 0x10081550
void LegoJetskiRaceActor::Animate(float p_time)
{
	if (m_animState == 0) {
		const LegoChar* raceState = VariableTable()->GetVariable(g_raceState);
		if (!stricmp(raceState, g_racing)) {
			m_animState = 1;
			m_transformTime = p_time - 1.0f;
			m_lastAcceleration = p_time;
		}
		else if (!m_userNavFlag) {
			LegoAnimActor::Animate(m_transformTime + 1.0f);
		}
	}

	if (m_animState == 1) {
		LegoAnimActor::Animate(p_time);
	}
}

// FUNCTION: LEGO1 0x10081840
// FUNCTION: BETA10 0x100cf680
inline MxU32 LegoCarRaceActor::CheckPresenterAndActorIntersections(
	LegoPathBoundary* p_boundary,
	Vector3& p_rayOrigin,
	Vector3& p_rayDirection,
	float p_rayLength,
	float p_radius,
	Vector3& p_intersectionPoint
)
{
	// STRING: LEGO1 0x100f7af4
	const char* str_rcdor = "rcdor";

	LegoAnimPresenterSet& presenters = p_boundary->GetPresenters();

	for (LegoAnimPresenterSet::iterator itap = presenters.begin(); itap != presenters.end(); itap++) {
		if ((*itap)->Intersect(p_rayOrigin, p_rayDirection, p_rayLength, p_radius, p_intersectionPoint)) {
			return 1;
		}
	}

	LegoPathActorSet& plpas = p_boundary->GetActors();
	LegoPathActorSet lpas(plpas);

	for (LegoPathActorSet::iterator itpa = lpas.begin(); itpa != lpas.end(); itpa++) {
		if (plpas.end() != plpas.find(*itpa)) {
			LegoPathActor* actor = *itpa;

			if (actor != this) {
				LegoROI* roi = actor->GetROI();

				if (roi != NULL && (roi->GetVisibility() || actor->GetCameraFlag())) {
					if (strncmp(roi->GetName(), str_rcdor, 5) == 0) {
						const CompoundObject* co = roi->GetComp(); // name verified by BETA10 0x100cf8ba

						if (co) {
							assert(co->size() == 2);

							LegoROI* firstROI = (LegoROI*) co->front();

							if (firstROI->Intersect(
									p_rayOrigin,
									p_rayDirection,
									p_rayLength,
									p_radius,
									p_intersectionPoint,
									m_collideBox && actor->GetCollideBox()
								)) {
								HitActor(actor, TRUE);

								if (actor->HitActor(this, FALSE) < 0) {
									return 0;
								}
								else {
									return 2;
								}
							}

							LegoROI* lastROI = (LegoROI*) co->back();

							if (lastROI->Intersect(
									p_rayOrigin,
									p_rayDirection,
									p_rayLength,
									p_radius,
									p_intersectionPoint,
									m_collideBox && actor->GetCollideBox()
								)) {
								HitActor(actor, TRUE);

								if (actor->HitActor(this, FALSE) < 0) {
									return 0;
								}
								else {
									return 2;
								}
							}
						}
					}
					else {
						if (roi->Intersect(
								p_rayOrigin,
								p_rayDirection,
								p_rayLength,
								p_radius,
								p_intersectionPoint,
								m_collideBox && actor->GetCollideBox()
							)) {
							HitActor(actor, TRUE);

							if (actor->HitActor(this, FALSE) < 0) {
								return 0;
							}
							else {
								return 2;
							}
						}
					}
				}
			}
		}
	}

	return 0;
}

// FUNCTION: LEGO1 0x10081fd0
inline MxU32 LegoJetskiRaceActor::CheckPresenterAndActorIntersections(
	LegoPathBoundary* p_boundary,
	Vector3& p_rayOrigin,
	Vector3& p_rayDirection,
	float p_rayLength,
	float p_radius,
	Vector3& p_intersectionPoint
)
{
	LegoAnimPresenterSet& presenters = p_boundary->GetPresenters();

	for (LegoAnimPresenterSet::iterator itap = presenters.begin(); itap != presenters.end(); itap++) {
		if ((*itap)->Intersect(p_rayOrigin, p_rayDirection, p_rayLength, p_radius, p_intersectionPoint)) {
			return 1;
		}
	}

	LegoPathActorSet& plpas = p_boundary->GetActors();
	LegoPathActorSet lpas(plpas);

	for (LegoPathActorSet::iterator itpa = lpas.begin(); itpa != lpas.end(); itpa++) {
		if (plpas.find(*itpa) != plpas.end()) {
			LegoPathActor* actor = *itpa;

			if (this != actor) {
				LegoROI* roi = actor->GetROI();

				if (roi != NULL && (roi->GetVisibility() || actor->GetCameraFlag())) {
					if (roi->Intersect(
							p_rayOrigin,
							p_rayDirection,
							p_rayLength,
							p_radius,
							p_intersectionPoint,
							m_collideBox && actor->GetCollideBox()
						)) {
						HitActor(actor, TRUE);

						if (actor->HitActor(this, FALSE) < 0) {
							return 0;
						}
						else {
							return 2;
						}
					}
				}
			}
		}
	}

	return 0;
}
