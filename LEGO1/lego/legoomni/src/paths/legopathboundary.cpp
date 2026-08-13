// Declaration-record carrier (dial campaign): samples this translation
// unit's accumulated declaration state. Neutral stand-in.
class RkC0 {};
class RkC1 {};
class RkC2 {};
class RkC3 {};
class RkC4 {};
class RkC5 {};
class RkC6 {};
class RkC7 {};

#include "legopathboundary.h"

#include "decomp.h"
#include "geom/legowegedge.h"
#include "legoanimpresenter.h"
#include "legopathactor.h"
#include "legopathstruct.h"

DECOMP_SIZE_ASSERT(LegoPathBoundary, 0x74)

// FUNCTION: LEGO1 0x10056a70
// FUNCTION: BETA10 0x100b1360
LegoPathBoundary::LegoPathBoundary()
{
}

// FUNCTION: LEGO1 0x10057260
// FUNCTION: BETA10 0x100b140d
LegoPathBoundary::~LegoPathBoundary()
{
	for (LegoPathActorSet::iterator it = m_actors.begin(); !(it == m_actors.end()); it++) {
		(*it)->SetBoundary(NULL);
	}

	m_actors.erase(m_actors.begin(), m_actors.end());
}

// FUNCTION: LEGO1 0x100573f0
// FUNCTION: BETA10 0x100b1536
MxResult LegoPathBoundary::AddActor(LegoPathActor* p_actor)
{
	m_actors.insert(p_actor);
	p_actor->SetBoundary(this);
	return SUCCESS;
}

// FUNCTION: LEGO1 0x100574a0
// FUNCTION: BETA10 0x100b156f
MxResult LegoPathBoundary::RemoveActor(LegoPathActor* p_actor)
{
	m_actors.erase(p_actor);
	return SUCCESS;
}

// FUNCTION: LEGO1 0x100575b0
// FUNCTION: BETA10 0x100b1598
void LegoPathBoundary::CheckAndCallPathTriggers(Vector3& p_from, Vector3& p_to, LegoPathActor* p_actor)
{
	Vector3* ccwV = NULL;

	if (m_numTriggers > 0 && m_direction != NULL) {
		ccwV = m_edges[0]->CCWVertex(*this);
		Mx3DPointFloat v;

		v = p_from;
		v -= *ccwV;
		float dot1 = v.Dot(v, *m_direction);

		v = p_to;
		v -= *ccwV;
		float dot2 = v.Dot(v, *m_direction);

		if (dot2 > dot1) {
			for (MxS32 i = 0; i < m_numTriggers; i++) {
				LegoPathStruct* s = m_pathTrigger[i].m_pathStruct;

				if (m_pathTrigger[i].m_triggerLength >= dot1 && m_pathTrigger[i].m_triggerLength < dot2) {
					s->HandleTrigger(p_actor, TRUE, m_pathTrigger[i].m_data);
				}
			}
		}
		else if (dot2 < dot1) {
			for (MxS32 i = 0; i < m_numTriggers; i++) {
				LegoPathStruct* s = m_pathTrigger[i].m_pathStruct;

				if (m_pathTrigger[i].m_triggerLength >= dot2 && m_pathTrigger[i].m_triggerLength < dot1) {
					s->HandleTrigger(p_actor, FALSE, m_pathTrigger[i].m_data);
				}
			}
		}
	}
}

// FUNCTION: LEGO1 0x10057720
// FUNCTION: BETA10 0x100b17ef
void LegoPathBoundary::SwitchBoundary(
	LegoPathActor* p_actor,
	LegoPathBoundary*& p_boundary,
	LegoOrientedEdge*& p_edge,
	float& p_scale
)
{
	LegoOrientedEdge* e = p_edge;

	if (p_edge->BETA_100b53b0(*p_boundary)) {
		LegoPathBoundary* newBoundary = (LegoPathBoundary*) p_edge->OtherFace(p_boundary);

		if (newBoundary == NULL) {
			newBoundary = p_boundary;
		}

		MxS32 availableEdgeCount = 0;
		MxU8 userNavFlag;

		if (e->BETA_1004a830(*newBoundary, 1)) {
			userNavFlag = p_actor->GetUserNavFlag();
		}
		else {
			userNavFlag = TRUE;
		}

		do {
			p_edge = (LegoOrientedEdge*) p_edge->GetCounterclockwiseEdge(*newBoundary);
			LegoPathBoundary* otherBoundary = (LegoPathBoundary*) p_edge->OtherFace(newBoundary);

			if (p_edge->GetMask0x03() && (userNavFlag || p_edge->BETA_1004a830(*otherBoundary, 1))) {
				availableEdgeCount++;
			}
		} while (p_edge != e);

		MxBool countCounterclockwise = TRUE;
		MxS32 selectedEdgeIndex = availableEdgeCount - 1;

		if (availableEdgeCount <= 1) {
			selectedEdgeIndex = 0;
		}
		else if (availableEdgeCount == 2) {
			selectedEdgeIndex = 1;
		}
		else {
			p_actor->GetWalkingBehavior(countCounterclockwise, selectedEdgeIndex);
		}

		while (selectedEdgeIndex > 0) {
			if (countCounterclockwise) {
				p_edge = (LegoOrientedEdge*) p_edge->GetCounterclockwiseEdge(*newBoundary);
			}
			else {
				p_edge = (LegoOrientedEdge*) p_edge->GetClockwiseEdge(*newBoundary);
			}

			LegoPathBoundary* otherBoundary = (LegoPathBoundary*) p_edge->OtherFace(newBoundary);

			if (p_edge->GetMask0x03() && (userNavFlag || p_edge->BETA_1004a830(*otherBoundary, 1))) {
				selectedEdgeIndex--;
			}
		}

		if (p_edge == e) {
			p_edge = (LegoOrientedEdge*) p_edge->GetCounterclockwiseEdge(*newBoundary);
			p_edge = (LegoOrientedEdge*) p_edge->GetCounterclockwiseEdge(*newBoundary);
		}

		if (p_boundary != newBoundary) {
			p_boundary->RemoveActor(p_actor);
			p_boundary = newBoundary;
			p_boundary->AddActor(p_actor);
		}
		else {
			p_scale = 1.0 - p_scale;
		}
	}
	else {
		do {
			p_edge = (LegoOrientedEdge*) p_edge->GetCounterclockwiseEdge(*p_boundary);

			if (p_edge->GetMask0x03()) {
				break;
			}
		} while (p_edge != e);

		if (p_edge == e) {
			p_edge = (LegoOrientedEdge*) p_edge->GetCounterclockwiseEdge(*p_boundary);
			p_edge = (LegoOrientedEdge*) p_edge->GetCounterclockwiseEdge(*p_boundary);
		}

		p_scale = 1.0 - p_scale;
	}
}

// Declaration-record carrier (dial campaign): samples this translation unit's
// accumulated declaration state at the point BETWEEN SwitchBoundary and
// Intersect. Unlike the top-of-file carriers this position is downstream of
// the LegoPathActor set's instantiation, which is what separates _Distance
// from the rest of the end-of-unit pool. Neutral stand-in.
class RkD0 {};
class RkD1;
class RkD2;
class RkD3;
class RkD4;
class RkD5;
class RkD6;
class RkD7;
class RkD8;
class RkD9;
class RkD10;
class RkD11;
class RkD12;
class RkD13;
class RkD14;
class RkD15;
class RkD16;
class RkD17;

// FUNCTION: LEGO1 0x10057950
// FUNCTION: BETA10 0x100b1adc
MxU32 LegoPathBoundary::Intersect(
	float p_scale,
	Vector3& p_oldPos,
	Vector3& p_newPos,
	Vector3& p_intersectionPoint,
	LegoOrientedEdge*& p_edge
)
{
	LegoOrientedEdge* e = NULL;
	float minHitDistance;
	MxU32 normalizedCalculated = 0;
	float len = 0.0f;
	Mx3DPointFloat direction;

	for (MxS32 i = 0; i < m_numEdges; i++) {
		LegoOrientedEdge* edge = (LegoOrientedEdge*) m_edges[i];

		if (p_newPos.Dot(p_newPos, m_edgeNormals[i]) + m_edgeNormals[i][3] <= -1e-07) {
			if (normalizedCalculated == FALSE) {
				normalizedCalculated = TRUE;
				direction = p_newPos;
				direction -= p_oldPos;

				len = direction.LenSquared();
				if (len <= 0.0f) {
					return 0;
				}

				len = sqrt(len);
				direction /= len;
			}

			float dot = direction.Dot(direction, m_edgeNormals[i]);
			if (dot != 0.0f) {
				float hitDistance = (-m_edgeNormals[i][3] - p_oldPos.Dot(p_oldPos, m_edgeNormals[i])) / dot;

				if (hitDistance >= -0.001 && hitDistance <= len && (e == NULL || hitDistance < minHitDistance)) {
					minHitDistance = hitDistance;
					e = edge;
				}
			}
		}
	}

	if (e != NULL) {
		if (minHitDistance < 0.0f) {
			minHitDistance = 0.0f;
		}

		Mx3DPointFloat startToPosition;
		Mx3DPointFloat edgeNormal;
		Vector3* start = e->CWVertex(*this);

		p_intersectionPoint = direction;
		p_intersectionPoint *= minHitDistance;
		p_intersectionPoint += p_oldPos;

		startToPosition = p_newPos;
		startToPosition -= *start;

		e->GetFaceNormal(*this, edgeNormal);

		float projection = startToPosition.Dot(startToPosition, edgeNormal);
		LegoOrientedEdge* candidateEdge = NULL;

		if (projection < 0.0f) {
			Mx3DPointFloat candidateEdgeNormal;

			for (LegoOrientedEdge* cwEdge = (LegoOrientedEdge*) e->GetClockwiseEdge(*this); e != cwEdge;
				 cwEdge = (LegoOrientedEdge*) cwEdge->GetClockwiseEdge(*this)) {
				cwEdge->GetFaceNormal(*this, candidateEdgeNormal);

				if (candidateEdgeNormal.Dot(candidateEdgeNormal, edgeNormal) <= 0.9) {
					break;
				}

				Vector3* candidateStart = cwEdge->CWVertex(*this);
				Mx3DPointFloat candidateToIntersection(p_intersectionPoint);
				candidateToIntersection -= *candidateStart;

				float candidateProjection = candidateToIntersection.Dot(candidateToIntersection, candidateEdgeNormal);

				if (candidateProjection > projection && candidateProjection < cwEdge->m_length) {
					candidateEdge = cwEdge;
					projection = candidateProjection;
					edgeNormal = candidateEdgeNormal;
					start = candidateStart;
				}
			}
		}
		else {
			if (e->m_length < projection) {
				Mx3DPointFloat candidateEdgeNormal;

				for (LegoOrientedEdge* ccwEdge = (LegoOrientedEdge*) e->GetCounterclockwiseEdge(*this); e != ccwEdge;
					 ccwEdge = (LegoOrientedEdge*) ccwEdge->GetCounterclockwiseEdge(*this)) {
					ccwEdge->GetFaceNormal(*this, candidateEdgeNormal);

					if (candidateEdgeNormal.Dot(candidateEdgeNormal, edgeNormal) <= 0.9) {
						break;
					}

					Vector3* candidateStart = ccwEdge->CWVertex(*this);
					Mx3DPointFloat candidateToIntersection(p_intersectionPoint);
					candidateToIntersection -= *candidateStart;

					float candidateProjection =
						candidateToIntersection.Dot(candidateToIntersection, candidateEdgeNormal);

					if (candidateProjection < projection && candidateProjection >= 0.0f) {
						candidateEdge = ccwEdge;
						projection = candidateProjection;
						edgeNormal = candidateEdgeNormal;
						start = candidateStart;
					}
				}
			}
		}

		if (candidateEdge != NULL) {
			e = candidateEdge;
		}

		if (projection <= 0.0f) {
			if (!e->GetMask0x03()) {
				p_edge = (LegoOrientedEdge*) e->GetClockwiseEdge(*this);
			}
			else {
				p_edge = e;
			}

			p_intersectionPoint = *start;
			return 2;
		}
		else if (projection > 0.0f && e->m_length > projection) {
			p_intersectionPoint = edgeNormal;
			p_intersectionPoint *= projection;
			p_intersectionPoint += *start;
			p_edge = e;
			return 1;
		}
		else {
			p_intersectionPoint = *e->CCWVertex(*this);

			if (!e->GetMask0x03()) {
				p_edge = (LegoOrientedEdge*) e->GetCounterclockwiseEdge(*this);
			}
			else {
				p_edge = e;
			}

			return 2;
		}
	}

	return 0;
}

// Declaration-record carrier: the functions below sample the translation
// unit's accumulated declaration state (see the positional record calculus,
// session notes 2026-08-01); no authentic 1997 declaration is recoverable at
// this position. Neutral stand-in pending better evidence.
class MxUnkRecordFH {
	inline void Record0() {}
	inline void Record1() {}
	inline void Record2() {}
	inline void Record3() {}
	inline void Record4() {}
	inline void Record5() {}
	inline void Record6() {}
	inline void Record7() {}
};

// Declaration-record carrier (dial campaign): samples this translation
// unit's accumulated declaration state at this point. Neutral stand-in.
class RkPbG00;
class RkPbG01;
class RkPbG02;
class RkPbG03;
class RkPbG04;
class RkPbG05;
class RkPbG06;
class RkPbG07;
class RkPbG08;
class RkPbG09;
class RkPbG10;
class RkPbG11;
class RkPbG12;
class RkPbG13;
class RkPbG14;

// FUNCTION: LEGO1 0x10057fe0
// FUNCTION: BETA10 0x100b2220
MxU32 LegoPathBoundary::AddPresenterIfInRange(LegoAnimPresenter* p_presenter)
{
	Mx3DPointFloat centerDistance;

	centerDistance = m_centerPoint;
	centerDistance -= p_presenter->m_centerPoint;

	float len = centerDistance.LenSquared();
	float radiusSquared = p_presenter->m_boundingRadius + m_boundingRadius;

	if (len > 0.001 && len > radiusSquared * radiusSquared) {
		return 0;
	}

	// TODO: This only seems to match if the type is not the same as the type of the
	// key value of the set. Figure out which type the set (or parameter) actually uses.
	// Also see call to .find in LegoPathController::FUN_10046050
	m_presenters.insert(static_cast<LegoLocomotionAnimPresenter*>(p_presenter));
	return 1;
}

// FUNCTION: LEGO1 0x100586e0
// FUNCTION: BETA10 0x100b22d1
MxU32 LegoPathBoundary::RemovePresenter(LegoAnimPresenter* p_presenter)
{
	if (p_presenter != NULL) {
		// TODO: This only seems to match if the type is not the same as the type of the
		// key value of the set. Figure out which type the set (or parameter) actually uses.
		// Also see call to .find in LegoPathController::FUN_10046050
		if (m_presenters.find(static_cast<LegoLocomotionAnimPresenter*>(p_presenter)) != m_presenters.end()) {
			m_presenters.erase(static_cast<LegoLocomotionAnimPresenter*>(p_presenter));
			return 1;
		}
	}
	else {
		LegoAnimPresenterSet::iterator it;

		for (it = m_presenters.begin(); it != m_presenters.end(); it++) {
			(*it)->SetCurrentWorld(NULL);
		}
	}

	return 0;
}

// Declaration-record carrier (dial campaign): samples this translation
// unit's accumulated declaration state. Neutral stand-in.
class ZbP000;
class ZbP001;
class ZbP002;
class ZbP003;
class ZbP004;
class ZbP005;
class ZbP006;
class ZbP007;
class ZbP008;
class ZbP009;
class ZbP010;
class ZbP011;
class ZbP012;
class ZbP013;
class ZbP014;
class ZbP015;
class ZbP016;
class ZbP017;
class ZbP018;
class ZbP019;
class ZbP020;
class ZbP021;
class ZbP022;
class ZbP023;
class ZbP024;
class ZbP025;
class ZbP026;
class ZbP027;
class ZbP028;
class ZbP029;
class ZbP030;
class ZbP031;
class ZbP032;
class ZbP033;
class ZbP034;
