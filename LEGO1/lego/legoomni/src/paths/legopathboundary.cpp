#include "legopathboundary.h"

#include "decomp.h"
#include "geom/legoorientededge.h"
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
	float& p_unk0xe4
)
{
	LegoOrientedEdge* e = p_edge;

	if (p_edge->BETA_100b53b0(*p_boundary)) {
		LegoPathBoundary* newBoundary = (LegoPathBoundary*) p_edge->OtherFace(p_boundary);

		if (newBoundary == NULL) {
			newBoundary = p_boundary;
		}

		MxS32 local10 = 0;
		MxU8 userNavFlag;

		if (e->BETA_1004a830(*newBoundary, 1)) {
			userNavFlag = p_actor->GetUserNavFlag();
		}
		else {
			userNavFlag = TRUE;
		}

		do {
			p_edge = (LegoOrientedEdge*) p_edge->GetCounterclockwiseEdge(*newBoundary);
			LegoPathBoundary* local20 = (LegoPathBoundary*) p_edge->OtherFace(newBoundary);

			if (p_edge->GetMask0x03() && (userNavFlag || p_edge->BETA_1004a830(*local20, 1))) {
				local10++;
			}
		} while (p_edge != e);

		MxBool localc = TRUE;
		MxS32 local8 = local10 - 1;

		if (local10 <= 1) {
			local8 = 0;
		}
		else if (local10 == 2) {
			local8 = 1;
		}
		else {
			p_actor->VTable0xa4(localc, local8);
		}

		while (local8 > 0) {
			if (localc) {
				p_edge = (LegoOrientedEdge*) p_edge->GetCounterclockwiseEdge(*newBoundary);
			}
			else {
				p_edge = (LegoOrientedEdge*) p_edge->GetClockwiseEdge(*newBoundary);
			}

			LegoPathBoundary* local20 = (LegoPathBoundary*) p_edge->OtherFace(newBoundary);

			if (p_edge->GetMask0x03() && (userNavFlag || p_edge->BETA_1004a830(*local20, 1))) {
				local8--;
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
			p_unk0xe4 = 1.0 - p_unk0xe4;
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

		p_unk0xe4 = 1.0 - p_unk0xe4;
	}
}

// FUNCTION: LEGO1 0x10057950
// FUNCTION: BETA10 0x100b1adc
MxU32 LegoPathBoundary::Intersect(
	float p_scale,
	Vector3& p_point1,
	Vector3& p_point2,
	Vector3& p_point3,
	LegoOrientedEdge*& p_edge
)
{
	LegoOrientedEdge* e = NULL;
	float localc;
	MxU32 local10 = 0;
	float len = 0.0f;
	Mx3DPointFloat vec;

	for (MxS32 i = 0; i < m_numEdges; i++) {
		LegoOrientedEdge* edge = (LegoOrientedEdge*) m_edges[i];

		if (p_point2.Dot(m_edgeNormals[i], p_point2) + m_edgeNormals[i][3] <= -1e-07) {
			if (local10 == 0) {
				local10 = 1;
				vec = p_point2;
				vec -= p_point1;

				len = vec.LenSquared();
				if (len <= 0.0f) {
					return 0;
				}

				len = sqrt(len);
				vec /= len;
			}

			float dot = vec.Dot(vec, m_edgeNormals[i]);
			if (dot != 0.0f) {
				float local34 = (-m_edgeNormals[i][3] - p_point1.Dot(p_point1, m_edgeNormals[i])) / dot;

				if (local34 >= -0.001 && local34 <= len && (e == NULL || local34 < localc)) {
					e = edge;
					localc = local34;
				}
			}
		}
	}

	if (e != NULL) {
		if (localc < 0.0f) {
			localc = 0.0f;
		}

		Mx3DPointFloat local50;
		Mx3DPointFloat local70;
		Vector3* local5c = e->CWVertex(*this);

		p_point3 = vec;
		p_point3 *= localc;
		p_point3 += p_point1;

		local50 = p_point2;
		local50 -= *local5c;

		e->GetFaceNormal(*this, local70);

		float local58 = local50.Dot(local50, local70);
		LegoOrientedEdge* local54 = NULL;

		if (local58 < 0.0f) {
			Mx3DPointFloat local84;

			for (LegoOrientedEdge* local88 = (LegoOrientedEdge*) e->GetClockwiseEdge(*this); e != local88;
				 local88 = (LegoOrientedEdge*) local88->GetClockwiseEdge(*this)) {
				local88->GetFaceNormal(*this, local84);

				if (local84.Dot(local84, local70) <= 0.9) {
					break;
				}

				Vector3* local90 = local88->CWVertex(*this);
				Mx3DPointFloat locala4(p_point3);
				locala4 -= *local90;

				float local8c = locala4.Dot(locala4, local84);

				if (local8c > local58 && local8c < local88->m_length) {
					local54 = local88;
					local58 = local8c;
					local70 = local84;
					local5c = local90;
				}
			}
		}
		else {
			if (e->m_length < local58) {
				Mx3DPointFloat localbc;

				for (LegoOrientedEdge* locala8 = (LegoOrientedEdge*) e->GetCounterclockwiseEdge(*this); e != locala8;
					 locala8 = (LegoOrientedEdge*) locala8->GetCounterclockwiseEdge(*this)) {
					locala8->GetFaceNormal(*this, localbc);

					if (localbc.Dot(localbc, local70) <= 0.9) {
						break;
					}

					Vector3* localc4 = locala8->CWVertex(*this);
					Mx3DPointFloat locald8(p_point3);
					locald8 -= *localc4;

					float localc0 = locald8.Dot(locald8, localbc);

					if (localc0 < local58 && localc0 >= 0.0f) {
						local54 = locala8;
						local58 = localc0;
						local70 = localbc;
						local5c = localc4;
					}
				}
			}
		}

		if (local54 != NULL) {
			e = local54;
		}

		if (local58 <= 0.0f) {
			if (!e->GetMask0x03()) {
				p_edge = (LegoOrientedEdge*) e->GetClockwiseEdge(*this);
			}
			else {
				p_edge = e;
			}

			p_point3 = *local5c;
			return 2;
		}
		else if (local58 > 0.0f && e->m_length > local58) {
			p_point3 = local70;
			p_point3 *= local58;
			p_point3 += *local5c;
			p_edge = e;
			return 1;
		}
		else {
			p_point3 = *e->CCWVertex(*this);

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
		for (LegoAnimPresenterSet::iterator it = m_presenters.begin(); it != m_presenters.end(); it++) {
			(*it)->SetCurrentWorld(NULL);
		}
	}

	return 0;
}
