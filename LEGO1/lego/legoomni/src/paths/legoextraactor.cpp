#include "legoextraactor.h"

#include "anim/legoanim.h"
#include "legoanimpresenter.h"
#include "legocachesoundmanager.h"
#include "legosoundmanager.h"
#include "legoworld.h"
#include "misc.h"
#include "mxmisc.h"
#include "mxtimer.h"

DECOMP_SIZE_ASSERT(LegoExtraActor, 0x1dc)

// GLOBAL: LEGO1 0x100f31d0
LegoWorld* g_reassemblyAnimWorld = NULL;

// GLOBAL: LEGO1 0x100f31d4
LegoLocomotionAnimPresenter* m_assAnimP = NULL;

// GLOBAL: LEGO1 0x100f31d8
LegoLocomotionAnimPresenter* m_disAnimP = NULL;

// GLOBAL: LEGO1 0x100f31dc
MxS32 g_hitCounter = 0;

// GLOBAL: LEGO1 0x10104c18
Mx3DPointFloat g_unk0x10104c18 = Mx3DPointFloat(0.0f, 2.5f, 0.0f);

// FUNCTION: LEGO1 0x1002a500
// FUNCTION: BETA10 0x10080908
LegoExtraActor::LegoExtraActor()
{
	m_lastPathStruct = 0.0f;
	m_scheduledTime = 0;
	m_pathWalkingMode = 0;
	m_animationAtCurrentBoundary = FALSE;
	m_reassemblyAnimation = e_none;
	m_assAnim = NULL;
	m_disAnim = NULL;
	m_hitBlockCounter = 0;
}

// FUNCTION: LEGO1 0x1002a6b0
LegoExtraActor::~LegoExtraActor()
{
	delete m_assAnim;
	delete m_disAnim;
}

// FUNCTION: LEGO1 0x1002a720
MxU32 LegoExtraActor::StepState(float p_time, Matrix4& p_transform)
{
	switch (m_actorState & c_maxState) {
	case c_initial:
	case c_ready:
		return TRUE;
	case c_hit:
		m_scheduledTime = p_time + 2000.0f;
		m_actorState = c_hitAnimation;
		m_actorTime += (p_time - m_transformTime) * m_worldSpeed;
		m_transformTime = p_time;
		return FALSE;
	case c_hitAnimation: {
		Vector3 positionRef(p_transform[3]);
		p_transform = m_roi->GetLocal2World();

		if (p_time < m_scheduledTime) {
			Mx3DPointFloat position;
			position = positionRef;
			positionRef.Clear();

			switch (m_axis) {
			case e_posz: {
				p_transform.RotateZ(0.7f);
				break;
			}
			case e_negz: {
				p_transform.RotateZ(-0.7f);
				break;
			}
			case e_posx: {
				p_transform.RotateX(0.7f);
				break;
			}
			case e_negx: {
				p_transform.RotateX(-0.7f);
				break;
			}
			}

			positionRef = position;
			m_actorTime += (p_time - m_transformTime) * m_worldSpeed;
			m_transformTime = p_time;
			ApplyTransform(p_transform);
			return FALSE;
		}
		else {
			m_actorState = c_initial;
			m_scheduledTime = 0.0f;
			positionRef -= g_unk0x10104c18;
			m_roi->SetLocal2World(p_transform);
			return TRUE;
		}
	}

	default:
		return FALSE;
	}
}

// FUNCTION: LEGO1 0x1002aa90
void LegoExtraActor::GetWalkingBehavior(MxBool& p_countCounterclockWise, MxS32& p_selectedEdgeIndex)
{
	switch (m_pathWalkingMode) {
	case 1:
		p_countCounterclockWise = TRUE;
		p_selectedEdgeIndex = 1;
		break;
	case 2:
		p_countCounterclockWise = FALSE;
		p_selectedEdgeIndex = 1;
		break;
	default:
		p_countCounterclockWise = TRUE;
		p_selectedEdgeIndex = rand() % p_selectedEdgeIndex + 1;
		break;
	}
}

// FUNCTION: LEGO1 0x1002aae0
MxResult LegoExtraActor::SwitchDirection()
{
	LegoPathBoundary* oldEdge = m_boundary;
	Vector3 rightRef(m_local2World[0]);
	Vector3 upRef(m_local2World[1]);
	Vector3 dirRef(m_local2World[2]);
	Vector3 positionRef(m_local2World[3]);

	dirRef *= -1.0f;
	rightRef.EqualsCross(upRef, dirRef);

	if (m_boundary == m_destEdge->m_faceA) {
		m_boundary = (LegoPathBoundary*) m_destEdge->m_faceB;
	}
	else {
		m_boundary = (LegoPathBoundary*) m_destEdge->m_faceA;
	}

	if (!m_boundary) {
		m_boundary = oldEdge;
	}

	LegoPathActor::CalculateSpline();
	return SUCCESS;
}

inline void LegoExtraActor::InitializeReassemblyAnim()
{
	LegoWorld* w = CurrentWorld();

	if (g_reassemblyAnimWorld != w) {
		g_reassemblyAnimWorld = w;
		m_assAnimP = (LegoLocomotionAnimPresenter*) w->Find("LegoAnimPresenter", "BNsAss01");
		m_disAnimP = (LegoLocomotionAnimPresenter*) w->Find("LegoAnimPresenter", "BNsDis01");
	}

	if (!m_assAnim) {
		MxS32 index = 0;
		m_assAnimP->CreateROIAndBuildMap(this, -20.0f);

		for (MxS32 i = 0; i < m_animMaps.size(); i++) {
			if (m_animMaps[i]->GetWorldSpeed() == -20.0f) {
				m_assAnim = new LegoAnimActorStruct(*m_animMaps[i]);
				break;
			}
		}
	}

	if (!m_disAnim) {
		MxS32 index = 0;
		m_disAnimP->CreateROIAndBuildMap(this, -21.0f);

		for (MxS32 i = 0; i < m_animMaps.size(); i++) {
			if (m_animMaps[i]->GetWorldSpeed() == -21.0f) {
				m_disAnim = new LegoAnimActorStruct(*m_animMaps[i]);
				break;
			}
		}
	}
}

// FUNCTION: LEGO1 0x1002aba0
// FUNCTION: BETA10 0x1008114a
MxResult LegoExtraActor::HitActor(LegoPathActor* p_actor, MxBool p_bool)
{
	if (p_actor->GetActorState() != c_initial || GetActorState() != c_initial) {
		return FAILURE;
	}

	if (p_bool) {
		if (m_hitBlockCounter != 0) {
			return FAILURE;
		}

		m_hitBlockCounter = 100;
		SwitchDirection();
	}
	else {
		MxU32 b = FALSE;

		if (++g_hitCounter % 2 == 0) {
			MxMatrix otherActorLocal(p_actor->GetROI()->GetLocal2World());
			MxMatrix local(m_roi->GetLocal2World());

			m_localBeforeHit = local;
			Vector3 positionRef(local[3]);
			Mx3DPointFloat otherActorDir(otherActorLocal[2]);

			otherActorDir *= 2.0f;
			positionRef += otherActorDir;

			for (MxS32 i = 0; i < m_boundary->GetNumEdges(); i++) {
				Mx4DPointFloat* normal = m_boundary->GetEdgeNormal(i);

				if (positionRef.Dot(*normal, positionRef) + normal->index_operator(3) < -0.001) {
					b = TRUE;
					break;
				}
			}

			if (!b) {
				m_roi->SetLocal2World(local);
				m_roi->WrappedUpdateWorldData();
				InitializeReassemblyAnim();
				assert(m_roi);
				assert(SoundManager()->GetCacheSoundManager());
				SoundManager()->GetCacheSoundManager()->Play("crash5", m_roi->GetName(), FALSE);
				m_scheduledTime = Timer()->GetTime() + m_disAnim->GetDuration();
				m_prevWorldSpeed = GetWorldSpeed();
				VTable0xc4();
				SetWorldSpeed(0);
				m_reassemblyAnimation = e_disassemble;
				SetActorState(c_ready | c_noCollide);
			}
		}

		if (b) {
			LegoROI* roi = GetROI();
			assert(roi);
			SoundManager()->GetCacheSoundManager()->Play("crash5", m_roi->GetName(), FALSE);
			VTable0xc4();
			SetActorState(c_hit | c_noCollide);
			Mx3DPointFloat dir = p_actor->GetWorldDirection();
			MxMatrix matrix3 = MxMatrix(roi->GetLocal2World());
			Vector3 positionRef(matrix3[3]);
			positionRef += g_unk0x10104c18;
			roi->SetLocal2World(matrix3);

			float dotX = dir.Dot(dir, Mx3DPointFloat(1.0f, 0, 0));
			float dotZ = dir.Dot(dir, Mx3DPointFloat(0, 0, 1.0f));

			if (fabs(dotZ) < fabs(dotX)) {
				m_axis = dotX > 0.0 ? e_posz : e_negz;
			}
			else {
				m_axis = dotZ > 0.0 ? e_posx : e_negx;
			}
		}
	}

	return SUCCESS;
}

// FUNCTION: LEGO1 0x1002b290
MxResult LegoExtraActor::CalculateSpline()
{
	LegoPathBoundary* oldBoundary = m_boundary;
	MxResult result = LegoPathActor::CalculateSpline();

	if (m_boundary != oldBoundary) {
		MxU32 foundAnimation = FALSE;
		LegoAnimPresenterSet& presenters = m_boundary->GetPresenters();

		for (LegoAnimPresenterSet::iterator it = presenters.begin(); it != presenters.end(); it++) {
			MxU32 roiMapSize;
			if ((*it)->GetROIMap(roiMapSize)) {
				foundAnimation = TRUE;
				break;
			}
		}

		if (foundAnimation) {
			m_animationAtCurrentBoundary = TRUE;
			m_prevWorldSpeed = GetWorldSpeed();
			SetWorldSpeed(0);
		}
	}

	return result;
}

// FUNCTION: LEGO1 0x1002b370
void LegoExtraActor::Restart()
{
	if (m_animationAtCurrentBoundary != 0) {
		MxU32 foundAnimation = FALSE;
		LegoAnimPresenterSet& presenters = m_boundary->GetPresenters();

		for (LegoAnimPresenterSet::iterator it = presenters.begin(); it != presenters.end(); it++) {
			MxU32 roiMapSize;
			if ((*it)->GetROIMap(roiMapSize)) {
				foundAnimation = TRUE;
				break;
			}
		}

		if (!foundAnimation) {
			SetWorldSpeed(m_prevWorldSpeed);
			m_animationAtCurrentBoundary = FALSE;
		}
	}
}

// FUNCTION: LEGO1 0x1002b440
void LegoExtraActor::Animate(float p_time)
{
	LegoAnimActorStruct* laas = NULL;

	switch (m_reassemblyAnimation) {
	case e_none:
		LegoAnimActor::Animate(p_time);
		break;
	case e_disassemble:
		if (m_scheduledTime < p_time) {
			m_reassemblyAnimation = e_assemble;
			m_actorState = c_ready | c_noCollide;
			m_scheduledTime = m_assAnim->GetDuration() + p_time;
			break;
		}
		else {
			laas = m_disAnim;
			break;
		}
	case e_assemble:
		if (m_scheduledTime < p_time) {
			m_reassemblyAnimation = e_none;
			m_actorState = c_initial;
			SetWorldSpeed(m_prevWorldSpeed);
			m_roi->SetLocal2World(m_localBeforeHit);
			m_transformTime = p_time;
			break;
		}
		else {
			laas = m_assAnim;
			break;
		}
	}

	if (laas) {
		float duration2, duration;
		duration = laas->GetDuration();
		duration2 = p_time - (m_scheduledTime - duration);

		if (duration2 < 0) {
			duration2 = 0;
		}
		else if (duration2 > duration) {
			duration2 = duration;
		}

		MxMatrix matrix(m_roi->GetLocal2World());
		LegoTreeNode* root = laas->m_AnimTreePtr->GetRoot();
		MxS32 count = root->GetNumChildren();

		for (MxS32 i = 0; i < count; i++) {
			LegoROI::ApplyAnimationTransformation(root->GetChild(i), matrix, duration2, laas->m_roiMap);
		}
	}
}

// FUNCTION: LEGO1 0x1002b5d0
void LegoExtraActor::ApplyTransform(Matrix4& p_transform)
{
	if (m_reassemblyAnimation == e_none) {
		LegoAnimActor::ApplyTransform(p_transform);
	}
}

// FUNCTION: LEGO1 0x1002b5f0
void LegoExtraActor::SetWorldSpeed(MxFloat p_worldSpeed)
{
	if (m_curAnim == 0 && p_worldSpeed > 0) {
		VTable0xc4();
	}

	LegoAnimActor::SetWorldSpeed(p_worldSpeed);
}

// FUNCTION: LEGO1 0x1002b630
void LegoExtraActor::VTable0xc4()
{
	if (m_curAnim != 0) {
		return;
	}

	if (m_worldSpeed > -0.001 || m_worldSpeed < 0.001) {
		MxU16 name = *((MxU16*) m_roi->GetName());
		MxBool b = name == TWOCC('m', 'a') || name == TWOCC('p', 'a');

		if (b) {
			float duration = m_animMaps[m_curAnim]->GetDuration();
			MxMatrix matrix(m_local2World);
			LegoAnimActor::AnimateWithTransform(duration, matrix);
		}
	}
}

// FUNCTION: LEGO1 0x1002b6f0
MxS32 LegoExtraActor::CheckIntersections(Vector3& p_rayOrigin, Vector3& p_rayEnd, Vector3& p_intersectionPoint)
{
	return LegoPathActor::CheckIntersections(p_rayOrigin, p_rayEnd, p_intersectionPoint);
}

// FUNCTION: LEGO1 0x1002b980
inline MxU32 LegoExtraActor::CheckPresenterAndActorIntersections(
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

			if (this != actor && !(actor->GetActorState() & LegoPathActor::c_noCollide)) {
				LegoROI* roi = actor->GetROI();

				if ((roi != NULL && roi->GetVisibility()) || actor->GetCameraFlag()) {
					if (actor->GetUserNavFlag()) {
						MxMatrix local2world = roi->GetLocal2World();
						Vector3 local60(local2world[3]);
						Mx3DPointFloat local54(p_rayOrigin);

						local54 -= local60;
						float local1c = p_rayDirection.Dot(p_rayDirection, p_rayDirection);
						float local24 = p_rayDirection.Dot(p_rayDirection, local54) * 2.0f;
						float local20 = local54.Dot(local54, local54);

						if (m_hitBlockCounter != 0 && local20 < 10.0f) {
							return 0;
						}

						local20 -= 1.0f;

						if (local1c >= 0.001 || local1c <= -0.001) {
							float local40 = (local24 * local24) + (local20 * local1c * -4.0f);

							if (local40 >= -0.001) {
								local1c *= 2.0f;
								local24 = -local24;

								if (local40 < 0.0f) {
									local40 = 0.0f;
								}

								local40 = sqrt(local40);
								float local20X = (local24 + local40) / local1c;
								float local1cX = (local24 - local40) / local1c;

								if (local1cX < local20X) {
									local40 = local20X;
									local20X = local1cX;
									local1cX = local40;
								}

								if ((local20X >= 0.0f && local20X <= p_rayLength) ||
									(local1cX >= 0.0f && local1cX <= p_rayLength) ||
									(local20X <= -0.01 && p_rayLength + 0.01 <= local1cX)) {
									p_intersectionPoint = p_rayOrigin;

									if (HitActor(actor, TRUE) < 0) {
										return 0;
									}

									actor->HitActor(this, FALSE);
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
							if (HitActor(actor, TRUE) < 0) {
								return 0;
							}

							actor->HitActor(this, FALSE);
							return 2;
						}
					}
				}
			}
		}
	}

	if (m_hitBlockCounter != 0) {
		m_hitBlockCounter--;
	}

	return 0;
}
