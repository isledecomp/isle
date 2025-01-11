#include "legoextraactor.h"

#include "anim/legoanim.h"
#include "legocachesoundmanager.h"
#include "legolocomotionanimpresenter.h"
#include "legosoundmanager.h"
#include "legoworld.h"
#include "misc.h"
#include "mxmisc.h"
#include "mxtimer.h"

DECOMP_SIZE_ASSERT(LegoExtraActor, 0x1dc)

// GLOBAL: LEGO1 0x100f31d0
LegoWorld* g_unk0x100f31d0 = NULL;

// GLOBAL: LEGO1 0x100f31d4
LegoLocomotionAnimPresenter* m_assAnimP = NULL;

// GLOBAL: LEGO1 0x100f31d8
LegoLocomotionAnimPresenter* m_disAnimP = NULL;

// GLOBAL: LEGO1 0x100f31dc
MxS32 g_unk0x100f31dc = 0;

// GLOBAL: LEGO1 0x10104c18
Mx3DPointFloat g_unk0x10104c18 = Mx3DPointFloat(0.0f, 2.5f, 0.0f);

// FUNCTION: LEGO1 0x1002a500
// FUNCTION: BETA10 0x10080908
LegoExtraActor::LegoExtraActor()
{
	m_unk0x70 = 0.0f;
	m_scheduledTime = 0;
	m_unk0x0c = 0;
	m_unk0x0e = 0;
	m_whichAnim = 0;
	m_assAnim = NULL;
	m_disAnim = NULL;
	m_unk0x15 = 0;
}

// FUNCTION: LEGO1 0x1002a6b0
LegoExtraActor::~LegoExtraActor()
{
	delete m_assAnim;
	delete m_disAnim;
}

// FUNCTION: LEGO1 0x1002a720
MxU32 LegoExtraActor::VTable0x90(float p_time, Matrix4& p_transform)
{
	switch (m_actorState & c_maxState) {
	case c_initial:
	case c_one:
		return TRUE;
	case c_two:
		m_scheduledTime = p_time + 2000.0f;
		m_actorState = c_three;
		m_actorTime += (p_time - m_lastTime) * m_worldSpeed;
		m_lastTime = p_time;
		return FALSE;
	case c_three: {
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
			m_actorTime += (p_time - m_lastTime) * m_worldSpeed;
			m_lastTime = p_time;
			VTable0x74(p_transform);
			return FALSE;
		}
		else {
			m_actorState = c_initial;
			m_scheduledTime = 0.0f;
			positionRef -= g_unk0x10104c18;
			m_roi->FUN_100a58f0(p_transform);
			return TRUE;
		}
	}

	default:
		return FALSE;
	}
}

// FUNCTION: LEGO1 0x1002aa90
void LegoExtraActor::VTable0xa4(MxBool& p_und1, MxS32& p_und2)
{
	switch (m_unk0x0c) {
	case 1:
		p_und1 = TRUE;
		p_und2 = 1;
		break;
	case 2:
		p_und1 = FALSE;
		p_und2 = 1;
		break;
	default:
		p_und1 = TRUE;
		p_und2 = rand() % p_und2 + 1;
		break;
	}
}

// FUNCTION: LEGO1 0x1002aae0
MxResult LegoExtraActor::FUN_1002aae0()
{
	LegoPathBoundary* oldEdge = m_boundary;
	Vector3 rightRef(m_unk0xec[0]);
	Vector3 upRef(m_unk0xec[1]);
	Vector3 dirRef(m_unk0xec[2]);
	Vector3 positionRef(m_unk0xec[3]);

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

	LegoPathActor::VTable0x9c();
	return SUCCESS;
}

inline void LegoExtraActor::FUN_1002ad8a()
{
	LegoWorld* w = CurrentWorld();

	if (g_unk0x100f31d0 != w) {
		g_unk0x100f31d0 = w;
		m_assAnimP = (LegoLocomotionAnimPresenter*) w->Find("LegoAnimPresenter", "BNsAss01");
		m_disAnimP = (LegoLocomotionAnimPresenter*) w->Find("LegoAnimPresenter", "BNsDis01");
	}

	if (!m_assAnim) {
		MxS32 index = 0;
		m_assAnimP->FUN_1006d680(this, -20.0f);

		for (MxS32 i = 0; i < m_animMaps.size(); i++) {
			if (m_animMaps[i]->GetUnknown0x00() == -20.0f) {
				m_assAnim = new LegoAnimActorStruct(*m_animMaps[i]);
				break;
			}
		}
	}

	if (!m_disAnim) {
		MxS32 index = 0;
		m_disAnimP->FUN_1006d680(this, -21.0f);

		for (MxS32 i = 0; i < m_animMaps.size(); i++) {
			if (m_animMaps[i]->GetUnknown0x00() == -21.0f) {
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
		if (m_unk0x15 != 0) {
			return FAILURE;
		}

		m_unk0x15 = 100;
		FUN_1002aae0();
	}
	else {
		MxU32 b = FALSE;

		if (++g_unk0x100f31dc % 2 == 0) {
			MxMatrix matrix(p_actor->GetROI()->GetLocal2World());
			MxMatrix matrix2(m_roi->GetLocal2World());

			m_unk0x18 = matrix2;
			Vector3 positionRef(matrix2[3]);
			Mx3DPointFloat dir(matrix[2]);

			dir *= 2.0f;
			positionRef += dir;

			for (MxS32 i = 0; i < m_boundary->GetNumEdges(); i++) {
				Mx4DPointFloat* normal = m_boundary->GetEdgeNormal(i);

				if (positionRef.Dot(*normal, positionRef) + normal->index_operator(3) < -0.001) {
					b = TRUE;
					break;
				}
			}

			if (!b) {
				m_roi->FUN_100a58f0(matrix2);
				m_roi->VTable0x14();
				FUN_1002ad8a();
				assert(m_roi);
				assert(SoundManager()->GetCacheSoundManager());
				SoundManager()->GetCacheSoundManager()->Play("crash5", m_roi->GetName(), FALSE);
				m_scheduledTime = Timer()->GetTime() + m_disAnim->GetDuration();
				m_prevWorldSpeed = GetWorldSpeed();
				VTable0xc4();
				SetWorldSpeed(0);
				m_whichAnim = 1;
				SetActorState(c_one | c_noCollide);
			}
		}

		if (b) {
			LegoROI* roi = GetROI();
			assert(roi);
			SoundManager()->GetCacheSoundManager()->Play("crash5", m_roi->GetName(), FALSE);
			VTable0xc4();
			SetActorState(c_two | c_noCollide);
			Mx3DPointFloat dir = p_actor->GetWorldDirection();
			MxMatrix matrix3 = MxMatrix(roi->GetLocal2World());
			Vector3 positionRef(matrix3[3]);
			positionRef += g_unk0x10104c18;
			roi->FUN_100a58f0(matrix3);

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
MxResult LegoExtraActor::VTable0x9c()
{
	LegoPathBoundary* oldBoundary = m_boundary;
	MxResult result = LegoPathActor::VTable0x9c();

	if (m_boundary != oldBoundary) {
		MxU32 b = FALSE;
		LegoAnimPresenterSet& presenters = m_boundary->GetPresenters();

		for (LegoAnimPresenterSet::iterator it = presenters.begin(); it != presenters.end(); it++) {
			MxU32 roiMapSize;
			if ((*it)->GetROIMap(roiMapSize)) {
				b = TRUE;
				break;
			}
		}

		if (b) {
			m_unk0x0e = 1;
			m_prevWorldSpeed = GetWorldSpeed();
			SetWorldSpeed(0);
		}
	}

	return result;
}

// FUNCTION: LEGO1 0x1002b370
void LegoExtraActor::Restart()
{
	if (m_unk0x0e != 0) {
		MxU32 b = FALSE;
		LegoAnimPresenterSet& presenters = m_boundary->GetPresenters();

		for (LegoAnimPresenterSet::iterator it = presenters.begin(); it != presenters.end(); it++) {
			MxU32 roiMapSize;
			if ((*it)->GetROIMap(roiMapSize)) {
				b = TRUE;
				break;
			}
		}

		if (!b) {
			SetWorldSpeed(m_prevWorldSpeed);
			m_unk0x0e = 0;
		}
	}
}

// FUNCTION: LEGO1 0x1002b440
void LegoExtraActor::Animate(float p_time)
{
	LegoAnimActorStruct* laas = NULL;

	switch (m_whichAnim) {
	case 0:
		LegoAnimActor::Animate(p_time);
		break;
	case 1:
		if (m_scheduledTime < p_time) {
			m_whichAnim = 2;
			m_actorState = c_one | c_noCollide;
			m_scheduledTime = m_assAnim->GetDuration() + p_time;
			break;
		}
		else {
			laas = m_disAnim;
			break;
		}
	case 2:
		if (m_scheduledTime < p_time) {
			m_whichAnim = 0;
			m_actorState = c_initial;
			SetWorldSpeed(m_prevWorldSpeed);
			m_roi->FUN_100a58f0(m_unk0x18);
			m_lastTime = p_time;
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
			LegoROI::FUN_100a8e80(root->GetChild(i), matrix, duration2, laas->m_roiMap);
		}
	}
}

// FUNCTION: LEGO1 0x1002b5d0
void LegoExtraActor::VTable0x74(Matrix4& p_transform)
{
	if (m_whichAnim == 0) {
		LegoAnimActor::VTable0x74(p_transform);
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
			MxMatrix matrix(m_unk0xec);
			LegoAnimActor::FUN_1001c360(duration, matrix);
		}
	}
}

// FUNCTION: LEGO1 0x1002b6f0
MxS32 LegoExtraActor::VTable0x68(Vector3& p_point1, Vector3& p_point2, Vector3& p_point3)
{
	return LegoPathActor::VTable0x68(p_point1, p_point2, p_point3);
}
