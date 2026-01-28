#include "legoraceactor.h"

#include "define.h"
#include "legocachesoundmanager.h"
#include "legosoundmanager.h"
#include "misc.h"
#include "mxmisc.h"
#include "mxtimer.h"
#include "mxvariabletable.h"
#include "roi/legoroi.h"

DECOMP_SIZE_ASSERT(LegoRaceActor, 0x180)

// Initialized at LEGO1 0x100145a0
// GLOBAL: LEGO1 0x10102b08
// GLOBAL: BETA10 0x102114a8
Mx3DPointFloat LegoRaceActor::g_unk0x10102b08 = Mx3DPointFloat(0.0, 2.0, 0.0);

// FUNCTION: LEGO1 0x100145d0
LegoRaceActor::LegoRaceActor()
{
	m_lastPathStruct = 0;
	m_unk0x08 = 0;
}

// FUNCTION: LEGO1 0x10014750
// FUNCTION: BETA10 0x100c9bba
MxS32 LegoRaceActor::CheckIntersections(Vector3& p_rayOrigin, Vector3& p_rayEnd, Vector3& p_intersectionPoint)
{
	MxS32 result = LegoPathActor::CheckIntersections(p_rayOrigin, p_rayEnd, p_intersectionPoint);

	if (m_userNavFlag && result) {
		MxLong time = Timer()->GetTime();
		if (time - g_timeLastHitSoundPlayed > 1000) {
			g_timeLastHitSoundPlayed = time;
			const char* soundKey = VariableTable()->GetVariable(g_strHIT_ACTOR_SOUND);

			if (soundKey && *soundKey) {
				SoundManager()->GetCacheSoundManager()->Play(soundKey, NULL, FALSE);
			}
		}
	}

	return result;
}

// FUNCTION: LEGO1 0x100147f0
// FUNCTION: BETA10 0x100c9c93
MxU32 LegoRaceActor::StepState(float p_time, Matrix4& p_transform)
{
	// Note: Code duplication with LegoExtraActor::StepState
	switch (m_actorState) {
	case c_initial:
	case c_ready:
		return TRUE;
	case c_hit:
		m_unk0x08 = p_time + 2000.0f;
		m_actorState = c_hitAnimation;
		m_actorTime += (p_time - m_transformTime) * m_worldSpeed;
		m_transformTime = p_time;
		return FALSE;
	case c_hitAnimation:
		assert(!m_userNavFlag);
		Vector3 positionRef(p_transform[3]);

		p_transform = m_roi->GetLocal2World();

		if (m_unk0x08 > p_time) {
			Mx3DPointFloat position;

			position = positionRef;
			positionRef.Clear();
			p_transform.RotateX(0.6);
			positionRef = position;

			m_actorTime += (p_time - m_transformTime) * m_worldSpeed;
			m_transformTime = p_time;

			ApplyTransform(p_transform);
			return FALSE;
		}
		else {
			m_actorState = c_initial;
			m_unk0x08 = 0;

			positionRef -= g_unk0x10102b08;
			m_roi->SetLocal2World(p_transform);
			return TRUE;
		}
	}

	return FALSE;
}

// FUNCTION: LEGO1 0x10014a00
// FUNCTION: BETA10 0x100c9f5c
MxResult LegoRaceActor::HitActor(LegoPathActor* p_actor, MxBool p_bool)
{
	if (!p_actor->GetUserNavFlag()) {
		if (p_actor->GetActorState() != c_initial) {
			return FAILURE;
		}

		if (p_bool) {
			MxMatrix matr;
			LegoROI* roi = p_actor->GetROI(); // name verified by BETA10 0x100c9fcf
			assert(roi);
			matr = roi->GetLocal2World();

			Vector3(matr[3]) += g_unk0x10102b08;

			roi->SetLocal2World(matr);

			p_actor->SetActorState(c_hit);
		}
	}

	return SUCCESS;
}

// FUNCTION: LEGO1 0x10014aa0
// FUNCTION: BETA10 0x100ca038
MxResult LegoRaceActor::FUN_10014aa0()
{
	return SUCCESS;
}
