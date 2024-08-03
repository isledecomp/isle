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
Mx3DPointFloat LegoRaceActor::g_unk0x10102b08 = Mx3DPointFloat(0.0, 2.0, 0.0);

// FUNCTION: LEGO1 0x100145d0
LegoRaceActor::LegoRaceActor()
{
	m_unk0x70 = 0;
	m_unk0x08 = 0;
}

// FUNCTION: LEGO1 0x10014750
// FUNCTION: BETA10 0x100c9bba
MxS32 LegoRaceActor::VTable0x68(Vector3& p_v1, Vector3& p_v2, Vector3& p_v3)
{
	MxS32 result = LegoPathActor::VTable0x68(p_v1, p_v2, p_v3);

	if (m_userNavFlag && result) {
		MxLong time = Timer()->GetTime();
		if (time - g_unk0x100f3308 > 1000) {
			g_unk0x100f3308 = time;
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
MxU32 LegoRaceActor::VTable0x90(float p_float, Matrix4& p_transform)
{
	// Note: Code duplication with LegoExtraActor::VTable0x90
	switch (m_state) {
	case 0:
	case 1:
		return 1;

	case 2:
		m_unk0x08 = p_float + 2000.0f;
		m_state = 3;
		m_actorTime += (p_float - m_lastTime) * m_worldSpeed;
		m_lastTime = p_float;
		return 0;

	case 3:
		assert(!m_userNavFlag);
		Vector3 positionRef(p_transform[3]);

		p_transform = m_roi->GetLocal2World();

		if (m_unk0x08 > p_float) {
			Mx3DPointFloat position;

			position = positionRef;
			positionRef.Clear();
			p_transform.RotateX(0.6);
			positionRef = position;

			m_actorTime += (p_float - m_lastTime) * m_worldSpeed;
			m_lastTime = p_float;

			VTable0x74(p_transform);
			return 0;
		}
		else {
			m_state = 0;
			m_unk0x08 = 0;

			((Vector3&) positionRef).Sub(g_unk0x10102b08);
			m_roi->FUN_100a58f0(p_transform);
			return 1;
		}
	}

	return 0;
}

// FUNCTION: LEGO1 0x10014a00
// FUNCTION: BETA10 0x100c9f5c
MxResult LegoRaceActor::VTable0x94(LegoPathActor* p_actor, MxBool p_bool)
{
	if (!p_actor->GetUserNavFlag()) {
		if (p_actor->GetState()) {
			return FAILURE;
		}

		if (p_bool) {
			LegoROI* roi = p_actor->GetROI(); // name verified by BETA10 0x100c9fcf
			assert(roi);
			MxMatrix matr;
			matr = roi->GetLocal2World();

			Vector3(matr[3]).Add(g_unk0x10102b08);

			roi->FUN_100a58f0(matr);

			p_actor->SetState(2);
		}
	}
	return 0;
}
