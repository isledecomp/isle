#include "act3actors.h"

#include "roi/legoroi.h"

DECOMP_SIZE_ASSERT(Act3Actor, 0x178)

// Initialized at LEGO1 0x1003fa20
// GLOBAL: LEGO1 0x10104ef0
Mx3DPointFloat Act3Actor::g_unk0x10104ef0 = Mx3DPointFloat(0.0, 5.0, 0.0);

// FUNCTION: LEGO1 0x1003fa50
Act3Actor::Act3Actor()
{
	m_unk0x1c = 0;
}

// FUNCTION: LEGO1 0x1003fb70
MxU32 Act3Actor::VTable0x90(float p_time, Matrix4& p_transform)
{
	// Note: Code duplication with LegoExtraActor::VTable0x90
	switch (m_state & 0xff) {
	case 0:
	case 1:
		return TRUE;
	case 2:
		m_unk0x1c = p_time + 2000.0f;
		m_state = 3;
		m_actorTime += (p_time - m_lastTime) * m_worldSpeed;
		m_lastTime = p_time;
		return FALSE;
	case 3:
		assert(!m_userNavFlag);
		Vector3 positionRef(p_transform[3]);

		p_transform = m_roi->GetLocal2World();

		if (m_unk0x1c > p_time) {
			Mx3DPointFloat position;

			position = positionRef;
			positionRef.Clear();
			p_transform.RotateX(0.6);
			positionRef = position;

			m_actorTime += (p_time - m_lastTime) * m_worldSpeed;
			m_lastTime = p_time;

			VTable0x74(p_transform);
			return FALSE;
		}
		else {
			m_state = 0;
			m_unk0x1c = 0;

			positionRef -= g_unk0x10104ef0;
			m_roi->FUN_100a58f0(p_transform);
			m_roi->VTable0x14();
			return TRUE;
		}
	}

	return FALSE;
}

// FUNCTION: LEGO1 0x1003fd90
MxResult Act3Actor::VTable0x94(LegoPathActor* p_actor, MxBool p_bool)
{
	if (!p_actor->GetUserNavFlag() && p_bool) {
		if (p_actor->GetState()) {
			return FAILURE;
		}

		LegoROI* roi = p_actor->GetROI();

		MxMatrix local2world;
		local2world = roi->GetLocal2World();

		Vector3(local2world[3]) += g_unk0x10104ef0;

		roi->FUN_100a58f0(local2world);
		roi->VTable0x14();

		p_actor->SetState(c_bit2 | c_bit9);
	}

	return SUCCESS;
}
