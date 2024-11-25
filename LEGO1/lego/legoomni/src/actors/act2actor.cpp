#include "act2actor.h"

#include "legocachesoundmanager.h"
#include "legosoundmanager.h"
#include "misc.h"
#include "roi/legoroi.h"

DECOMP_SIZE_ASSERT(Act2Actor, 0x1a8)

// STUB: LEGO1 0x100187e0
Act2Actor::Act2Actor()
{
	m_unk0x1c = 0;
	m_unk0x1d = 0;
	m_unk0x1f = FALSE;
	m_unk0x24 = 0;
	m_unk0x20 = 0;
	m_unk0x1e = 0;
	m_unk0x28 = 4;
	m_unk0x2c = 0;
	m_unk0x30 = 0;
	m_unk0x34 = 0;
	m_unk0x44 = 0;
	m_unk0x40 = 1;
	m_unk0x48 = 0;
	m_unk0x4c = 0;
	m_unk0x38 = 0;
	m_unk0x3c = 0;
}

// FUNCTION: LEGO1 0x10018940
void Act2Actor::SetROI(LegoROI* p_roi, MxBool p_bool1, MxBool p_bool2)
{
	LegoAnimActor::SetROI(p_roi, p_bool1, p_bool2);
	m_roi->SetVisibility(FALSE);
}

// FUNCTION: LEGO1 0x100189f0
MxResult Act2Actor::VTable0x94(LegoPathActor*, MxBool)
{
	if (m_unk0x1f == FALSE) {
		m_unk0x1f = TRUE;
		m_unk0x20 = 0;
	}

	SoundManager()->GetCacheSoundManager()->Play("hitactor", NULL, FALSE);
	return SUCCESS;
}

// STUB: LEGO1 0x10018a20
MxResult Act2Actor::VTable0x9c()
{
	// TODO
	return SUCCESS;
}

// STUB: LEGO1 0x10018c30
void Act2Actor::VTable0x70(float p_und)
{
	// TODO
}

// FUNCTION: LEGO1 0x10019280
void Act2Actor::SetWorldSpeed(MxFloat p_worldSpeed)
{
	LegoAnimActor::SetWorldSpeed(p_worldSpeed);
	m_unk0x44 = 0;
}

// STUB: LEGO1 0x100195a0
MxS32 Act2Actor::VTable0xa0()
{
	// TODO
	return 0;
}

// STUB: LEGO1 0x10019520
// STUB: BETA10 0x1000d4d6
void Act2Actor::FUN_10019520()
{
	// TODO
}

// FUNCTION: LEGO1 0x1001a180
MxS32 Act2Actor::VTable0x68(Vector3& p_v1, Vector3& p_v2, Vector3& p_v3)
{
	if (m_unk0x1f) {
		return 0;
	}

	return LegoAnimActor::VTable0x68(p_v1, p_v2, p_v3);
}
