#include "act2actor.h"

#include "legocachesoundmanager.h"
#include "legosoundmanager.h"
#include "misc.h"
#include "roi/legoroi.h"

DECOMP_SIZE_ASSERT(Act2Actor, 0x1a8)
DECOMP_SIZE_ASSERT(Act2Actor::UnknownListStructure, 0x20)

// TODO: Copy the data once we know more about its fields. Total: 10 entries
// GLOBAL: LEGO1 0x100f0db8
// GLOBAL: BETA10 0x101dbd00
Act2Actor::UnknownListStructure g_unk0x100f0db8[] = {{{0}, 0, {0}}};

// FUNCTION: LEGO1 0x100187e0
// FUNCTION: BETA10 0x1000c7fb
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

	// TODO replace 10 by sizeOfArray once the data are there
	for (MxS32 i = 0; i < 10; i++) {
		g_unk0x100f0db8[i].m_unk0x1c = 0;
	}
}

// FUNCTION: LEGO1 0x10018940
// FUNCTION: BETA10 0x1003d65f
void Act2Actor::SetROI(LegoROI* p_roi, MxBool p_bool1, MxBool p_bool2)
{
	LegoAnimActor::SetROI(p_roi, p_bool1, p_bool2);
	m_roi->SetVisibility(FALSE);
}

// FUNCTION: LEGO1 0x100189f0
// FUNCTION: BETA10 0x1000ca64
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
// STUB: BETA10 0x1000cb52
void Act2Actor::VTable0x70(float p_und)
{
	// TODO
}

// FUNCTION: LEGO1 0x10019280
// FUNCTION: BETA10 0x1000d4a6
void Act2Actor::SetWorldSpeed(MxFloat p_worldSpeed)
{
	LegoAnimActor::SetWorldSpeed(p_worldSpeed);
	m_unk0x44 = 0;
}

// FUNCTION: LEGO1 0x100192a0
void Act2Actor::FUN_100192a0(undefined4 p_param)
{
	// TODO
}

// FUNCTION: LEGO1 0x10019520
// FUNCTION: BETA10 0x1000d4d6
void Act2Actor::FUN_10019520()
{
	m_unk0x1e = 4;
	SetWorldSpeed(m_unk0x28 + 3);
	FUN_100192a0(10);
}

// FUNCTION: LEGO1 0x100195a0
// FUNCTION: BETA10 0x1000d7d3
MxS32 Act2Actor::VTable0xa0()
{
	undefined4 newLocation;

	CurrentWorld();
	MxU16 randomVal = rand() / (RAND_MAX / 2) + 1;

	if (m_unk0x48 == 8 && m_unk0x1d != 8) {
		newLocation = 8;
	}
	else {
		switch (m_unk0x1d) {
		case 0:
			if (randomVal == 1) {
				newLocation = 3;
			}
			else {
				newLocation = 7;
			}
			break;
		case 1:
			if (randomVal == 1) {
				newLocation = 2;
			}
			else {
				newLocation = 4;
			}
			break;
		case 2:
			if (randomVal == 1) {
				newLocation = 3;
			}
			else {
				newLocation = 6;
			}
			break;
		case 3:
			if (randomVal == 1) {
				newLocation = 5;
			}
			else {
				newLocation = 1;
			}
			break;
		case 4:
			if (randomVal == 1) {
				newLocation = 7;
			}
			else {
				newLocation = 0;
			}
			break;
		case 5:
			if (randomVal == 1) {
				newLocation = 6;
			}
			else {
				newLocation = 1;
			}
			break;
		case 6:
			if (randomVal == 1) {
				newLocation = 0;
			}
			else {
				newLocation = 4;
			}
			break;
		case 7:
			if (randomVal == 1) {
				newLocation = 2;
			}
			else {
				newLocation = 5;
			}
			break;
		case 8:
			if (randomVal == 1) {
				newLocation = 0;
			}
			else {
				newLocation = 4;
			}
		}
	}

	undefined4 firstChoice = newLocation;

	if (m_unk0x48 < 7 || g_unk0x100f0db8[m_unk0x1d].m_unk0x1c) {
		while (g_unk0x100f0db8[newLocation].m_unk0x1c || m_unk0x1d == newLocation) {
			if (newLocation == 7) {
				newLocation = 0;
			}
			else {
				newLocation++;
			}

			assert(newLocation != firstChoice);
		}
	}

	m_unk0x1d = newLocation;
	FUN_100192a0(newLocation);

	if (m_grec) {
		return SUCCESS;
	}
	else {
		return FAILURE;
	}
}

// FUNCTION: LEGO1 0x1001a180
MxS32 Act2Actor::VTable0x68(Vector3& p_v1, Vector3& p_v2, Vector3& p_v3)
{
	if (m_unk0x1f) {
		return 0;
	}

	return LegoAnimActor::VTable0x68(p_v1, p_v2, p_v3);
}
