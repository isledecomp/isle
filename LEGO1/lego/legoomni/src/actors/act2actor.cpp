#include "act2actor.h"

#include "legocachesoundmanager.h"
#include "legopathcontroller.h"
#include "legopathedgecontainer.h"
#include "legosoundmanager.h"
#include "misc.h"
#include "roi/legoroi.h"

DECOMP_SIZE_ASSERT(Act2Actor, 0x1a8)
DECOMP_SIZE_ASSERT(Act2Actor::UnknownListStructure, 0x20)

// GLOBAL: LEGO1 0x100f0db8
// GLOBAL: BETA10 0x101dbd00
Act2Actor::UnknownListStructure g_unk0x100f0db8[] = {
	{{-47.92, 7.0699968, -31.58}, {-0.999664, 0.0, -0.025916}, "edg01_27", FALSE},
	{{-70.393349, 8.07, 3.151935}, {-0.90653503, 0.0, 0.422131}, "int06", FALSE},
	{{-47.74, 4.079995, -52.3}, {-0.98293, 0.0, -0.18398}, "edg01_08", FALSE},
	{{-26.273487, 0.069, 12.170015}, {0.987199, 0.0, -0.159491}, "INT14", FALSE},
	{{26.16499, 0.069, 5.61}, {0.027719, 0.0, 0.999616}, "INT22", FALSE},
	{{66.383446, 4.07, 32.387417}, {0.979487, 0.0, -0.201506}, "edg02_27", FALSE},
	{{71.843285, 0.069, -49.524852}, {0.99031502, 0.0, 0.13884}, "edg02_39", FALSE},
	{{26.470566, 0.069, -44.670845}, {0.004602, 0.0, -0.99998897}, "int26", FALSE},
	{{-6.323625, 0.069, -47.96045}, {-0.982068, 0.0, 0.188529}, "edg02_53", FALSE},
	{{-36.689, -0.978409, 31.449}, {0.083792, -0.94303, -0.66398698}, "edg00_157", FALSE},
	{{-44.6, 0.1, 45.3}, {0.95, 0.0, -0.3}, "edg00_154", FALSE},
};

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

	// Odd: The code says < 10, but there are 11 entries in the array
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
// FUNCTION: BETA10 0x1000d4d6
void Act2Actor::FUN_100192a0(undefined4 p_param)
{
	Mx3DPointFloat local38(0.0, 0.0, 0.0);
	Mx3DPointFloat local4c(0.0, 0.0, 0.0);

	if (m_grec) {
		delete m_grec;
	}

	m_grec = new LegoPathEdgeContainer();
	assert(m_grec);

	local38 = g_unk0x100f0db8[p_param].m_unk0x00;
	local4c = g_unk0x100f0db8[p_param].m_unk0x0c;

	LegoPathBoundary* otherBoundary = m_controller->GetPathBoundary(g_unk0x100f0db8[p_param].m_unk0x18);

	MxResult sts = m_controller->FUN_10048310(
		m_grec,
		m_roi->GetWorldPosition(),
		m_roi->GetWorldDirection(),
		m_boundary,
		local38,
		local4c,
		otherBoundary,
		TRUE,
		NULL
	);

	assert(!sts);

	if (sts) {
		delete m_grec;
		m_grec = NULL;
	}
}

// FUNCTION: LEGO1 0x10019520
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
