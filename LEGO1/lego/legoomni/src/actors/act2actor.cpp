#include "act2actor.h"

#include "3dmanager/lego3dmanager.h"
#include "actions/act2main_actions.h"
#include "legoact2.h"
#include "legocachesoundmanager.h"
#include "legopathcontroller.h"
#include "legopathedgecontainer.h"
#include "legosoundmanager.h"
#include "legovideomanager.h"
#include "legoworld.h"
#include "misc.h"
#include "roi/legoroi.h"
#include "viewmanager/viewmanager.h"

#include <vec.h>

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

// GLOBAL: LEGO1 0x100f0f1c
MxFloat g_unk0x100f0f1c = 0.0f;

// GLOBAL: LEGO1 0x10102b1c
// GLOBAL: BETA10 0x10209f60
undefined4 g_nextHeadWavIndex = 0;

// GLOBAL: LEGO1 0x10102b20
// GLOBAL: BETA10 0x10209f64
undefined4 g_nextBehindWavIndex = 0;

// GLOBAL: LEGO1 0x10102b24
// GLOBAL: BETA10 0x10209f68
undefined4 g_nextInterruptWavIndex = 0;

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
	m_shootAnim = NULL;
	m_unk0x44 = 0;
	m_unk0x40 = 1;
	m_unk0x48 = 0;
	m_unk0x4c = 0;
	m_unk0x38 = NULL;
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

// FUNCTION: LEGO1 0x10018980
// FUNCTION: BETA10 0x1000c963
void Act2Actor::FUN_10018980()
{
	for (MxS32 i = 0; i < m_animMaps.size(); i++) {
		if (m_animMaps[i]->GetUnknown0x00() == -1.0f) {
			m_shootAnim = m_animMaps[i];
		}
	}

	assert(m_shootAnim);

	m_unk0x38 = SoundManager()->GetCacheSoundManager()->FindSoundByKey("xarrow");
	m_unk0x38->SetDistance(45, 55);
	m_roi->SetVisibility(TRUE);
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

// FUNCTION: LEGO1 0x10018a20
MxResult Act2Actor::VTable0x9c()
{
	if (m_grec && !(m_grec->m_flags & LegoPathEdgeContainer::c_bit1)) {
		delete m_grec;
		m_grec = NULL;
		return SUCCESS;
	}
	else {
		if (m_unk0x1f) {
			MxMatrix matrix = m_roi->GetLocal2World();
			matrix[3][1] -= 3.0f;
			m_roi->UpdateTransformationRelativeToParent(matrix);

			LegoROI* brickstrROI = FindROI("brickstr");
			MxMatrix brickstrMatrix = brickstrROI->GetLocal2World();
			brickstrMatrix[3][1] -= 3.0f;
			brickstrROI->UpdateTransformationRelativeToParent(brickstrMatrix);
		}

		return LegoPathActor::VTable0x9c();
	}
}

// FUNCTION: LEGO1 0x10018c30
// FUNCTION: BETA10 0x1000cb52
void Act2Actor::VTable0x70(float p_time)
{
	int dummy1; // for BETA10, not sure what it is being used for
	ViewManager* vm;
	LegoROI* roiPepper;
	LegoROI* childROI;
	const MxFloat* childPosition;
	const MxFloat* pepperWorldPosition;
	const MxFloat* worldPosition;
	MxFloat distance2;
	MxFloat distance3;

#ifdef NDEBUG
	MxFloat local48float = 0.0f;
	if (g_unk0x100f0f1c != 0.0f) {
		local48float = p_time - g_unk0x100f0f1c;
	}

	g_unk0x100f0f1c = p_time;
#endif

	LegoAnimActor::VTable0x70(p_time);

	if (m_unk0x44 != 0.0f && m_unk0x44 < p_time) {
		SetWorldSpeed(m_unk0x28);
	}

	if (m_unk0x1f) {
		if (m_unk0x20 > 600.0f) {
			m_unk0x1f = FALSE;
			m_unk0x20 = 0;
		}
		else {
#ifdef NDEBUG
			m_unk0x20 += local48float;
#endif
			MxMatrix matrix = m_roi->GetLocal2World();
			matrix[3][1] += 3.0f;
			m_roi->UpdateTransformationRelativeToParent(matrix);

#ifdef NDEBUG
			LegoROI* brickstrROI = FindROI("brickstr");
			MxMatrix brickstrMatrix = brickstrROI->GetLocal2World();
			brickstrMatrix[3][1] += 3.0f;
			brickstrROI->UpdateTransformationRelativeToParent(brickstrMatrix);
#endif
			return;
		}
	}

	if (!m_grec) {
		if (m_unk0x1e == 2) {
			m_unk0x1e = 0;
			m_unk0x2c = m_shootAnim->GetDuration() + p_time;
			m_unk0x30 = m_unk0x2c - 1300.0f;
			SetWorldSpeed(0);
			m_unk0x1c = FALSE;
		}
		else if (m_unk0x1e == 1) {
			FindROI("pwrbrik")->SetVisibility(FALSE);
			FindROI("debrick")->SetVisibility(FALSE);
			FindROI("ray")->SetVisibility(FALSE);
			m_unk0x4c = 0;
			m_unk0x1e = 2;
			VTable0xa0();
			FUN_10019250(m_unk0x28 + 3, p_time + 3000.0f);
		}
		else if (m_unk0x1e == 0) {
			if (m_unk0x40) {
				m_unk0x40 = 0;
				m_unk0x2c = m_shootAnim->GetDuration() + p_time;
				m_unk0x30 = m_unk0x2c - 1300.0f;
			}

			if (FUN_10019700(p_time) == 1) {
				return;
			}
		}
		else if (m_unk0x1e == 5) {
			FindROI("brickstr")->SetVisibility(FALSE);
			GetROI()->SetVisibility(FALSE);
			CurrentWorld()->RemoveActor(this);
			return;
		}
#ifdef NDEBUG
		else if (m_unk0x1e == 4) {
			if (m_worldSpeed == 0.0f) {
				return;
			}

			SetWorldSpeed(0.0f);
			((LegoAct2*) CurrentWorld())->FUN_100517b0();
			return;
		}
#endif
	}

	if (m_unk0x1e == 5 || m_unk0x1e == 4) {
		return;
	}

	if (m_unk0x1e == 3) {
		if (p_time - m_unk0x24 > 600.0f) {
			m_unk0x1e = 2;
			FUN_10019250(m_unk0x28 + 4, p_time + 15000.0f);
		}
	}
	else {
		roiPepper = FindROI("pepper");

		if (roiPepper) {
			vm = VideoManager()->Get3DManager()->GetLego3DView()->GetViewManager();
			assert(vm);

			MxU32 inFrustum = vm->IsBoundingBoxInFrustum(m_roi->GetWorldBoundingBox());

			if (inFrustum) {
				Mx3DPointFloat local18(roiPepper->GetWorldDirection());
				Mx3DPointFloat local30(m_roi->GetWorldPosition());
				Mx3DPointFloat local60(roiPepper->GetWorldPosition());
				local30 -= local60;
				local30.Unitize();

				MxFloat dotproduct = local18.Dot(&local30, &local18);

				if (dotproduct >= 0.0) {
					pepperWorldPosition = roiPepper->GetWorldPosition();
					worldPosition = m_roi->GetWorldPosition();

					MxFloat distance1 = DISTSQRD3(pepperWorldPosition, worldPosition);

					if (distance1 < 75.0f) {
						if (!m_unk0x1c) {
							m_unk0x1c = 1;

							if (!m_unk0x1e) {
								FUN_100199f0(2);
								m_unk0x1e = 1;
							}
							else {
								childROI = m_roi->FindChildROI("windsd", m_roi);
								childPosition = childROI->GetWorldPosition();
								distance2 = DISTSQRD3(pepperWorldPosition, childPosition);

								childROI = m_roi->FindChildROI("reardr", m_roi);
								childPosition = childROI->GetWorldPosition();
								distance3 = DISTSQRD3(pepperWorldPosition, childPosition);

								if (distance3 > distance2) {
									FUN_100199f0(0);
								}
								else
#ifdef NDEBUG
									// `distance2` is guessed, looks promising
									if (distance2 - m_unk0x24 > 3000.0f) {
#endif
										SetWorldSpeed(m_unk0x28 - 1);
										m_unk0x1e = 3;
										// guessed
										m_unk0x24 = distance2;

										if (!((LegoAct2*) CurrentWorld())->FUN_100516b0()) {
											FUN_100199f0(1);
										}
#ifdef NDEBUG
									}
#endif
							}
						}
					}
					else {

						if (m_unk0x1c) {
							m_unk0x1c = 0;
						}
					}
				}
			}
		}
	}
}

// FUNCTION: LEGO1 0x10019250
// FUNCTION: BETA10 0x1000d45c
void Act2Actor::FUN_10019250(MxFloat p_speed, MxFloat p_param2)
{
	// The arguments have been changed from BETA10 to LEGO1
	SetWorldSpeed(p_speed);
	m_unk0x44 = p_param2;
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
	Mx3DPointFloat newPosition(0.0, 0.0, 0.0);
	Mx3DPointFloat newDirection(0.0, 0.0, 0.0);

	if (m_grec) {
		delete m_grec;
	}

	m_grec = new LegoPathEdgeContainer();
	assert(m_grec);

	newPosition = g_unk0x100f0db8[p_param].m_position;
	newDirection = g_unk0x100f0db8[p_param].m_direction;
	LegoPathBoundary* newBoundary = m_controller->GetPathBoundary(g_unk0x100f0db8[p_param].m_boundary);

	MxResult sts = m_controller->FUN_10048310(
		m_grec,
		m_roi->GetWorldPosition(),
		m_roi->GetWorldDirection(),
		m_boundary,
		newPosition,
		newDirection,
		newBoundary,
		LegoUnknown100db7f4::c_bit1,
		NULL
	);

	assert(!sts); // == SUCCESS

	if (sts != SUCCESS) {
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

// FUNCTION: LEGO1 0x10019560
void Act2Actor::FUN_10019560()
{
	m_unk0x1e = 5;
	SetWorldSpeed(m_unk0x28 + 5);
	FUN_100192a0(9);
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

// STUB: LEGO1 0x10019700
// STUB: BETA10 0x1000dd27
undefined4 Act2Actor::FUN_10019700(MxFloat p_param)
{
	// TODO
	return 0;
}

// FUNCTION: LEGO1 0x100199f0
// FUNCTION: BETA10 0x1000e11a
void Act2Actor::FUN_100199f0(MxS8 p_param)
{
	switch (p_param) {
	case 0:
		switch (g_nextHeadWavIndex) {
		case 0:
			((LegoAct2*) CurrentWorld())
				->FUN_10052560(Act2mainScript::c_VOhead0_PlayWav, FALSE, FALSE, NULL, NULL, NULL);

			g_nextHeadWavIndex++;
			break;
		default:
			((LegoAct2*) CurrentWorld())
				->FUN_10052560(Act2mainScript::c_VOhead1_PlayWav, FALSE, FALSE, NULL, NULL, NULL);
			g_nextHeadWavIndex = 0;
			break;
		}
		break;
	case 1:
		switch (g_nextBehindWavIndex) {
		case 0:
			((LegoAct2*) CurrentWorld())
				->FUN_10052560(Act2mainScript::c_VObehind0_PlayWav, FALSE, TRUE, NULL, NULL, NULL);
			g_nextBehindWavIndex++;
			break;
		case 1:
			((LegoAct2*) CurrentWorld())
				->FUN_10052560(Act2mainScript::c_VObehind1_PlayWav, FALSE, TRUE, NULL, NULL, NULL);
			g_nextBehindWavIndex++;
			break;
		case 2:
			((LegoAct2*) CurrentWorld())
				->FUN_10052560(Act2mainScript::c_VObehind2_PlayWav, FALSE, TRUE, NULL, NULL, NULL);
			g_nextBehindWavIndex++;
			break;
		default:
			((LegoAct2*) CurrentWorld())
				->FUN_10052560(Act2mainScript::c_VObehind3_PlayWav, FALSE, TRUE, NULL, NULL, NULL);
			g_nextBehindWavIndex = 0;
			break;
		}
		break;
	case 2:
		switch (g_nextInterruptWavIndex) {
		case 0:
			((LegoAct2*) CurrentWorld())
				->FUN_10052560(Act2mainScript::c_VOinterrupt0_PlayWav, FALSE, FALSE, NULL, NULL, NULL);
			g_nextInterruptWavIndex++;
			break;
		case 1:
			((LegoAct2*) CurrentWorld())
				->FUN_10052560(Act2mainScript::c_VOinterrupt1_PlayWav, FALSE, FALSE, NULL, NULL, NULL);
			g_nextInterruptWavIndex++;
			break;
		case 2:
			((LegoAct2*) CurrentWorld())
				->FUN_10052560(Act2mainScript::c_VOinterrupt2_PlayWav, FALSE, FALSE, NULL, NULL, NULL);
			g_nextInterruptWavIndex++;
			break;
		default:
			((LegoAct2*) CurrentWorld())
				->FUN_10052560(Act2mainScript::c_VOinterrupt3_PlayWav, FALSE, FALSE, NULL, NULL, NULL);
			g_nextInterruptWavIndex = 0;
			break;
		}
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
