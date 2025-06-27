#include "act2actor.h"

#include "3dmanager/lego3dmanager.h"
#include "act2main_actions.h"
#include "anim/legoanim.h"
#include "legoact2.h"
#include "legobuildingmanager.h"
#include "legocachesoundmanager.h"
#include "legopathcontroller.h"
#include "legopathedgecontainer.h"
#include "legoplantmanager.h"
#include "legoplants.h"
#include "legosoundmanager.h"
#include "legovideomanager.h"
#include "legoworld.h"
#include "misc.h"
#include "mxdebug.h"
#include "roi/legoroi.h"
#include "viewmanager/viewmanager.h"

#include <vec.h>

DECOMP_SIZE_ASSERT(Act2Actor, 0x1a8)
DECOMP_SIZE_ASSERT(Act2Actor::Location, 0x20)

// GLOBAL: LEGO1 0x100f0db8
// GLOBAL: BETA10 0x101dbd00
Act2Actor::Location g_brickstrLocations[] = {
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

// GLOBAL: LEGO1 0x100f0f20
// GLOBAL: BETA10 0x101dbe40
MxBool g_unk0x100f0f20 = FALSE;

// GLOBAL: LEGO1 0x100f0f24
MxBool g_unk0x100f0f24 = FALSE;

// GLOBAL: LEGO1 0x100f0f28
// GLOBAL: BETA10 0x101dbe44
MxBool g_unk0x100f0f28 = FALSE;

// --- All of these are indices into g_plantInfo (0x10103180) ---

// GLOBAL: LEGO1 0x100f0f30
// GLOBAL: BETA10 0x101dbe48
MxS32 g_stage0Plants[] = {2, 23, 32, 66, 71, 72, 73, -1};

// GLOBAL: LEGO1 0x100f0f50
// GLOBAL: BETA10 0x101dbe68
MxS32 g_stage1Plants[] = {0, 7, 16, 18, 20, 21, 34, 49, 58, 59, 63, 65, 69, 74, -1};

// GLOBAL: LEGO1 0x100f0f90
// GLOBAL: BETA10 0x101dbea8
MxS32 g_stage2Plants[] = {12, 19, 24, 48, 60, -1};

// GLOBAL: LEGO1 0x100f0fa8
// GLOBAL: BETA10 0x101dbec0
MxS32 g_stage3Plants[] = {8, 15, 46, -1};

// GLOBAL: LEGO1 0x100f0fb8
// GLOBAL: BETA10 0x101dbed0
MxS32 g_stage4Plants[] = {25, 26, 28, 29, 38, 39, 42, 50, 51, 56, -1};

// GLOBAL: LEGO1 0x100f0fe8
// GLOBAL: BETA10 0x101dbf00
MxS32 g_stage5Plants[] = {3, 40, 53, 55, -1};

// GLOBAL: LEGO1 0x100f1000
// GLOBAL: BETA10 0x101dbf18
MxS32 g_stage6Plants[] = {22, 33, 41, 45, 67, -1};

// GLOBAL: LEGO1 0x100f1018
// GLOBAL: BETA10 0x101dbf30
MxS32 g_stage7Plants[] = {13, 30, 31, 62, -1};

// GLOBAL: LEGO1 0x100f1030
// GLOBAL: BETA10 0x101dbf48
MxS32 g_stage8Plants[] = {1, 27, 37, 44, 47, 54, 61, 64, -1};

// --- End of indices into g_plantInfo ---

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
	m_unk0x4c = NULL;
	m_unk0x38 = NULL;
	m_unk0x3c = 0;

	// Odd: The code says < 10, but there are 11 entries in the array
	for (MxS32 i = 0; i < 10; i++) {
		g_brickstrLocations[i].m_unk0x1c = FALSE;
	}
}

// FUNCTION: LEGO1 0x10018940
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
		if (m_animMaps[i]->GetWorldSpeed() == -1.0f) {
			m_shootAnim = m_animMaps[i];
		}
	}

	assert(m_shootAnim);

	m_unk0x38 = SoundManager()->GetCacheSoundManager()->FindSoundByKey("xarrow");
#ifdef BETA10
	// actually 0x2c and 0x30
	m_unk0x38 = SoundManager()->GetCacheSoundManager()->FindSoundByKey("bcrash");
	m_unk0x38->SetDistance(35, 60);
	m_unk0x38->SetDistance(35, 60);
#else
	m_unk0x38->SetDistance(45, 55);
	m_roi->SetVisibility(TRUE);
#endif
}

// FUNCTION: LEGO1 0x100189f0
// FUNCTION: BETA10 0x1000ca64
MxResult Act2Actor::HitActor(LegoPathActor*, MxBool)
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
	if (m_grec && !m_grec->GetBit1()) {
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
void Act2Actor::Animate(float p_time)
{
	int dummy1; // for BETA10, not sure what it is being used for

#ifndef BETA10
	MxFloat local48float = 0.0f;
	if (g_unk0x100f0f1c != 0.0f) {
		local48float = p_time - g_unk0x100f0f1c;
	}

	g_unk0x100f0f1c = p_time;
#endif

	LegoAnimActor::Animate(p_time);

	if (m_unk0x44 != 0.0f && m_unk0x44 < p_time) {
		SetWorldSpeed(m_unk0x28);
	}

	if (m_unk0x1f) {
		if (m_unk0x20 > 600.0f) {
			m_unk0x1f = FALSE;
			m_unk0x20 = 0;
		}
		else {
#ifndef BETA10
			m_unk0x20 += local48float;
#endif
			MxMatrix matrix = m_roi->GetLocal2World();
			matrix[3][1] += 3.0f;
			m_roi->UpdateTransformationRelativeToParent(matrix);

#ifndef BETA10
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
			m_unk0x4c = NULL;
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

			if (FUN_10019700(p_time) == TRUE) {
				return;
			}
		}
		else if (m_unk0x1e == 5) {
			FindROI("brickstr")->SetVisibility(FALSE);
			GetROI()->SetVisibility(FALSE);
			CurrentWorld()->RemoveActor(this);
			return;
		}
#ifndef BETA10
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
		LegoROI* roiPepper = FindROI("pepper");

		if (roiPepper) {
			ViewManager* vm = VideoManager()->Get3DManager()->GetLego3DView()->GetViewManager();
			assert(vm);

			MxU32 inFrustum = vm->IsBoundingBoxInFrustum(m_roi->GetWorldBoundingBox());

			if (inFrustum) {
				Mx3DPointFloat local18(roiPepper->GetWorldDirection());
				Mx3DPointFloat local30(m_roi->GetWorldPosition());
				Mx3DPointFloat local60(roiPepper->GetWorldPosition());
				local30 -= local60;
				local30.Unitize();

				MxFloat dotproduct = local18.Dot(local30, local18);

				if (dotproduct >= 0.0) {
					const MxFloat* pepperWorldPosition = roiPepper->GetWorldPosition();
					const MxFloat* worldPosition = m_roi->GetWorldPosition();

					MxFloat distance1 = DISTSQRD3(pepperWorldPosition, worldPosition);

					if (distance1 < 75.0f) {
						if (!m_unk0x1c) {
							m_unk0x1c = 1;

							if (!m_unk0x1e) {
								FUN_100199f0(2);
								m_unk0x1e = 1;
							}
							else {
								LegoROI* childROI = m_roi->FindChildROI("windsd", m_roi);
								const MxFloat* childPosition = childROI->GetWorldPosition();
								MxFloat distance2 = DISTSQRD3(pepperWorldPosition, childPosition);

								childROI = m_roi->FindChildROI("reardr", m_roi);
								childPosition = childROI->GetWorldPosition();
								MxFloat distance3 = DISTSQRD3(pepperWorldPosition, childPosition);

								if (distance3 > distance2) {
									FUN_100199f0(0);
								}
								else
#ifndef BETA10
									if (p_time - m_unk0x24 > 3000.0f) {
#endif
									SetWorldSpeed(m_unk0x28 - 1);
									m_unk0x1e = 3;
									m_unk0x24 = p_time;

									if (((LegoAct2*) CurrentWorld())->FUN_100516b0() == SUCCESS) {
										FUN_100199f0(1);
									}
#ifndef BETA10
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
void Act2Actor::FUN_100192a0(undefined4 p_location)
{
	Mx3DPointFloat newPosition(0.0, 0.0, 0.0);
	Mx3DPointFloat newDirection(0.0, 0.0, 0.0);

	if (m_grec) {
		delete m_grec;
	}

	m_grec = new LegoPathEdgeContainer();
	assert(m_grec);

	newPosition = g_brickstrLocations[p_location].m_position;
	newDirection = g_brickstrLocations[p_location].m_direction;
	LegoPathBoundary* newBoundary = m_pathController->GetPathBoundary(g_brickstrLocations[p_location].m_boundary);

	MxResult sts = m_pathController->FUN_10048310(
		m_grec,
		m_roi->GetWorldPosition(),
		m_roi->GetWorldDirection(),
		m_boundary,
		newPosition,
		newDirection,
		newBoundary,
		LegoOrientedEdge::c_bit1,
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

	assert(!m_grec);

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

	if (m_unk0x48 < 7 || g_brickstrLocations[m_unk0x1d].m_unk0x1c) {
		while (g_brickstrLocations[newLocation].m_unk0x1c || m_unk0x1d == newLocation) {
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

// FUNCTION: LEGO1 0x10019700
// FUNCTION: BETA10 0x1000dd27
MxU32 Act2Actor::FUN_10019700(MxFloat p_param)
{
	if (!m_unk0x4c) {
		g_unk0x100f0f20 = FALSE;
		m_unk0x4c = FUN_10019b90(&g_unk0x100f0f20);
		g_unk0x100f0f24 = FALSE;
		g_unk0x100f0f28 = FALSE;
	}

	if (!m_unk0x4c) {
		MxTrace("nothing left to destroy at location %d\n", m_unk0x1d);
		m_unk0x1e = 1;

		if (m_unk0x1d == 8) {
			((LegoAct2*) CurrentWorld())->BadEnding();
		}

		return TRUE;
	}

	if (!g_unk0x100f0f28 && m_unk0x30 < p_param) {
		g_unk0x100f0f28 = TRUE;
		assert(SoundManager()->GetCacheSoundManager());
		SoundManager()->GetCacheSoundManager()->Play(m_unk0x38, "brickstr", FALSE);

		if (g_unk0x100f0f20) {
			BuildingManager()->ScheduleAnimation(m_unk0x4c, 800, TRUE, FALSE);
		}
		else {
			PlantManager()->ScheduleAnimation(m_unk0x4c, 800);
		}
	}

	if (m_unk0x2c < p_param) {
		g_unk0x100f0f20 = FALSE;
		m_unk0x4c = FUN_10019b90(&g_unk0x100f0f20);
		m_unk0x2c = m_shootAnim->GetDuration() + p_param;
		m_unk0x30 = m_unk0x2c - 1300.0f;
		g_unk0x100f0f24 = FALSE;
		g_unk0x100f0f28 = FALSE;
		return FALSE;
	}

	m_lastTime = p_param;
	LegoROI* brickstrROI = FindROI("brickstr");

	MxMatrix matrix = m_roi->GetLocal2World();
	matrix[3][1] += 1.0f;
	brickstrROI->SetLocal2World(matrix);
	brickstrROI->WrappedUpdateWorldData();

	Vector3 col0(matrix[0]);
	Vector3 col1(matrix[1]);
	Vector3 col2(matrix[2]);
	Vector3 col3(matrix[3]);

	col2 = col3;
	col2 -= m_unk0x4c->GetROI()->GetWorldPosition();
	col2.Unitize();
	col0.EqualsCross(col1, col2);
	col0.Unitize();
	col1.EqualsCross(col2, col0);

	assert(!m_cameraFlag);

	LegoTreeNode* root = m_shootAnim->GetAnimTreePtr()->GetRoot();
	MxFloat time = p_param - (m_unk0x2c - m_shootAnim->GetDuration());

	for (MxS32 i = 0; i < root->GetNumChildren(); i++) {
		LegoROI::ApplyAnimationTransformation(root->GetChild(i), matrix, time, m_shootAnim->GetROIMap());
	}

	return FALSE;
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

// FUNCTION: LEGO1 0x10019b90
// FUNCTION: BETA10 0x1000e374
LegoEntity* Act2Actor::FUN_10019b90(MxBool* p_param)
{
	MxS32 i;
	LegoBuildingInfo* buildingInfo = BuildingManager()->GetInfoArray(i);
	LegoPlantInfo* plantInfo = PlantManager()->GetInfoArray(i);
	LegoEntity* result = 0;

	switch (m_unk0x1d) {
	case 0:
		if (buildingInfo[12].m_counter) {
			result = buildingInfo[12].m_entity;
			*p_param = TRUE;
		}
		else if (buildingInfo[14].m_counter) {
			result = buildingInfo[14].m_entity;
			*p_param = TRUE;
		}
		else {
			for (i = 0; g_stage0Plants[i] != -1; i++) {
				if (plantInfo[g_stage0Plants[i]].m_counter) {
					result = plantInfo[g_stage0Plants[i]].m_entity;
					break;
				}
			}
		}
		break;
	case 1:
		if (buildingInfo[13].m_counter) {
			result = buildingInfo[13].m_entity;
			*p_param = TRUE;
		}
		else {
			for (i = 0; g_stage1Plants[i] != -1; i++) {
				if (plantInfo[g_stage1Plants[i]].m_counter) {
					result = plantInfo[g_stage1Plants[i]].m_entity;
					break;
				}
			}
		}
		break;
	case 2:
		if (buildingInfo[9].m_counter) {
			result = buildingInfo[9].m_entity;
			*p_param = TRUE;
		}
		else if (buildingInfo[11].m_counter) {
			result = buildingInfo[11].m_entity;
			*p_param = TRUE;
		}
		else {
			for (i = 0; g_stage2Plants[i] != -1; i++) {
				if (plantInfo[g_stage2Plants[i]].m_counter) {
					result = plantInfo[g_stage2Plants[i]].m_entity;
					break;
				}
			}
		}
		break;
	case 3:
		if (buildingInfo[7].m_counter) {
			result = buildingInfo[7].m_entity;
			*p_param = TRUE;
		}
		else if (buildingInfo[8].m_counter) {
			result = buildingInfo[8].m_entity;
			*p_param = TRUE;
		}
		else if (buildingInfo[3].m_counter) {
			result = buildingInfo[3].m_entity;
			*p_param = TRUE;
		}
		else {
			for (i = 0; g_stage3Plants[i] != -1; i++) {
				if (plantInfo[g_stage3Plants[i]].m_counter) {
					result = plantInfo[g_stage3Plants[i]].m_entity;
					break;
				}
			}
		}
		break;
	case 4:
		if (buildingInfo[5].m_counter) {
			result = buildingInfo[5].m_entity;
			*p_param = TRUE;
		}
		else if (buildingInfo[10].m_counter) {
			result = buildingInfo[10].m_entity;
			*p_param = TRUE;
		}
		else {
			for (i = 0; g_stage4Plants[i] != -1; i++) {
				if (plantInfo[g_stage4Plants[i]].m_counter) {
					result = plantInfo[g_stage4Plants[i]].m_entity;
					break;
				}
			}
		}
		break;
	case 5:
		if (buildingInfo[4].m_counter) {
			result = buildingInfo[4].m_entity;
			*p_param = TRUE;
		}
		else {
			for (i = 0; g_stage5Plants[i] != -1; i++) {
				if (plantInfo[g_stage5Plants[i]].m_counter) {
					result = plantInfo[g_stage5Plants[i]].m_entity;
					break;
				}
			}
		}
		break;
	case 6:
		if (buildingInfo[2].m_counter) {
			result = buildingInfo[2].m_entity;
			*p_param = TRUE;
		}
		else {
			for (i = 0; g_stage6Plants[i] != -1; i++) {
				if (plantInfo[g_stage6Plants[i]].m_counter) {
					result = plantInfo[g_stage6Plants[i]].m_entity;
					break;
				}
			}
		}
		break;
	case 7:
		if (buildingInfo[6].m_counter) {
			result = buildingInfo[6].m_entity;
			*p_param = TRUE;
		}
		else {
			for (i = 0; g_stage7Plants[i] != -1; i++) {
				if (plantInfo[g_stage7Plants[i]].m_counter) {
					result = plantInfo[g_stage7Plants[i]].m_entity;
					break;
				}
			}
		}
		break;
	case 8:
		for (i = 0; g_stage8Plants[i] != -1; i++) {
			if (plantInfo[g_stage8Plants[i]].m_counter) {
				result = plantInfo[g_stage8Plants[i]].m_entity;
				break;
			}
		}

		if (result) {
			return result;
		}

		if (buildingInfo[15].m_counter) {
			result = buildingInfo[15].m_entity;
			*p_param = TRUE;
		}
		break;
	}

	if (!result && !g_brickstrLocations[m_unk0x1d].m_unk0x1c) {
		g_brickstrLocations[m_unk0x1d].m_unk0x1c = TRUE;
		m_unk0x48++;
	}

	return result;
}
