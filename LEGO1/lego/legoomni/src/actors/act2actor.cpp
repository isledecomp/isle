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
#ifndef BETA10
	{{-44.6, 0.1, 45.3}, {0.95, 0.0, -0.3}, "edg00_154", FALSE},
#endif
};

// GLOBAL: LEGO1 0x100f0f1c
MxFloat g_lastAnimationTime = 0.0f;

// GLOBAL: LEGO1 0x100f0f20
// GLOBAL: BETA10 0x101dbe40
MxBool g_nextEntityIsBuilding = FALSE;

// GLOBAL: LEGO1 0x100f0f24
MxBool g_unk0x100f0f24 = FALSE;

// GLOBAL: LEGO1 0x100f0f28
// GLOBAL: BETA10 0x101dbe44
MxBool g_playedShootSound = FALSE;

// --- All of these are indices into g_plantInfo (0x10103180) ---

// GLOBAL: LEGO1 0x100f0f30
// GLOBAL: BETA10 0x101dbe48
MxS32 g_location0Plants[] = {2, 23, 32, 66, 71, 72, 73, -1};

// GLOBAL: LEGO1 0x100f0f50
// GLOBAL: BETA10 0x101dbe68
MxS32 g_location1Plants[] = {0, 7, 16, 18, 20, 21, 34, 49, 58, 59, 63, 65, 69, 74, -1};

// GLOBAL: LEGO1 0x100f0f90
// GLOBAL: BETA10 0x101dbea8
MxS32 g_location2Plants[] = {12, 19, 24, 48, 60, -1};

// GLOBAL: LEGO1 0x100f0fa8
// GLOBAL: BETA10 0x101dbec0
MxS32 g_location3Plants[] = {8, 15, 46, -1};

// GLOBAL: LEGO1 0x100f0fb8
// GLOBAL: BETA10 0x101dbed0
MxS32 g_location4Plants[] = {25, 26, 28, 29, 38, 39, 42, 50, 51, 56, -1};

// GLOBAL: LEGO1 0x100f0fe8
// GLOBAL: BETA10 0x101dbf00
MxS32 g_location5Plants[] = {3, 40, 53, 55, -1};

// GLOBAL: LEGO1 0x100f1000
// GLOBAL: BETA10 0x101dbf18
MxS32 g_location6Plants[] = {22, 33, 41, 45, 67, -1};

// GLOBAL: LEGO1 0x100f1018
// GLOBAL: BETA10 0x101dbf30
MxS32 g_location7Plants[] = {13, 30, 31, 62, -1};

// GLOBAL: LEGO1 0x100f1030
// GLOBAL: BETA10 0x101dbf48
MxS32 g_location8Plants[] = {1, 27, 37, 44, 47, 54, 61, 64, -1};

// --- End of indices into g_plantInfo ---

// GLOBAL: LEGO1 0x10102b1c
// GLOBAL: BETA10 0x10209f60
MxU32 g_nextHeadWavIndex = 0;

// GLOBAL: LEGO1 0x10102b20
// GLOBAL: BETA10 0x10209f64
MxU32 g_nextBehindWavIndex = 0;

// GLOBAL: LEGO1 0x10102b24
// GLOBAL: BETA10 0x10209f68
MxU32 g_nextInterruptWavIndex = 0;

// FUNCTION: LEGO1 0x100187e0
// FUNCTION: BETA10 0x1000c7fb
Act2Actor::Act2Actor()
{
	m_skipAnimation = FALSE;
	m_targetLocation = 0;
	m_animatingHit = FALSE;
	m_createBrickTime = 0;
	m_animationDuration = 0;
	m_state = e_readyToShoot;
	m_baseWorldSpeed = 4;
	m_shootAnimEnd = 0;
	m_entityAnimationTime = 0;
	m_shootAnim = NULL;
	m_resetWorldSpeedAt = 0;
	m_initializing = TRUE;
	m_visitedLocations = 0;
	m_nextEntity = NULL;
	m_cachedShootSound = NULL;
	m_unk0x3c = 0;

	// Odd: The code says < 10, but there are 11 entries in the array
	for (MxS32 i = 0; i < 10; i++) {
		g_brickstrLocations[i].m_cleared = FALSE;
	}
}

// FUNCTION: LEGO1 0x10018940
void Act2Actor::SetROI(LegoROI* p_roi, MxBool p_bool1, MxBool p_updateTransform)
{
	LegoAnimActor::SetROI(p_roi, p_bool1, p_updateTransform);
	m_roi->SetVisibility(FALSE);
}

// FUNCTION: LEGO1 0x10018980
// FUNCTION: BETA10 0x1000c963
void Act2Actor::InitializeNextShot()
{
	for (MxS32 i = 0; i < m_animMaps.size(); i++) {
		if (m_animMaps[i]->GetWorldSpeed() == -1.0f) {
			m_shootAnim = m_animMaps[i];
		}
	}

	assert(m_shootAnim);

	m_cachedShootSound = SoundManager()->GetCacheSoundManager()->FindSoundByKey("xarrow");
#ifdef BETA10
	// actually 0x2c and 0x30
	m_cachedShootSound = SoundManager()->GetCacheSoundManager()->FindSoundByKey("bcrash");
	m_cachedShootSound->SetDistance(35, 60);
	m_cachedShootSound->SetDistance(35, 60);
#else
	m_cachedShootSound->SetDistance(45, 55);
	m_roi->SetVisibility(TRUE);
#endif
}

// FUNCTION: LEGO1 0x100189f0
// FUNCTION: BETA10 0x1000ca64
MxResult Act2Actor::HitActor(LegoPathActor*, MxBool)
{
	if (m_animatingHit == FALSE) {
		m_animatingHit = TRUE;
		m_animationDuration = 0;
	}

	SoundManager()->GetCacheSoundManager()->Play("hitactor", NULL, FALSE);
	return SUCCESS;
}

// FUNCTION: LEGO1 0x10018a20
MxResult Act2Actor::VTable0x9c()
{
	if (m_grec && !m_grec->HasPath()) {
		delete m_grec;
		m_grec = NULL;
		return SUCCESS;
	}
	else {
		if (m_animatingHit) {
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
	MxFloat timeSinceLastAnimate = 0.0f;
	if (g_lastAnimationTime != 0.0f) {
		timeSinceLastAnimate = p_time - g_lastAnimationTime;
	}

	g_lastAnimationTime = p_time;
#endif

	LegoAnimActor::Animate(p_time);

	if (m_resetWorldSpeedAt != 0.0f && m_resetWorldSpeedAt < p_time) {
		SetWorldSpeed(m_baseWorldSpeed);
	}

	if (m_animatingHit) {
		if (m_animationDuration > 600.0f) {
			m_animatingHit = FALSE;
			m_animationDuration = 0;
		}
		else {
#ifndef BETA10
			m_animationDuration += timeSinceLastAnimate;
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
		if (m_state == e_roaming) {
			m_state = e_readyToShoot;
			m_shootAnimEnd = m_shootAnim->GetDuration() + p_time;
			m_entityAnimationTime = m_shootAnimEnd - 1300.0f;
			SetWorldSpeed(0);
			m_skipAnimation = FALSE;
		}
		else if (m_state == e_endShot) {
			FindROI("pwrbrik")->SetVisibility(FALSE);
			FindROI("debrick")->SetVisibility(FALSE);
			FindROI("ray")->SetVisibility(FALSE);
			m_nextEntity = NULL;
			m_state = e_roaming;
			NextTargetLocation();
			SetWorldSpeed(m_baseWorldSpeed + 3, p_time + 3000.0f);
		}
		else if (m_state == e_readyToShoot) {
			if (m_initializing) {
				m_initializing = FALSE;
				m_shootAnimEnd = m_shootAnim->GetDuration() + p_time;
				m_entityAnimationTime = m_shootAnimEnd - 1300.0f;
			}

			if (UpdateShot(p_time) == TRUE) {
				return;
			}
		}
		else if (m_state == e_hiding) {
			FindROI("brickstr")->SetVisibility(FALSE);
			GetROI()->SetVisibility(FALSE);
			CurrentWorld()->RemoveActor(this);
			return;
		}
#ifndef BETA10
		else if (m_state == e_goingToHide) {
			if (m_worldSpeed == 0.0f) {
				return;
			}

			SetWorldSpeed(0.0f);
			((LegoAct2*) CurrentWorld())->FUN_100517b0();
			return;
		}
#endif
	}

	if (m_state == e_hiding || m_state == e_goingToHide) {
		return;
	}

	if (m_state == e_createdBrick) {
		if (p_time - m_createBrickTime > 600.0f) {
			m_state = e_roaming;
			SetWorldSpeed(m_baseWorldSpeed + 4, p_time + 15000.0f);
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

					MxFloat distanceToAmbulance = DISTSQRD3(pepperWorldPosition, worldPosition);

					if (distanceToAmbulance < 75.0f) {
						if (!m_skipAnimation) {
							m_skipAnimation = TRUE;

							if (!m_state) {
								PlayNextVoiceOver(VoiceOver::e_interrupt);
								m_state = e_endShot;
							}
							else {
								LegoROI* childROI = m_roi->FindChildROI("windsd", m_roi);
								const MxFloat* childPosition = childROI->GetWorldPosition();
								MxFloat distanceToWindshield = DISTSQRD3(pepperWorldPosition, childPosition);

								childROI = m_roi->FindChildROI("reardr", m_roi);
								childPosition = childROI->GetWorldPosition();
								MxFloat distanceToRearDoor = DISTSQRD3(pepperWorldPosition, childPosition);

								if (distanceToRearDoor > distanceToWindshield) {
									PlayNextVoiceOver(VoiceOver::e_head);
								}
								else
#ifndef BETA10
									if (p_time - m_createBrickTime > 3000.0f) {
#endif
									SetWorldSpeed(m_baseWorldSpeed - 1);
									m_state = e_createdBrick;
									m_createBrickTime = p_time;

									if (((LegoAct2*) CurrentWorld())->CreateBrick() == SUCCESS) {
										PlayNextVoiceOver(VoiceOver::e_behind);
									}
#ifndef BETA10
								}
#endif
							}
						}
					}
					else {
						if (m_skipAnimation) {
							m_skipAnimation = FALSE;
						}
					}
				}
			}
		}
	}
}

// FUNCTION: LEGO1 0x10019250
// FUNCTION: BETA10 0x1000d45c
void Act2Actor::SetWorldSpeed(MxFloat p_speed, MxFloat p_resetWorldSpeedAt)
{
	// The arguments have been changed from BETA10 to LEGO1
	SetWorldSpeed(p_speed);
	m_resetWorldSpeedAt = p_resetWorldSpeedAt;
}

// FUNCTION: LEGO1 0x10019280
// FUNCTION: BETA10 0x1000d4a6
void Act2Actor::SetWorldSpeed(MxFloat p_worldSpeed)
{
	LegoAnimActor::SetWorldSpeed(p_worldSpeed);
	m_resetWorldSpeedAt = 0;
}

// FUNCTION: LEGO1 0x100192a0
// FUNCTION: BETA10 0x1000d4d6
void Act2Actor::FindPath(MxU32 p_location)
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

	MxResult sts = m_pathController->FindPath(
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
void Act2Actor::GoingToHide()
{
	m_state = e_goingToHide;
	SetWorldSpeed(m_baseWorldSpeed + 3);
	FindPath(10);
}

// FUNCTION: LEGO1 0x10019560
void Act2Actor::Hide()
{
	m_state = e_hiding;
	SetWorldSpeed(m_baseWorldSpeed + 5);
	FindPath(9);
}

// FUNCTION: LEGO1 0x100195a0
// FUNCTION: BETA10 0x1000d7d3
MxS32 Act2Actor::NextTargetLocation()
{
	MxU32 newLocation;

	assert(!m_grec);

	CurrentWorld();
	MxU16 randomVal = rand() / (RAND_MAX / 2) + 1;

	if (m_visitedLocations == 8 && m_targetLocation != 8) {
		newLocation = 8;
	}
	else {
		switch (m_targetLocation) {
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

	MxU32 firstChoice = newLocation;

	if (m_visitedLocations < 7 || g_brickstrLocations[m_targetLocation].m_cleared) {
		while (g_brickstrLocations[newLocation].m_cleared || m_targetLocation == newLocation) {
			if (newLocation == 7) {
				newLocation = 0;
			}
			else {
				newLocation++;
			}

			assert(newLocation != firstChoice);
		}
	}

	m_targetLocation = newLocation;
	FindPath(newLocation);

	if (m_grec) {
		return SUCCESS;
	}
	else {
		return FAILURE;
	}
}

// FUNCTION: LEGO1 0x10019700
// FUNCTION: BETA10 0x1000dd27
MxU32 Act2Actor::UpdateShot(MxFloat p_time)
{
	if (!m_nextEntity) {
		g_nextEntityIsBuilding = FALSE;
		m_nextEntity = GetNextEntity(&g_nextEntityIsBuilding);
		g_unk0x100f0f24 = FALSE;
		g_playedShootSound = FALSE;
	}

	if (!m_nextEntity) {
		MxTrace("nothing left to destroy at location %d\n", m_targetLocation);
		m_state = e_endShot;

		if (m_targetLocation == 8) {
			((LegoAct2*) CurrentWorld())->BadEnding();
		}

		return TRUE;
	}

	if (!g_playedShootSound && m_entityAnimationTime < p_time) {
		g_playedShootSound = TRUE;
		assert(SoundManager()->GetCacheSoundManager());
		SoundManager()->GetCacheSoundManager()->Play(m_cachedShootSound, "brickstr", FALSE);

		if (g_nextEntityIsBuilding) {
			BuildingManager()->ScheduleAnimation(m_nextEntity, 800, TRUE, FALSE);
		}
		else {
			PlantManager()->ScheduleAnimation(m_nextEntity, 800);
		}
	}

	if (m_shootAnimEnd < p_time) {
		g_nextEntityIsBuilding = FALSE;
		m_nextEntity = GetNextEntity(&g_nextEntityIsBuilding);
		m_shootAnimEnd = m_shootAnim->GetDuration() + p_time;
		m_entityAnimationTime = m_shootAnimEnd - 1300.0f;
		g_unk0x100f0f24 = FALSE;
		g_playedShootSound = FALSE;
		return FALSE;
	}

	m_lastTime = p_time;
	LegoROI* brickstrROI = FindROI("brickstr");

	MxMatrix initialTransform = m_roi->GetLocal2World();
	initialTransform[3][1] += 1.0f;
	brickstrROI->SetLocal2World(initialTransform);
	brickstrROI->WrappedUpdateWorldData();

	Vector3 col0(initialTransform[0]);
	Vector3 col1(initialTransform[1]);
	Vector3 col2(initialTransform[2]);
	Vector3 col3(initialTransform[3]);

	col2 = col3;
	col2 -= m_nextEntity->GetROI()->GetWorldPosition();
	col2.Unitize();
	col0.EqualsCross(col1, col2);
	col0.Unitize();
	col1.EqualsCross(col2, col0);

	assert(!m_cameraFlag);

	LegoTreeNode* root = m_shootAnim->GetAnimTreePtr()->GetRoot();
	MxFloat time = p_time - (m_shootAnimEnd - m_shootAnim->GetDuration());

	for (MxS32 i = 0; i < root->GetNumChildren(); i++) {
		LegoROI::ApplyAnimationTransformation(root->GetChild(i), initialTransform, time, m_shootAnim->GetROIMap());
	}

	return FALSE;
}

// FUNCTION: LEGO1 0x100199f0
// FUNCTION: BETA10 0x1000e11a
void Act2Actor::PlayNextVoiceOver(MxS8 p_voiceOverType)
{
	switch (p_voiceOverType) {
	case VoiceOver::e_head:
		switch (g_nextHeadWavIndex) {
		case 0:
			((LegoAct2*) CurrentWorld())
				->StartAction(Act2mainScript::c_VOhead0_PlayWav, FALSE, FALSE, NULL, NULL, NULL);

			g_nextHeadWavIndex++;
			break;
		default:
			((LegoAct2*) CurrentWorld())
				->StartAction(Act2mainScript::c_VOhead1_PlayWav, FALSE, FALSE, NULL, NULL, NULL);
			g_nextHeadWavIndex = 0;
			break;
		}
		break;
	case VoiceOver::e_behind:
		switch (g_nextBehindWavIndex) {
		case 0:
			((LegoAct2*) CurrentWorld())
				->StartAction(Act2mainScript::c_VObehind0_PlayWav, FALSE, TRUE, NULL, NULL, NULL);
			g_nextBehindWavIndex++;
			break;
		case 1:
			((LegoAct2*) CurrentWorld())
				->StartAction(Act2mainScript::c_VObehind1_PlayWav, FALSE, TRUE, NULL, NULL, NULL);
			g_nextBehindWavIndex++;
			break;
		case 2:
			((LegoAct2*) CurrentWorld())
				->StartAction(Act2mainScript::c_VObehind2_PlayWav, FALSE, TRUE, NULL, NULL, NULL);
			g_nextBehindWavIndex++;
			break;
		default:
			((LegoAct2*) CurrentWorld())
				->StartAction(Act2mainScript::c_VObehind3_PlayWav, FALSE, TRUE, NULL, NULL, NULL);
			g_nextBehindWavIndex = 0;
			break;
		}
		break;
	case VoiceOver::e_interrupt:
		switch (g_nextInterruptWavIndex) {
		case 0:
			((LegoAct2*) CurrentWorld())
				->StartAction(Act2mainScript::c_VOinterrupt0_PlayWav, FALSE, FALSE, NULL, NULL, NULL);
			g_nextInterruptWavIndex++;
			break;
		case 1:
			((LegoAct2*) CurrentWorld())
				->StartAction(Act2mainScript::c_VOinterrupt1_PlayWav, FALSE, FALSE, NULL, NULL, NULL);
			g_nextInterruptWavIndex++;
			break;
		case 2:
			((LegoAct2*) CurrentWorld())
				->StartAction(Act2mainScript::c_VOinterrupt2_PlayWav, FALSE, FALSE, NULL, NULL, NULL);
			g_nextInterruptWavIndex++;
			break;
		default:
			((LegoAct2*) CurrentWorld())
				->StartAction(Act2mainScript::c_VOinterrupt3_PlayWav, FALSE, FALSE, NULL, NULL, NULL);
			g_nextInterruptWavIndex = 0;
			break;
		}
	}
}

// FUNCTION: LEGO1 0x10019b90
// FUNCTION: BETA10 0x1000e374
LegoEntity* Act2Actor::GetNextEntity(MxBool* p_isBuilding)
{
	MxS32 i;
	LegoBuildingInfo* buildingInfo = BuildingManager()->GetInfoArray(i);
	LegoPlantInfo* plantInfo = PlantManager()->GetInfoArray(i);
	LegoEntity* result = 0;

	switch (m_targetLocation) {
	case 0:
		if (buildingInfo[12].m_counter) {
			result = buildingInfo[12].m_entity;
			*p_isBuilding = TRUE;
		}
		else if (buildingInfo[14].m_counter) {
			result = buildingInfo[14].m_entity;
			*p_isBuilding = TRUE;
		}
		else {
			for (i = 0; g_location0Plants[i] != -1; i++) {
				if (plantInfo[g_location0Plants[i]].m_counter) {
					result = plantInfo[g_location0Plants[i]].m_entity;
					break;
				}
			}
		}
		break;
	case 1:
		if (buildingInfo[13].m_counter) {
			result = buildingInfo[13].m_entity;
			*p_isBuilding = TRUE;
		}
		else {
			for (i = 0; g_location1Plants[i] != -1; i++) {
				if (plantInfo[g_location1Plants[i]].m_counter) {
					result = plantInfo[g_location1Plants[i]].m_entity;
					break;
				}
			}
		}
		break;
	case 2:
		if (buildingInfo[9].m_counter) {
			result = buildingInfo[9].m_entity;
			*p_isBuilding = TRUE;
		}
		else if (buildingInfo[11].m_counter) {
			result = buildingInfo[11].m_entity;
			*p_isBuilding = TRUE;
		}
		else {
			for (i = 0; g_location2Plants[i] != -1; i++) {
				if (plantInfo[g_location2Plants[i]].m_counter) {
					result = plantInfo[g_location2Plants[i]].m_entity;
					break;
				}
			}
		}
		break;
	case 3:
		if (buildingInfo[7].m_counter) {
			result = buildingInfo[7].m_entity;
			*p_isBuilding = TRUE;
		}
		else if (buildingInfo[8].m_counter) {
			result = buildingInfo[8].m_entity;
			*p_isBuilding = TRUE;
		}
		else if (buildingInfo[3].m_counter) {
			result = buildingInfo[3].m_entity;
			*p_isBuilding = TRUE;
		}
		else {
			for (i = 0; g_location3Plants[i] != -1; i++) {
				if (plantInfo[g_location3Plants[i]].m_counter) {
					result = plantInfo[g_location3Plants[i]].m_entity;
					break;
				}
			}
		}
		break;
	case 4:
		if (buildingInfo[5].m_counter) {
			result = buildingInfo[5].m_entity;
			*p_isBuilding = TRUE;
		}
		else if (buildingInfo[10].m_counter) {
			result = buildingInfo[10].m_entity;
			*p_isBuilding = TRUE;
		}
		else {
			for (i = 0; g_location4Plants[i] != -1; i++) {
				if (plantInfo[g_location4Plants[i]].m_counter) {
					result = plantInfo[g_location4Plants[i]].m_entity;
					break;
				}
			}
		}
		break;
	case 5:
		if (buildingInfo[4].m_counter) {
			result = buildingInfo[4].m_entity;
			*p_isBuilding = TRUE;
		}
		else {
			for (i = 0; g_location5Plants[i] != -1; i++) {
				if (plantInfo[g_location5Plants[i]].m_counter) {
					result = plantInfo[g_location5Plants[i]].m_entity;
					break;
				}
			}
		}
		break;
	case 6:
		if (buildingInfo[2].m_counter) {
			result = buildingInfo[2].m_entity;
			*p_isBuilding = TRUE;
		}
		else {
			for (i = 0; g_location6Plants[i] != -1; i++) {
				if (plantInfo[g_location6Plants[i]].m_counter) {
					result = plantInfo[g_location6Plants[i]].m_entity;
					break;
				}
			}
		}
		break;
	case 7:
		if (buildingInfo[6].m_counter) {
			result = buildingInfo[6].m_entity;
			*p_isBuilding = TRUE;
		}
		else {
			for (i = 0; g_location7Plants[i] != -1; i++) {
				if (plantInfo[g_location7Plants[i]].m_counter) {
					result = plantInfo[g_location7Plants[i]].m_entity;
					break;
				}
			}
		}
		break;
	case 8:
		for (i = 0; g_location8Plants[i] != -1; i++) {
			if (plantInfo[g_location8Plants[i]].m_counter) {
				result = plantInfo[g_location8Plants[i]].m_entity;
				break;
			}
		}

		if (result) {
			return result;
		}

		if (buildingInfo[15].m_counter) {
			result = buildingInfo[15].m_entity;
			*p_isBuilding = TRUE;
		}
		break;
	}

	if (!result && !g_brickstrLocations[m_targetLocation].m_cleared) {
		g_brickstrLocations[m_targetLocation].m_cleared = TRUE;
		m_visitedLocations++;
	}

	return result;
}
