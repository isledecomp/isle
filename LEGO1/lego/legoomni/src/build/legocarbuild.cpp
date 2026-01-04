#include "legocarbuild.h"

#include "copter_actions.h"
#include "dunebuggy.h"
#include "dunecar_actions.h"
#include "helicopter.h"
#include "isle_actions.h"
#include "jetski.h"
#include "jetski_actions.h"
#include "jukebox_actions.h"
#include "legocarbuildpresenter.h"
#include "legocontrolmanager.h"
#include "legogamestate.h"
#include "legoinputmanager.h"
#include "legomain.h"
#include "legosoundmanager.h"
#include "legoutils.h"
#include "misc.h"
#include "mxactionnotificationparam.h"
#include "mxbackgroundaudiomanager.h"
#include "mxcontrolpresenter.h"
#include "mxmisc.h"
#include "mxnotificationmanager.h"
#include "mxsoundpresenter.h"
#include "mxstillpresenter.h"
#include "mxticklemanager.h"
#include "mxtransitionmanager.h"
#include "mxvariabletable.h"
#include "racecar.h"
#include "racecar_actions.h"
#include "scripts.h"

#include <isle.h>
#include <vec.h>

// Names and values verified by BETA10 0x1006d742.
// Note that these were probably hard-coded numbers in the original.
#define Helicopter_Actor CopterScript::c_Helicopter_Actor
#define DuneBugy_Actor DunecarScript::c_DuneBugy_Actor
#define Jetski_Actor JetskiScript::c_Jetski_Actor
#define RaceCar_Actor RacecarScript::c_RaceCar_Actor

DECOMP_SIZE_ASSERT(LegoCarBuild, 0x34c)
DECOMP_SIZE_ASSERT(LegoVehicleBuildState, 0x50)
DECOMP_SIZE_ASSERT(LegoCarBuild::LookupTableActions, 0x1c);

// These four structs can be matched to the vehicle types using BETA10 0x10070520

// GLOBAL: LEGO1 0x100d65b0
// GLOBAL: BETA10 0x101bb7c0
LegoCarBuild::LookupTableActions LegoCarBuild::g_actorScripts[] = {
	{DunecarScript::c_igs001d3_RunAnim,
	 DunecarScript::c_igs002d3_RunAnim,
	 DunecarScript::c_igs003d3_RunAnim,
	 DunecarScript::c_igs004d3_RunAnim,
	 DunecarScript::c_igs005d3_RunAnim,
	 DunecarScript::c_igs004d3_RunAnim,
	 DunecarScript::c_igsxx1d3_RunAnim},
	{JetskiScript::c_ijs001d4_RunAnim,
	 JetskiScript::c_ijs003d4_RunAnim,
	 JetskiScript::c_ijs004d4_RunAnim,
	 JetskiScript::c_ijs005d4_RunAnim,
	 JetskiScript::c_ijs006d4_RunAnim,
	 JetskiScript::c_ijs007d4_RunAnim,
	 JetskiScript::c_ijsxx2d4_RunAnim},
	{CopterScript::c_ips001d2_RunAnim,
	 CopterScript::c_ips002d2_RunAnim,
	 CopterScript::c_ips003d2_RunAnim,
	 CopterScript::c_ips005d2_RunAnim,
	 CopterScript::c_ips004d2_RunAnim,
	 CopterScript::c_ips004d2_RunAnim,
	 CopterScript::c_ipsxx1d2_RunAnim},
	{RacecarScript::c_irt001d1_RunAnim,
	 RacecarScript::c_irt002d1_RunAnim,
	 RacecarScript::c_irt003d1_RunAnim,
	 RacecarScript::c_irt004d1_RunAnim,
	 RacecarScript::c_irt005d1_RunAnim,
	 RacecarScript::c_irt004d1_RunAnim,
	 RacecarScript::c_irtxx4d1_RunAnim}
};

// GLOBAL: LEGO1 0x100d65a4
MxFloat LegoCarBuild::g_selectedPartRotationAngleStepYAxis = -0.1f;

// GLOBAL: LEGO1 0x100d65a8
MxFloat LegoCarBuild::g_rotationAngleStepYAxis = 0.07;

// GLOBAL: LEGO1 0x100f11cc
MxS16 LegoCarBuild::g_lastTickleState = -1;

// FUNCTION: LEGO1 0x100226d0
// FUNCTION: BETA10 0x1006ac10
LegoCarBuild::LegoCarBuild()
{
	m_clickState = e_idle;
	m_selectedPart = 0;
	m_resetPlacedSelectedPart = c_disabled;
	m_displayedPartIsPlaced = FALSE;
	m_animPresenter = NULL;
	m_ColorBook_Bitmap = NULL;
	m_Yellow_Ctl = NULL;
	m_Red_Ctl = NULL;
	m_Blue_Ctl = NULL;
	m_Green_Ctl = NULL;
	m_Gray_Ctl = NULL;
	m_Black_Ctl = NULL;
	m_Shelf_Sound = NULL;
	m_PlaceBrick_Sound = NULL;
	m_GetBrick_Sound = NULL;
	m_Paint_Sound = NULL;
	m_Decal_Sound = NULL;
	m_Decal_Bitmap = NULL;
	m_Decals_Ctl = NULL;
	m_Decals_Ctl1 = NULL;
	m_Decals_Ctl2 = NULL;
	m_Decals_Ctl3 = NULL;
	m_Decals_Ctl4 = NULL;
	m_Decals_Ctl5 = NULL;
	m_Decals_Ctl6 = NULL;
	m_Decals_Ctl7 = NULL;
	m_tickledControl = NULL;
	m_buildState = NULL;
	m_unk0x104 = 0;
	m_missclickCounter = 0;
	m_numAnimsRun = 0;
	m_jukeboxPresenter = 0;
	m_destLocation = LegoGameState::e_undefined;
	m_playingActorScript = DS_NOT_A_STREAM;
	m_alreadyFinished = 0;
	NotificationManager()->Register(this);
}

// FUNCTION: LEGO1 0x10022a80
// FUNCTION: BETA10 0x1006aea3
LegoCarBuild::~LegoCarBuild()
{
	m_clickState = e_idle;
	m_selectedPart = NULL;

	if (m_animPresenter) {
		m_animPresenter->SetShelfState(LegoCarBuildAnimPresenter::e_selected);
		m_animPresenter->SetTickleState(MxPresenter::e_idle);
		m_animPresenter = NULL;
	}

	ControlManager()->Unregister(this);
	TickleManager()->UnregisterClient(this);

	if (InputManager()->GetWorld() == this) {
		InputManager()->ClearWorld();
	}

	InputManager()->UnRegister(this);
	NotificationManager()->Unregister(this);
}

// FUNCTION: LEGO1 0x10022b70
// FUNCTION: BETA10 0x1006afd9
MxResult LegoCarBuild::Create(MxDSAction& p_dsAction)
{
	MxResult result = LegoWorld::Create(p_dsAction);

	if (!result) {
		// TickleManager()->RegisterClient(this, 100);
		InputManager()->SetWorld(this);
		ControlManager()->Register(this);

		SetIsWorldActive(FALSE);

		InputManager()->Register(this);

		// variable name verified by BETA10 0x1006b1a6
		const char* buildStateClassName = NULL;

		if (m_atomId == *g_copterScript) {
			buildStateClassName = "LegoCopterBuildState";
			GameState()->m_currentArea = LegoGameState::e_copterbuild;
			m_carId = Helicopter_Actor;
		}
		else if (m_atomId == *g_dunecarScript) {
			buildStateClassName = "LegoDuneCarBuildState";
			GameState()->m_currentArea = LegoGameState::e_dunecarbuild;
			m_carId = DuneBugy_Actor;
		}
		else if (m_atomId == *g_jetskiScript) {
			buildStateClassName = "LegoJetskiBuildState";
			GameState()->m_currentArea = LegoGameState::e_jetskibuild;
			m_carId = Jetski_Actor;
		}
		else if (m_atomId == *g_racecarScript) {
			buildStateClassName = "LegoRaceCarBuildState";
			GameState()->m_currentArea = LegoGameState::e_racecarbuild;
			m_carId = RaceCar_Actor;
		}

		LegoGameState* gameState = GameState();

		LegoVehicleBuildState* buildState = (LegoVehicleBuildState*) gameState->GetState(buildStateClassName);

		if (!buildState) {
			buildState = (LegoVehicleBuildState*) gameState->CreateState(buildStateClassName);
		}

		m_buildState = buildState;
		m_alreadyFinished = m_buildState->m_finishedBuild;

		GameState()->StopArea(LegoGameState::e_previousArea);

		m_buildState->m_animationState = LegoVehicleBuildState::e_entering;
		m_clickState = e_idle;

		BackgroundAudioManager()->Stop();
		EnableAnimations(FALSE);

		result = SUCCESS;
	}

	return result;
}

// FUNCTION: LEGO1 0x10022cd0
MxS16 LegoCarBuild::GetPlacedPartCount()
{
	if (m_buildState) {
		return m_buildState->m_placedPartCount;
	}
	else {
		return 0;
	}
}

// FUNCTION: LEGO1 0x10022cf0
void LegoCarBuild::SetPlacedPartCount(MxU8 p_placedPartCount)
{
	if (m_buildState) {
		m_buildState->m_placedPartCount = p_placedPartCount;
	}
}

// FUNCTION: LEGO1 0x10022d10
// FUNCTION: BETA10 0x1006b27a
void LegoCarBuild::InitPresenters()
{
	m_ColorBook_Bitmap = (MxStillPresenter*) Find("MxStillPresenter", "ColorBook_Bitmap");
	assert(m_ColorBook_Bitmap);
	m_Yellow_Ctl = (MxControlPresenter*) Find("MxControlPresenter", "Yellow_Ctl");
	assert(m_Yellow_Ctl);
	m_Red_Ctl = (MxControlPresenter*) Find("MxControlPresenter", "Red_Ctl");
	assert(m_Red_Ctl);
	m_Blue_Ctl = (MxControlPresenter*) Find("MxControlPresenter", "Blue_Ctl");
	assert(m_Blue_Ctl);
	m_Green_Ctl = (MxControlPresenter*) Find("MxControlPresenter", "Green_Ctl");
	assert(m_Green_Ctl);
	m_Gray_Ctl = (MxControlPresenter*) Find("MxControlPresenter", "Gray_Ctl");
	assert(m_Gray_Ctl);
	m_Black_Ctl = (MxControlPresenter*) Find("MxControlPresenter", "Black_Ctl");
	assert(m_Black_Ctl);
	m_Shelf_Sound = (MxSoundPresenter*) Find("MxSoundPresenter", "Shelf_Sound");
	assert(m_Shelf_Sound);
	m_PlaceBrick_Sound = (MxSoundPresenter*) Find("MxSoundPresenter", "PlaceBrick_Sound");
	assert(m_PlaceBrick_Sound);
	m_GetBrick_Sound = (MxSoundPresenter*) Find("MxSoundPresenter", "GetBrick_Sound");
	assert(m_GetBrick_Sound);
	m_Paint_Sound = (MxSoundPresenter*) Find("MxSoundPresenter", "Paint_Sound");
	assert(m_Paint_Sound);
	m_Decal_Sound = (MxSoundPresenter*) Find("MxSoundPresenter", "Decal_Sound");
	m_Decals_Ctl = (MxControlPresenter*) Find("MxControlPresenter", "Decals_Ctl");
	m_Decals_Ctl1 = (MxControlPresenter*) Find("MxControlPresenter", "Decals_Ctl1");
	m_Decals_Ctl2 = (MxControlPresenter*) Find("MxControlPresenter", "Decals_Ctl2");
	m_Decal_Bitmap = (MxStillPresenter*) Find("MxStillPresenter", "Decal_Bitmap");
#ifdef BETA10
	assert(m_Decal_Bitmap);
#endif
	if (m_Decal_Bitmap) {
		m_Decals_Ctl3 = (MxControlPresenter*) Find("MxControlPresenter", "Decals_Ctl3");
		assert(m_Decals_Ctl3);
		m_Decals_Ctl4 = (MxControlPresenter*) Find("MxControlPresenter", "Decals_Ctl4");
		assert(m_Decals_Ctl4);
		m_Decals_Ctl5 = (MxControlPresenter*) Find("MxControlPresenter", "Decals_Ctl5");
		assert(m_Decals_Ctl5);
		m_Decals_Ctl6 = (MxControlPresenter*) Find("MxControlPresenter", "Decals_Ctl6");
		assert(m_Decals_Ctl6);
		m_Decals_Ctl7 = (MxControlPresenter*) Find("MxControlPresenter", "Decals_Ctl7");
		assert(m_Decals_Ctl7);
	}
}

// FUNCTION: LEGO1 0x10022f00
void LegoCarBuild::DisplaySelectedPart()
{
	if (m_selectedPart) {
		InitializeDisplayingTransform();
		m_animPresenter->SetShelfState(LegoCarBuildAnimPresenter::e_selected);
		m_clickState = e_displaying;
	}
}

// FUNCTION: LEGO1 0x10022f30
// FUNCTION: BETA10 0x1006b835
void LegoCarBuild::ResetSelectedPart()
{
	if (m_selectedPart) {
		EnableColorControlsForSelectedPart(FALSE);
		EnableDecalForSelectedPart(FALSE);

		if (m_animPresenter->PartIsPlaced(m_selectedPart->GetName())) {
			m_PlaceBrick_Sound->Enable(FALSE);
			m_PlaceBrick_Sound->Enable(TRUE);
		}

		m_animPresenter->SetShelfState(LegoCarBuildAnimPresenter::e_stopped);
		m_animPresenter->PutFrame();
		m_selectedPart = NULL;
		m_clickState = e_idle;
	}
}

// FUNCTION: LEGO1 0x10022fc0
// FUNCTION: BETA10 0x1006b90b
void LegoCarBuild::InitializeDisplayingTransform()
{
	m_selectedPartStartTransform = m_displayTransform;
	m_selectedPart->WrappedSetLocal2WorldWithWorldDataUpdate(m_selectedPartStartTransform);
	m_selectedPartStartPosition = Vector4(m_selectedPart->GetWorldPosition());

	CalculateStartAndTargetScreenPositions();
}

// FUNCTION: LEGO1 0x10023020
// FUNCTION: BETA10 0x1006b991
void LegoCarBuild::CalculateStartAndTargetScreenPositions()
{
	MxFloat worldPos[3];
	MxFloat screenPos[4];

	worldPos[0] = m_selectedPartStartPosition[0];
	worldPos[1] = m_selectedPartStartPosition[1];
	worldPos[2] = m_selectedPartStartPosition[2];

	TransformWorldToScreen(worldPos, screenPos);

	m_selectedPartStartScreenPosition[0] = screenPos[0] / screenPos[3];
	m_selectedPartStartScreenPosition[1] = screenPos[1] / screenPos[3];

	worldPos[0] = m_selectedPartTargetPosition[0];
	worldPos[1] = m_selectedPartTargetPosition[1];
	worldPos[2] = m_selectedPartTargetPosition[2];

	TransformWorldToScreen(worldPos, screenPos);

	m_selectedPartTargetScreenPosition[0] = screenPos[0] / screenPos[3];
	m_selectedPartTargetScreenPosition[1] = screenPos[1] / screenPos[3];

	m_normalizedDistance =
		sqrt((MxDouble) DISTSQRD2(m_selectedPartStartScreenPosition, m_selectedPartTargetScreenPosition));

	m_draggingQuarternionTransformer.SetStartEnd(m_selectedPartStartTransform, m_selectedPartTargetTransform);
}

// FUNCTION: LEGO1 0x10023130
// FUNCTION: BETA10 0x1006bb22
void LegoCarBuild::CalculateSelectedPartMatrix(MxLong p_x, MxLong p_y)
{
	if (m_selectedPart) {
		MxFloat screenCoordinatesForRay[2];
		MxFloat local30[3];
		MxFloat local84[3];

		p_x += (m_selectedPartStartScreenPosition[0] - m_selectedPartStartMousePosition[0]);
		p_y += (m_selectedPartStartScreenPosition[1] - m_selectedPartStartMousePosition[1]);

		screenCoordinatesForRay[0] = p_x;
		screenCoordinatesForRay[1] = p_y;

		if (CalculateRayOriginDirection(screenCoordinatesForRay, local30, local84)) {
			MxFloat positionOffset[3];
			MxFloat screenPosition[2];

			screenPosition[0] = p_x;
			screenPosition[1] = p_y;

			positionOffset[0] = 0;
			positionOffset[1] = 0;
			positionOffset[2] = 0;

			MxMatrix transform;

			if (p_y < m_selectedPartStartScreenPosition[1]) {
				CalculateDragPositionAbove(screenPosition, positionOffset);
			}
			else if (p_y > m_selectedPartTargetScreenPosition[1]) {
				CalculateDragPositionOnGround(screenPosition, positionOffset);
			}
			else if (p_y >= m_selectedPartStartScreenPosition[1]) {
				CalculateDragPositionBetween(screenPosition, positionOffset);
			}

			MxS32 currentDistance[2];

			currentDistance[0] = p_x - m_selectedPartStartScreenPosition[0];
			currentDistance[1] = p_y - m_selectedPartStartScreenPosition[1];

			MxFloat distanceRatio = sqrt((double) (NORMSQRD2(currentDistance))) / m_normalizedDistance;

			m_draggingQuarternionTransformer.InterpolateToMatrix(transform, distanceRatio);

			transform[3][0] = m_selectedPartStartTransform[3][0] + positionOffset[0];
			transform[3][1] = m_selectedPartStartTransform[3][1] + positionOffset[1];
			transform[3][2] = m_selectedPartStartTransform[3][2] + positionOffset[2];
			transform[3][3] = 1.0;

			m_selectedPart->WrappedSetLocal2WorldWithWorldDataUpdate(transform);
		}
	}
}

// FUNCTION: LEGO1 0x10023500
// FUNCTION: BETA10 0x1006bdf6
void LegoCarBuild::CalculateDragPositionAbove(MxFloat p_coordinates[2], MxFloat p_position[3])
{
	MxFloat planeFactor;
	MxFloat origin[3];
	MxFloat direction[3];

	CalculateRayOriginDirection(p_coordinates, direction, origin);

	planeFactor = (m_selectedPartStartPosition[2] - origin[2]) / direction[2];
	p_position[0] = (planeFactor * direction[0] + origin[0]) - m_selectedPartStartPosition[0];
	p_position[1] = (planeFactor * direction[1] + origin[1]) - m_selectedPartStartPosition[1];
	p_position[2] = 0.0;
}

// FUNCTION: LEGO1 0x10023570
// FUNCTION: BETA10 0x1006be91
void LegoCarBuild::CalculateDragPositionBetween(MxFloat p_coordinates[2], MxFloat p_position[3])
{
	MxFloat planeFactor;
	MxFloat direction[3];
	MxFloat origin[3];

	CalculateRayOriginDirection(p_coordinates, direction, origin);

	p_position[2] = m_selectedPartStartPosition[2] +
					(m_selectedPartTargetPosition[2] - m_selectedPartStartPosition[2]) *
						((p_coordinates[1] - m_selectedPartStartScreenPosition[1]) /
						 (m_selectedPartTargetScreenPosition[1] - m_selectedPartStartScreenPosition[1]));
	planeFactor = (p_position[2] - origin[2]) / direction[2];
	p_position[0] = planeFactor * direction[0] - m_selectedPartStartPosition[0] + origin[0];
	p_position[1] = planeFactor * direction[1] - m_selectedPartStartPosition[1] + origin[1];
	p_position[2] = p_position[2] - m_selectedPartStartPosition[2];
}

// FUNCTION: LEGO1 0x10023620
// FUNCTION: BETA10 0x1006bfb5
void LegoCarBuild::CalculateDragPositionOnGround(MxFloat p_coordinates[2], MxFloat p_position[3])
{
	MxFloat direction[3];
	MxFloat origin[3];
	CalculateRayOriginDirection(p_coordinates, direction, origin);

	MxFloat planeFactor = (m_selectedPartTargetPosition[1] - origin[1]) / direction[1];
	p_position[0] = planeFactor * direction[0] - m_selectedPartStartPosition[0] + origin[0];
	p_position[1] = m_selectedPartTargetPosition[1] - m_selectedPartStartPosition[1];
	p_position[2] = planeFactor * direction[2] - m_selectedPartStartPosition[2] + origin[2];
}

// FUNCTION: LEGO1 0x100236a0
// FUNCTION: BETA10 0x100701f0
void LegoCarBuild::VTable0x80(MxFloat p_param1[2], MxFloat p_param2[2], MxFloat p_param3, MxFloat p_param4[2])
{
	if (p_param1[1] == 0.0f) {
		return;
	}
	p_param4[0] = ((p_param3 - p_param2[1]) / p_param1[1]) * p_param1[0] + p_param2[0];
	p_param4[1] = p_param3;
}

// FUNCTION: LEGO1 0x100236d0
// FUNCTION: BETA10 0x1006c076
void LegoCarBuild::AddSelectedPartToBuild()
{
	MxS32 jukeboxScript;

	EnableColorControlsForSelectedPart(FALSE);
	EnableDecalForSelectedPart(FALSE);
	m_animPresenter->AddPartToBuildByName(m_selectedPart->GetName());
	m_animPresenter->SetShelfState(LegoCarBuildAnimPresenter::e_stopped);
	m_selectedPart = NULL;
	m_clickState = e_idle;

	if (m_animPresenter->AllPartsPlaced()) {
		// Note the code duplication with LEGO1 0x10025ee0
		switch (m_carId) {
		case Helicopter_Actor:
			jukeboxScript = JukeboxScript::c_HelicopterBuild_Movie;
			break;
		case DuneBugy_Actor:
			jukeboxScript = JukeboxScript::c_DuneCarBuild_Movie;
			break;
		case Jetski_Actor:
			jukeboxScript = JukeboxScript::c_JetskiBuild_Movie;
			break;
		case RaceCar_Actor:
			jukeboxScript = JukeboxScript::c_RaceCarBuild_Movie;
		}

		BackgroundAudioManager()->Init();
		InvokeAction(Extra::e_stop, *g_jukeboxScript, jukeboxScript, NULL);

		if (m_numAnimsRun > 0) {
			DeleteObjects(&m_atomId, 500, 510);
		}

		if (GameState()->GetCurrentAct() == LegoGameState::e_act2) {
			InitExiting();
		}
		else {
			m_buildState->m_finishedBuild = TRUE;
			InvokeAction(Extra::e_start, m_atomId, m_carId, NULL);
			NotificationManager()->Send(this, MxNotificationParam());
			m_buildState->m_animationState = LegoVehicleBuildState::e_finishedBuild;
			m_buildState->m_placedPartCount = 0;
		}
	}
}

#define LEGOCARBUILD_TICKLE_CASE(subtract, start, end, str)                                                            \
	if (start < dTime && dTime < end) {                                                                                \
		TickleControl(str, dTime - subtract);                                                                          \
		break;                                                                                                         \
	}

// FUNCTION: LEGO1 0x100238b0
// FUNCTION: BETA10 0x1006c18f
MxResult LegoCarBuild::Tickle()
{
	if (!m_worldStarted) {
		LegoWorld::Tickle();
		return SUCCESS;
	}

	if (m_resetPlacedSelectedPart == c_enabled) {
		if (m_rotateBuild == 1) {
			RotateVehicle();
		}

		if (m_selectedPart) {
			if (m_animPresenter->PartIsPlaced(m_selectedPart->GetName())) {
				ResetSelectedPart();
			}
		}
	}

	if (m_clickState == e_displaying && m_selectedPart) {
		RotateY(m_selectedPart, g_selectedPartRotationAngleStepYAxis);
	}

	if (m_lastActorScript) {
		MxULong time = timeGetTime();
		MxULong dTime = (time - m_lastActorScriptStartTime) / 100;

		if (m_carId == RaceCar_Actor) {
			switch (m_lastActorScript) {
			case RacecarScript::c_irt001d1_RunAnim:
				LEGOCARBUILD_TICKLE_CASE(160, 160, 180, "Exit_Ctl")
				LEGOCARBUILD_TICKLE_CASE(260, 260, 280, "ShelfUp_Ctl")
				LEGOCARBUILD_TICKLE_CASE(330, 330, 340, "Yellow_Ctl")
				LEGOCARBUILD_TICKLE_CASE(340, 340, 360, "Platform_Ctl")
				LEGOCARBUILD_TICKLE_CASE(390, 390, 410, "Exit_Ctl")
				break;
			case RacecarScript::c_irt004d1_RunAnim:
				LEGOCARBUILD_TICKLE_CASE(50, 50, 60, "ShelfUp_Ctl")
				LEGOCARBUILD_TICKLE_CASE(63, 65, 70, "Yellow_Ctl")
				LEGOCARBUILD_TICKLE_CASE(70, 70, 80, "Platform_Ctl")
				LEGOCARBUILD_TICKLE_CASE(95, 95, 105, "Exit_Ctl")
				break;
			case RacecarScript::c_irtxx4d1_RunAnim:
				LEGOCARBUILD_TICKLE_CASE(22, 24, 29, "Exit_Ctl")
				LEGOCARBUILD_TICKLE_CASE(33, 35, 40, "ShelfUp_Ctl")
				LEGOCARBUILD_TICKLE_CASE(43, 45, 50, "Yellow_Ctl")
				LEGOCARBUILD_TICKLE_CASE(56, 58, 63, "Platform_Ctl")
				break;
			}
		}
		else if (m_carId == Jetski_Actor) {
			switch (m_lastActorScript) {
			case JetskiScript::c_ijs001d4_RunAnim:
				LEGOCARBUILD_TICKLE_CASE(291, 291, 311, "Exit_Ctl")
				LEGOCARBUILD_TICKLE_CASE(311, 311, 331, "ShelfUp_Ctl")
				LEGOCARBUILD_TICKLE_CASE(412, 412, 432, "Yellow_Ctl")
				LEGOCARBUILD_TICKLE_CASE(437, 437, 457, "Platform_Ctl")
				LEGOCARBUILD_TICKLE_CASE(485, 485, 505, "Exit_Ctl")
				break;
			case JetskiScript::c_ijsxx2d4_RunAnim:
				LEGOCARBUILD_TICKLE_CASE(32, 34, 39, "Exit_Ctl")
				LEGOCARBUILD_TICKLE_CASE(68, 70, 75, "ShelfUp_Ctl")
				LEGOCARBUILD_TICKLE_CASE(105, 105, 115, "Yellow_Ctl")
				LEGOCARBUILD_TICKLE_CASE(133, 135, 140, "Platform_Ctl")
				break;
			case JetskiScript::c_ijs005d4_RunAnim:
				LEGOCARBUILD_TICKLE_CASE(78, 78, 98, "Exit_Ctl")
				break;
			case JetskiScript::c_ijs006d4_RunAnim:
				LEGOCARBUILD_TICKLE_CASE(93, 93, 113, "Exit_Ctl")
				break;
			}
		}
		else if (m_carId == DuneBugy_Actor) {
			switch (m_lastActorScript) {
			case DunecarScript::c_igs001d3_RunAnim:
				LEGOCARBUILD_TICKLE_CASE(155, 155, 175, "Exit_Ctl")
				LEGOCARBUILD_TICKLE_CASE(215, 215, 235, "ShelfUp_Ctl")
				LEGOCARBUILD_TICKLE_CASE(285, 285, 305, "Yellow_Ctl")
				LEGOCARBUILD_TICKLE_CASE(300, 300, 320, "Platform_Ctl")
				LEGOCARBUILD_TICKLE_CASE(340, 340, 360, "Exit_Ctl")
				break;
			case DunecarScript::c_igsxx1d3_RunAnim:
				LEGOCARBUILD_TICKLE_CASE(23, 23, 33, "Exit_Ctl")
				LEGOCARBUILD_TICKLE_CASE(37, 39, 44, "ShelfUp_Ctl")
				LEGOCARBUILD_TICKLE_CASE(105, 105, 115, "Yellow_Ctl")
				LEGOCARBUILD_TICKLE_CASE(122, 124, 129, "Platform_Ctl")
				break;
			}
		}
		else if (m_carId == Helicopter_Actor) {
			switch (m_lastActorScript) {
			case CopterScript::c_ips001d2_RunAnim:
				LEGOCARBUILD_TICKLE_CASE(185, 185, 205, "Exit_Ctl")
				LEGOCARBUILD_TICKLE_CASE(235, 235, 255, "ShelfUp_Ctl")
				LEGOCARBUILD_TICKLE_CASE(292, 292, 312, "Yellow_Ctl")
				LEGOCARBUILD_TICKLE_CASE(315, 315, 335, "Platform_Ctl")
				LEGOCARBUILD_TICKLE_CASE(353, 353, 373, "Exit_Ctl")
				break;
			case CopterScript::c_ipsxx1d2_RunAnim:
				LEGOCARBUILD_TICKLE_CASE(43, 45, 50, "Exit_Ctl")
				LEGOCARBUILD_TICKLE_CASE(72, 74, 79, "ShelfUp_Ctl")
				LEGOCARBUILD_TICKLE_CASE(114, 116, 121, "Yellow_Ctl")
				LEGOCARBUILD_TICKLE_CASE(128, 130, 135, "Platform_Ctl")
				break;
			case CopterScript::c_ips005d2_RunAnim:
				LEGOCARBUILD_TICKLE_CASE(30, 30, 40, "ShelfUp_Ctl")
				LEGOCARBUILD_TICKLE_CASE(60, 60, 70, "Yellow_Ctl")
				LEGOCARBUILD_TICKLE_CASE(48, 48, 58, "Platform_Ctl")
				break;
			}
		}
	}

	return SUCCESS;
}

// FUNCTION: LEGO1 0x10024050
// FUNCTION: BETA10 0x1006c976
MxLong LegoCarBuild::Notify(MxParam& p_param)
{
	MxLong result = LegoWorld::Notify(p_param);
	MxNotificationParam& param = (MxNotificationParam&) p_param;

	if (m_worldStarted) {
		switch (param.GetNotification()) {
		case c_notificationType0:
			HandleType0Notification((MxNotificationParam*) &p_param);
			result = 1;
			break;
		case c_notificationEndAction:
			result = HandleEndAction((MxActionNotificationParam*) &p_param);
			break;
		case c_notificationKeyPress:
			result = HandleKeyPress((LegoEventNotificationParam*) &p_param);
			break;
		case c_notificationButtonUp:
			result = HandleButtonUp(
				((LegoEventNotificationParam&) p_param).GetX(),
				((LegoEventNotificationParam&) p_param).GetY()
			);

			if (result || m_lastActorScript ||
				m_buildState->m_animationState == LegoVehicleBuildState::e_finishedBuild ||
				m_buildState->m_animationState == LegoVehicleBuildState::e_exiting) {
				m_missclickCounter = 0;
				break;
			}

			if (++m_missclickCounter > 2) {
				StartActorScriptByType(LookupTableActionType::e_shortExplanation);
				m_missclickCounter = 0;
			}

			break;
		case c_notificationButtonDown:
			assert(m_buildState);
			if (((m_buildState->m_animationState != LegoVehicleBuildState::e_finishedBuild) &&
				 (m_buildState->m_animationState != LegoVehicleBuildState::e_exiting)) &&
				(m_buildState->m_animationState != LegoVehicleBuildState::e_settingUpMovie)) {
				m_buildState->m_animationState = LegoVehicleBuildState::e_none;
				result = SelectPartFromMousePosition(
					((LegoEventNotificationParam&) p_param).GetX(),
					((LegoEventNotificationParam&) p_param).GetY()
				);
			}

			break;
		case c_notificationMouseMove:
			result = HandleMouseMove(
				((LegoEventNotificationParam&) p_param).GetX(),
				((LegoEventNotificationParam&) p_param).GetY()
			);

			if (result == 1) {
				m_missclickCounter = 0;
			}

			break;
		case c_notificationControl:
			result = HandleControl(&p_param);

			if (result == 1) {
				m_missclickCounter = 0;
			}

			break;
		case c_notificationEndAnim:
			if (m_numAnimsRun > 0) {
				m_numAnimsRun -= 1;
			}

			HandleEndAnim();
			m_lastActorScript = 0;
			result = 1;
			break;
		case c_notificationTransitioned:
			assert(m_destLocation != LegoGameState::e_undefined);
			GameState()->SwitchArea(m_destLocation);
		}
	}

	return result;
}

// FUNCTION: LEGO1 0x10024250
// FUNCTION: BETA10 0x1006cc48
MxLong LegoCarBuild::HandleKeyPress(LegoEventNotificationParam* p_param)
{
	if (p_param->GetKey() == ' ' && m_buildState->m_animationState != LegoVehicleBuildState::e_finishedBuild &&
		m_buildState->m_animationState != LegoVehicleBuildState::e_settingUpMovie) {
		if (m_numAnimsRun > 0) {
			DeleteObjects(&m_atomId, 500, 0x1fe);
			BackgroundAudioManager()->RaiseVolume();
			m_missclickCounter = 0;
		}

		return 1;
	}

	return 0;
}

// FUNCTION: LEGO1 0x100242c0
void LegoCarBuild::ReadyWorld()
{
	m_presentersEnabled = FALSE;
	InitPresenters();

	if (BackgroundAudioManager()->GetEnabled()) {
		InvokeAction(Extra::ActionType::e_start, *g_jukeboxScript, GetBuildMovieId(m_carId), NULL);
		m_buildState->m_animationState = LegoVehicleBuildState::e_settingUpMovie;
		NotificationManager()->Send(this, MxNotificationParam());
	}
	else {
		StartIntroduction();
	}
}

// FUNCTION: LEGO1 0x100243a0
void LegoCarBuild::InitExiting()
{
	switch (m_carId) {
	case Helicopter_Actor:
		if (GameState()->GetCurrentAct() == LegoGameState::Act::e_act2) {
			m_destLocation = LegoGameState::Area::e_act3script;
			TransitionManager()->StartTransition(MxTransitionManager::TransitionType::e_mosaic, 50, FALSE, FALSE);
			break;
		}
		else {
			m_destLocation = LegoGameState::Area::e_polidoor;
			TransitionManager()->StartTransition(MxTransitionManager::TransitionType::e_mosaic, 50, FALSE, FALSE);
			break;
		}
	case DuneBugy_Actor:
		m_destLocation = LegoGameState::Area::e_garadoor;
		TransitionManager()->StartTransition(MxTransitionManager::TransitionType::e_mosaic, 50, FALSE, FALSE);
		break;
	case Jetski_Actor:
		m_destLocation = LegoGameState::Area::e_jetskibuildExited;
		TransitionManager()->StartTransition(MxTransitionManager::TransitionType::e_mosaic, 50, FALSE, FALSE);
		break;
	case RaceCar_Actor:
		m_destLocation = LegoGameState::Area::e_racecarbuildExited;
		TransitionManager()->StartTransition(MxTransitionManager::TransitionType::e_mosaic, 50, FALSE, FALSE);
	}
}

// FUNCTION: LEGO1 0x10024480
MxLong LegoCarBuild::HandleEndAction(MxActionNotificationParam* p_param)
{
	MxLong result = 0;

	switch (m_buildState->m_animationState) {
	case LegoVehicleBuildState::e_cutscene:
		BackgroundAudioManager()->RaiseVolume();
		m_buildState->m_animationState = LegoVehicleBuildState::e_none;
		result = 1;
		break;
	case LegoVehicleBuildState::e_exiting:
		if (p_param->GetAction()->GetObjectId() == m_playingActorScript) {
			InitExiting();
			result = 1;
			break;
		}
	}

	return result;
}

// FUNCTION: LEGO1 0x100244e0
// FUNCTION: BETA10 0x1006cfb6
MxLong LegoCarBuild::SelectPartFromMousePosition(MxLong p_x, MxLong p_y)
{
	m_selectedPartStartMousePosition[0] = p_x;
	m_selectedPartStartMousePosition[1] = p_y;

	LegoROI* roi = PickROI(p_x, p_y);

	if (!roi || !m_animPresenter->StringEndsOnYOrN(roi->GetName())) {
		return 0;
	}

	if (m_selectedPart != roi) {
		ResetSelectedPart();
		m_selectedPart = roi;
		EnableColorControlsForSelectedPart(TRUE);
		EnableDecalForSelectedPart(TRUE);
	}

	if (m_clickState == e_displaying && m_animPresenter->PartIsPlaced(m_selectedPart->GetName())) {
		m_displayedPartIsPlaced = TRUE;
	}
	else {
		m_displayedPartIsPlaced = FALSE;
	}
	CalculateStartAndTargetTransforms();
	CalculateStartAndTargetScreenPositions();

	if (m_animPresenter->PartIsPlaced(m_selectedPart->GetName())) {
		if (m_clickState != e_displaying) {
			m_selectedPartStartMousePosition[0] +=
				m_selectedPartStartScreenPosition[0] - m_selectedPartTargetScreenPosition[0];
			m_selectedPartStartMousePosition[1] +=
				m_selectedPartStartScreenPosition[1] - m_selectedPartTargetScreenPosition[1];
		}

		if (m_clickState == e_idle) {
			m_targetBoundingSphere = m_selectedPart->GetWorldBoundingSphere();
		}
	}
	else {
		if (m_animPresenter->IsNextPartToPlace(m_selectedPart->GetName())) {
			m_targetBoundingSphere = m_animPresenter->GetTargetBoundingSphere();
		}
	}

	switch (m_clickState) {
	case e_idle:
		m_clickState = e_selecting;
		break;
	case e_displaying:
		m_clickState = e_returning;
		break;
	}

	m_GetBrick_Sound->Enable(FALSE);
	m_GetBrick_Sound->Enable(TRUE);

	m_animPresenter->SetShelfState(LegoCarBuildAnimPresenter::e_selected);
	return 1;
}

// FUNCTION: LEGO1 0x100246e0
// FUNCTION: BETA10 0x1006d25a
MxLong LegoCarBuild::HandleButtonUp(MxLong p_x, MxLong p_y)
{
	MxLong result = 0;

	switch (m_clickState) {
	case e_returning:
		ResetSelectedPart();
		result = 1;
		break;
	case e_selecting:
		DisplaySelectedPart();
		result = 1;
		break;
	case e_dragging:
		if (m_animPresenter->PartIsPlaced(m_selectedPart->GetName()) &&
			SpheresIntersect(m_targetBoundingSphere, m_selectedPart->GetWorldBoundingSphere())) {
			EnableColorControlsForSelectedPart(FALSE);
			EnableDecalForSelectedPart(FALSE);
			m_clickState = e_idle;
			m_selectedPart = NULL;
			m_PlaceBrick_Sound->Enable(FALSE);
			m_PlaceBrick_Sound->Enable(TRUE);
			m_animPresenter->SetShelfState(LegoCarBuildAnimPresenter::e_stopped);
		}
		else if (m_animPresenter->IsNextPartToPlace(m_selectedPart->GetName())) {
			if (SpheresIntersect(m_targetBoundingSphere, m_selectedPart->GetWorldBoundingSphere())) {
				m_PlaceBrick_Sound->Enable(FALSE);
				m_PlaceBrick_Sound->Enable(TRUE);
				AddSelectedPartToBuild();
			}
			else {
				InitializeDisplayingTransform();
				m_clickState = e_displaying;
			}
		}
		else {
			InitializeDisplayingTransform();
			m_clickState = e_displaying;
		}

		result = 1;
		break;
	}

	return result;
}

// FUNCTION: LEGO1 0x10024850
// FUNCTION: BETA10 0x1006d48e
MxLong LegoCarBuild::HandleMouseMove(MxLong p_x, MxLong p_y)
{
	MxLong result = 0;

	switch (m_clickState) {
	case e_returning:
	case e_selecting:
		m_clickState = e_dragging;
	case e_dragging:
		CalculateSelectedPartMatrix(p_x, p_y);
		result = 1;
		break;
	}

	return result;
}

#ifndef BETA10

// FUNCTION: LEGO1 0x10024890
MxLong LegoCarBuild::HandleControl(MxParam* p_param)
{
	MxLong result = 0;
	LegoControlManagerNotificationParam* param = (LegoControlManagerNotificationParam*) p_param;
	assert(m_buildState);

	if (param->m_enabledChild) {
		switch (param->m_clickedObjectId) {
		// The enum values are all identical between CopterScript, DunecarScript, JetskiScript, and RacecarScript
		case CopterScript::c_Info_Ctl:
			if (m_buildState->m_animationState != LegoVehicleBuildState::e_finishedBuild &&
				m_buildState->m_animationState != LegoVehicleBuildState::e_settingUpMovie &&
				m_buildState->m_animationState != LegoVehicleBuildState::e_exiting &&
				GameState()->GetCurrentAct() != LegoGameState::e_act2) {
				if (m_numAnimsRun > 0) {
					DeleteObjects(&m_atomId, 500, 510);
				}

				m_animPresenter->SetShelfState(LegoCarBuildAnimPresenter::e_selected);
				m_destLocation = LegoGameState::e_infomain;
				TransitionManager()->StartTransition(MxTransitionManager::e_mosaic, 50, FALSE, FALSE);
				result = 1;
			}

			break;
		case CopterScript::c_Exit_Ctl:
			if (m_buildState->m_animationState != LegoVehicleBuildState::e_exiting &&
				m_buildState->m_animationState != LegoVehicleBuildState::e_finishedBuild) {
				if (m_numAnimsRun > 0) {
					DeleteObjects(&m_atomId, 500, 510);
				}

				m_animPresenter->SetShelfState(LegoCarBuildAnimPresenter::e_selected);

				if (GameState()->GetCurrentAct() == LegoGameState::e_act2) {
					InitExiting();
				}
				else if (m_animPresenter->AllPartsPlaced() || m_buildState->m_finishedBuild) {
					m_buildState->m_finishedBuild = TRUE;
					InvokeAction(Extra::e_start, m_atomId, m_carId, NULL);

					NotificationManager()->Send(this, MxNotificationParam());

					m_buildState->m_animationState = LegoVehicleBuildState::e_finishedBuild;
				}
				else {
					StartActorScriptByType(LookupTableActionType::e_leaveUnfinished);
					m_buildState->m_animationState = LegoVehicleBuildState::e_exiting;
				}

				result = 1;
			}
			break;
		case CopterScript::c_ShelfUp_Ctl:
			MoveShelves();
			m_Shelf_Sound->Enable(FALSE);
			m_Shelf_Sound->Enable(TRUE);
			result = 1;
			break;
		case CopterScript::c_Platform_Ctl:
			RotateVehicle();
			m_resetPlacedSelectedPart = c_enabled;
			m_rotateBuild = param->m_enabledChild;
			result = 1;
			break;
		default:
			if ((m_Decals_Ctl && m_Decals_Ctl->GetAction()->GetObjectId() == param->m_clickedObjectId) ||
				(m_Decals_Ctl1 && m_Decals_Ctl1->GetAction()->GetObjectId() == param->m_clickedObjectId) ||
				(m_Decals_Ctl2 && m_Decals_Ctl2->GetAction()->GetObjectId() == param->m_clickedObjectId) ||
				(m_Decals_Ctl3 && m_Decals_Ctl3->GetAction()->GetObjectId() == param->m_clickedObjectId) ||
				(m_Decals_Ctl4 && m_Decals_Ctl4->GetAction()->GetObjectId() == param->m_clickedObjectId) ||
				(m_Decals_Ctl5 && m_Decals_Ctl5->GetAction()->GetObjectId() == param->m_clickedObjectId) ||
				(m_Decals_Ctl6 && m_Decals_Ctl6->GetAction()->GetObjectId() == param->m_clickedObjectId) ||
				(m_Decals_Ctl7 && m_Decals_Ctl7->GetAction()->GetObjectId() == param->m_clickedObjectId)) {
				m_animPresenter->SetPartObjectIdByName(m_selectedPart->GetName(), param->m_clickedObjectId);
				m_Decal_Sound->Enable(FALSE);
				m_Decal_Sound->Enable(TRUE);
			}
			else {
				SetPartColor(param->m_clickedObjectId);
			}

			result = 1;
		}
	}
	else {
		m_resetPlacedSelectedPart = c_disabled;
		m_rotateBuild = -1;
	}

	// It is a bit unexpected that LEGO1 and BETA10 match so well with the `return 1`
	// and ignoring the `result` variable, but the match is hard to argue with
	return 1;
}

#else

// FUNCTION: BETA10 0x1006d512
MxLong LegoCarBuild::HandleControl(MxParam* p_param)
{
	MxLong result = 0;
	LegoControlManagerNotificationParam* param = (LegoControlManagerNotificationParam*) p_param;
	assert(m_buildState);

	if (param->m_enabledChild) {
		switch (param->m_clickedObjectId) {
		case CopterScript::c_Info_Ctl:
			m_animPresenter->SetShelfState(LegoCarBuildAnimPresenter::e_selected);
			m_destLocation = LegoGameState::e_infomain;
			TransitionManager()->StartTransition(MxTransitionManager::e_mosaic, 50, FALSE, FALSE);
			result = 1;
			break;
		case CopterScript::c_Exit_Ctl:
			if (m_buildState->m_animationState != LegoVehicleBuildState::e_exiting) {
				m_animPresenter->SetShelfState(LegoCarBuildAnimPresenter::e_selected);

				if (m_animPresenter->AllPartsPlaced() || m_buildState->m_finishedBuild) {
					m_buildState->m_finishedBuild = TRUE;

					// GameState()->GetCurrentAct() returns an MxS16 in BETA10
					if (GameState()->GetCurrentAct() == 0) {
						InvokeAction(Extra::e_start, m_atomId, m_carId, NULL);

						NotificationManager()->Send(this, MxNotificationParam());

						assert(m_buildState);
						m_buildState->m_animationState = LegoVehicleBuildState::e_finishedBuild;
					}

					else {
						StartActorScriptByType(LookupTableActionType::e_completed);
						m_buildState->m_animationState = LegoVehicleBuildState::e_exiting;
					}
				}
				else {
					StartActorScriptByType(LookupTableActionType::e_leaveUnfinished);
					m_buildState->m_animationState = LegoVehicleBuildState::e_exiting;
				}

				switch (GameState()->m_currentArea) {
				case LegoGameState::e_copterbuild:
					assert(m_carId == Helicopter_Actor);
					break;
				case LegoGameState::e_dunecarbuild:
					assert(m_carId == DuneBugy_Actor);
					break;
				case LegoGameState::e_jetskibuild:
					assert(m_carId == Jetski_Actor);
					break;
				case LegoGameState::e_racecarbuild:
					assert(m_carId == RaceCar_Actor);
					break;
				}

				result = 1;
			}
			break;
		case CopterScript::c_ShelfUp_Ctl:
			MoveShelves();
			m_Shelf_Sound->Enable(FALSE);
			m_Shelf_Sound->Enable(TRUE);
			result = 1;
			break;
		case CopterScript::c_Platform_Ctl:
			RotateVehicle();
			m_resetPlacedSelectedPart = c_enabled;
			m_rotateBuild = param->m_enabledChild;
			result = 1;
			break;
		default:
			if ((m_Decals_Ctl && m_Decals_Ctl->GetAction()->GetObjectId() == param->m_clickedObjectId) ||
				(m_Decals_Ctl1 && m_Decals_Ctl1->GetAction()->GetObjectId() == param->m_clickedObjectId) ||
				(m_Decals_Ctl2 && m_Decals_Ctl2->GetAction()->GetObjectId() == param->m_clickedObjectId) ||
				(m_Decals_Ctl3 && m_Decals_Ctl3->GetAction()->GetObjectId() == param->m_clickedObjectId) ||
				(m_Decals_Ctl4 && m_Decals_Ctl4->GetAction()->GetObjectId() == param->m_clickedObjectId) ||
				(m_Decals_Ctl5 && m_Decals_Ctl5->GetAction()->GetObjectId() == param->m_clickedObjectId) ||
				(m_Decals_Ctl6 && m_Decals_Ctl6->GetAction()->GetObjectId() == param->m_clickedObjectId) ||
				(m_Decals_Ctl7 && m_Decals_Ctl7->GetAction()->GetObjectId() == param->m_clickedObjectId)) {
				m_animPresenter->SetPartObjectIdByName(m_selectedPart->GetName(), param->m_clickedObjectId);
				m_Decal_Sound->Enable(FALSE);
				m_Decal_Sound->Enable(TRUE);
			}
			else {
				SetPartColor(param->m_clickedObjectId);
			}
			result = 1;
		}
	}
	else {
		m_resetPlacedSelectedPart = c_disabled;
		m_rotateBuild = -1;
	}

	return 1;
}

#endif

// FUNCTION: LEGO1 0x10024c20
// FUNCTION: BETA10 0x1006db21
MxLong LegoCarBuild::HandleType0Notification(MxNotificationParam* p_param)
{
	LegoEntity* entity;
	assert(m_buildState);

	switch (m_buildState->m_animationState) {
	case LegoVehicleBuildState::AnimationState::e_finishedBuild:
		entity = (LegoEntity*) Find(m_atomId, m_carId);

		if (entity && entity->GetROI()) {
			// This function was changed between BETA10 and LEGO1.
			// These lines looks like a relic from older code.
			LegoWorld* destWorld = NULL;
			destWorld = FindWorld(*g_isleScript, IsleScript::c__Isle);

			Act1State* gameState = (Act1State*) GameState()->GetState("Act1State");

			switch (GameState()->m_currentArea) {
			case LegoGameState::e_copterbuild:
				if (gameState->m_helicopter) {
					delete gameState->m_helicopter;
				}

				gameState->m_helicopter = (Helicopter*) entity;
				gameState->m_helicopterPlane.Reset();
				break;
			case LegoGameState::e_dunecarbuild:
				if (gameState->m_dunebuggy) {
					delete gameState->m_dunebuggy;
				}

				gameState->m_dunebuggy = (DuneBuggy*) entity;
				gameState->m_dunebuggyPlane.Reset();
				break;
			case LegoGameState::e_jetskibuild:
				if (gameState->m_jetski) {
					delete gameState->m_jetski;
				}

				gameState->m_jetski = (Jetski*) entity;
				gameState->m_jetskiPlane.Reset();
				break;
			case LegoGameState::e_racecarbuild:
				if (gameState->m_racecar) {
					delete gameState->m_racecar;
				}

				gameState->m_racecar = (RaceCar*) entity;
				gameState->m_racecarPlane.Reset();
				break;
			}

			assert(destWorld);
			m_buildState->m_animationState = LegoVehicleBuildState::e_exiting;

			if (!m_animPresenter->AllPartsPlaced()) {
				InitExiting();
			}
			else {
				StartActorScriptByType(LookupTableActionType::e_completed);
			}
		}
		else {
			NotificationManager()->Send(this, MxNotificationParam());
		}
		break;
	case LegoVehicleBuildState::AnimationState::e_settingUpMovie:
		MxU32 jukeboxScript;

		switch (m_carId) {
		case Helicopter_Actor:
			jukeboxScript = JukeboxScript::c_HelicopterBuild_Music;
			break;
		case DuneBugy_Actor:
			jukeboxScript = JukeboxScript::c_DuneCarBuild_Music;
			break;
		case Jetski_Actor:
			jukeboxScript = JukeboxScript::c_JetskiBuild_Music;
			break;
		case RaceCar_Actor:
			jukeboxScript = JukeboxScript::c_RaceCarBuild_Music;
		}

		m_jukeboxPresenter = SoundManager()->FindPresenter(*g_jukeboxScript, jukeboxScript);

		if (m_jukeboxPresenter) {
			BackgroundAudioManager()->SetPendingPresenter(m_jukeboxPresenter, 5, MxPresenter::e_repeating);
			StartIntroduction();
		}
		else {
			// In BETA10, NotificationManager->Send() also takes __FILE__ and __LINE__ arguments
			NotificationManager()->Send(this, MxNotificationParam());
		}
		break;
	}

	return 1;
}

// FUNCTION: LEGO1 0x10024ef0
void LegoCarBuild::StartIntroduction()
{
	ResetViewVelocity();
	m_buildState->m_animationState = LegoVehicleBuildState::e_cutscene;
	StartActorScriptByType(GetNextIntroduction());
	m_buildState->m_introductionCounter += 1;
	Disable(FALSE, LegoOmni::c_disableInput | LegoOmni::c_disable3d | LegoOmni::c_clearScreen);
}

// FUNCTION: LEGO1 0x10024f30
// FUNCTION: BETA10 0x1006dfa0
void LegoCarBuild::MoveShelves()
{
	ResetSelectedPart();
	m_animPresenter->SetShelfState(LegoCarBuildAnimPresenter::e_moving);
}

// FUNCTION: LEGO1 0x10024f50
// FUNCTION: BETA10 0x1006dfce
void LegoCarBuild::RotateVehicle()
{
	m_displayedPartIsPlaced = FALSE;
	m_animPresenter->RotateAroundYAxis(g_rotationAngleStepYAxis);
}

// FUNCTION: LEGO1 0x10024f70
// FUNCTION: BETA10 0x1006e002
void LegoCarBuild::EnableColorControlsForSelectedPart(MxBool p_enabled)
{
	if (m_animPresenter->StringEndsOnY(m_selectedPart->GetName())) {
		SetColorControlsEnabled(p_enabled);
	}
}

// FUNCTION: LEGO1 0x10024fa0
// FUNCTION: BETA10 0x1006e04f
void LegoCarBuild::SetColorControlsEnabled(MxBool p_enabled)
{
	m_presentersEnabled = p_enabled;
	m_ColorBook_Bitmap->Enable(p_enabled);
	m_Yellow_Ctl->Enable(p_enabled);
	m_Red_Ctl->Enable(p_enabled);
	m_Blue_Ctl->Enable(p_enabled);
	m_Green_Ctl->Enable(p_enabled);
	m_Gray_Ctl->Enable(p_enabled);
	m_Black_Ctl->Enable(p_enabled);
}

// FUNCTION: LEGO1 0x10025010
void LegoCarBuild::ToggleColorControlsEnabled()
{
	m_ColorBook_Bitmap->Enable(!m_ColorBook_Bitmap->IsEnabled());
	m_Yellow_Ctl->Enable(!m_Yellow_Ctl->IsEnabled());
	m_Red_Ctl->Enable(!m_Red_Ctl->IsEnabled());
	m_Blue_Ctl->Enable(!m_Blue_Ctl->IsEnabled());
	m_Green_Ctl->Enable(!m_Green_Ctl->IsEnabled());
	m_Gray_Ctl->Enable(!m_Gray_Ctl->IsEnabled());
	m_Black_Ctl->Enable(!m_Black_Ctl->IsEnabled());
}

// FUNCTION: LEGO1 0x100250e0
// FUNCTION: BETA10 0x1006e124
void LegoCarBuild::EnableDecalForSelectedPart(MxBool p_enabled)
{
	if (m_animPresenter->StringDoesNotEndOnZero(m_selectedPart->GetName()) && m_Decals_Ctl) {
		if (strnicmp(m_selectedPart->GetName(), "JSFRNT", strlen("JSFRNT")) == 0) {
			m_Decal_Bitmap->Enable(p_enabled);
			m_Decals_Ctl->Enable(p_enabled);
			m_Decals_Ctl1->Enable(p_enabled);
			m_Decals_Ctl2->Enable(p_enabled);
			m_Decals_Ctl3->Enable(p_enabled);
		}
		else if (strnicmp(m_selectedPart->GetName(), "JSWNSH", strlen("JSWNSH")) == 0) {
			m_Decal_Bitmap->Enable(p_enabled);
			m_Decals_Ctl4->Enable(p_enabled);
			m_Decals_Ctl5->Enable(p_enabled);
			m_Decals_Ctl6->Enable(p_enabled);
			m_Decals_Ctl7->Enable(p_enabled);
		}
		else if (strnicmp(m_selectedPart->GetName(), "RCBACK", strlen("RCBACK")) == 0) {
			m_Decals_Ctl1->Enable(p_enabled);
		}
		else if (strnicmp(m_selectedPart->GetName(), "RCTAIL", strlen("RCTAIL")) == 0) {
			m_Decals_Ctl2->Enable(p_enabled);
		}
		else if (m_Decals_Ctl1 && strnicmp(m_selectedPart->GetName(), "chljety", strlen("chljety")) == 0) {
			m_Decals_Ctl1->Enable(p_enabled);
		}
		else if (m_Decals_Ctl2 && strnicmp(m_selectedPart->GetName(), "chrjety", strlen("chrjety")) == 0) {
			m_Decals_Ctl2->Enable(p_enabled);
		}
		else if (m_Decals_Ctl) {
			m_Decals_Ctl->Enable(p_enabled);
		}
	}
}

// FUNCTION: LEGO1 0x10025350
// FUNCTION: BETA10 0x1006e3c0
void LegoCarBuild::SetPartColor(MxS32 p_objectId)
{
	const LegoChar* color;
	LegoChar buffer[256];

	if (!m_selectedPart) {
		return;
	}

	if (m_Yellow_Ctl->GetAction()->GetObjectId() == p_objectId) {
		color = "lego yellow";
	}
	else if (m_Red_Ctl->GetAction()->GetObjectId() == p_objectId) {
		color = "lego red";
	}
	else if (m_Blue_Ctl->GetAction()->GetObjectId() == p_objectId) {
		color = "lego blue";
	}
	else if (m_Green_Ctl->GetAction()->GetObjectId() == p_objectId) {
		color = "lego green";
	}
	else if (m_Gray_Ctl->GetAction()->GetObjectId() == p_objectId) {
		color = "lego white";
	}
	else if (m_Black_Ctl->GetAction()->GetObjectId() == p_objectId) {
		color = "lego black";
	}
	else {
		return;
	}

	m_Paint_Sound->Enable(FALSE);
	m_Paint_Sound->Enable(TRUE);
	m_selectedPart->SetColorByName(color);
	sprintf(buffer, "c_%s", m_selectedPart->GetName());
	VariableTable()->SetVariable(buffer, color);
}

// FUNCTION: LEGO1 0x10025450
// FUNCTION: BETA10 0x1006e599
void LegoCarBuild::CalculateStartAndTargetTransforms()
{
	m_originalSelectedPartTransform = m_selectedPart->GetLocal2World();
	m_displayTransform = m_originalSelectedPartTransform;

	Vector3 displayPosition(m_displayTransform[3]);
	displayPosition = Vector3(m_animPresenter->GetBuildViewMatrix()[3]);

	// This looks odd, but it improves the LEGO1 match while breaking the BETA10 match.
	// I don't know whether this is due to compiler entropy.
	// Feel free to replace selectedPartStartTransform -> m_selectedPartStartTransform and remove this variable if it
	// improves the LEGO1 match in the future.
	MxMatrix* selectedPartStartTransform = &m_selectedPartStartTransform;
	*selectedPartStartTransform = m_originalSelectedPartTransform;

	if (m_animPresenter->PartIsPlaced(m_selectedPart->GetName())) {
		m_selectedPartStartPosition = Vector4(m_selectedPart->GetWorldPosition());

		if (!m_displayedPartIsPlaced) {
			m_selectedPartTargetPosition = m_selectedPartStartPosition;

			m_selectedPartTargetTransform = m_originalSelectedPartTransform;
			m_selectedPartStartPosition[0] += m_displayTransform[3][0] - m_selectedPartTargetTransform[3][0];
			m_selectedPartStartPosition[1] += m_displayTransform[3][1] - m_selectedPartTargetTransform[3][1];
			m_selectedPartStartPosition[2] += m_displayTransform[3][2] - m_selectedPartTargetTransform[3][2];
		}

		*selectedPartStartTransform = m_displayTransform;
	}
	else {
		const LegoChar* wiredName;

		if (!m_animPresenter->IsNextPartToPlace(m_selectedPart->GetName())) {
			wiredName = m_animPresenter->GetWiredNameByPartName(m_selectedPart->GetName());
		}
		else {
			wiredName = m_animPresenter->GetWiredNameOfLastPlacedPart();
		}

		LegoROI* parentROI = (LegoROI*) m_selectedPart->GetParentROI();
		m_selectedPartTargetTransform = parentROI->FindChildROI(wiredName, parentROI)->GetLocal2World();
		m_selectedPartTargetPosition = Vector4(parentROI->FindChildROI(wiredName, parentROI)->GetWorldPosition());
		m_selectedPartStartPosition = Vector4(m_selectedPart->GetWorldPosition());

		m_selectedPartStartPosition[2] += (m_displayTransform[3][2] - m_originalSelectedPartTransform[3][2]);
		m_selectedPartStartTransform[3][2] = m_displayTransform[3][2];
	}
}

// FUNCTION: LEGO1 0x100256c0
// FUNCTION: BETA10 0x1006e96c
void LegoCarBuild::Enable(MxBool p_enable)
{
	LegoWorld::Enable(p_enable);

	if (p_enable) {
		InputManager()->SetWorld(this);
		SetIsWorldActive(FALSE);
	}
	else {
		BackgroundAudioManager()->Init();
		if (InputManager()->GetWorld() == this) {
			InputManager()->ClearWorld();
		}
	}
}

// FUNCTION: BETA10 0x10070520
inline MxU32 LegoCarBuild::GetLookupIndex()
{
	switch (m_carId) {
	case Helicopter_Actor:
		return 2;
	case DuneBugy_Actor:
		return 0;
	case Jetski_Actor:
		return 1;
	case RaceCar_Actor:
		return 3;
	default:
		assert(0);
		return 0;
	}
}

inline void LegoCarBuild::StopPlayingActorScript()
{
	// There is no direct evidence for this inline function in LEGO1,
	// but some code doesn't make much sense otherwise. For example,
	// sometimes `m_playingActorScript` is set to another value right below this call,
	// which the original developer would likely have refactored.
	if (m_playingActorScript != DS_NOT_A_STREAM) {
		InvokeAction(Extra::ActionType::e_stop, m_atomId, m_playingActorScript, NULL);
		m_playingActorScript = DS_NOT_A_STREAM;
	}
}

// FUNCTION: LEGO1 0x10025720
// FUNCTION: BETA10 0x1006e9df
void LegoCarBuild::StartActorScriptByType(MxS32 p_actionType)
{
	m_numAnimsRun++;
	m_lastActorScript = 0;
	MxS32 nextActorScript;

#ifndef BETA10
	if (GameState()->GetCurrentAct() == LegoGameState::e_act2) {
		// This is most likely related to the helicopter rebuild in Act 2
		switch (p_actionType) {
		case LookupTableActionType::e_introduction0:
		case LookupTableActionType::e_introduction1:
		case LookupTableActionType::e_introduction2:
		case LookupTableActionType::e_introduction3:
			switch (rand() % 3) {
			case 0:
				m_lastActorScript = CopterScript::c_ips004d2_RunAnim;
				StopPlayingActorScript();
				m_playingActorScript = CopterScript::c_ips004d2_RunAnim;
				BackgroundAudioManager()->LowerVolume();
				InvokeAction(Extra::ActionType::e_start, m_atomId, CopterScript::c_ips004d2_RunAnim, NULL);
				break;
			case 1:
				m_lastActorScript = CopterScript::c_ips006d2_RunAnim;
				StopPlayingActorScript();
				m_playingActorScript = CopterScript::c_ips006d2_RunAnim;
				BackgroundAudioManager()->LowerVolume();
				InvokeAction(Extra::ActionType::e_start, m_atomId, CopterScript::c_ips006d2_RunAnim, NULL);
				break;
			case 2:
				m_lastActorScript = CopterScript::c_slp01xd2_RunAnim;
				StopPlayingActorScript();
				m_playingActorScript = CopterScript::c_slp01xd2_RunAnim;
				BackgroundAudioManager()->LowerVolume();
				InvokeAction(Extra::ActionType::e_start, m_atomId, CopterScript::c_slp01xd2_RunAnim, NULL);
				break;
			}
			break;
		case LookupTableActionType::e_leaveUnfinished:
			StartActorScript(g_actorScripts[GetLookupIndex()].m_leaveUnfinished);
			break;
		case LookupTableActionType::e_completed:
			StartActorScript(g_actorScripts[GetLookupIndex()].m_completed);
			break;
		case LookupTableActionType::e_shortExplanation:
			m_lastActorScript = g_actorScripts[GetLookupIndex()].m_shortExplanation;
			nextActorScript = m_lastActorScript;
			StopPlayingActorScript();

			if (nextActorScript != DS_NOT_A_STREAM) {
				m_playingActorScript = nextActorScript;
				BackgroundAudioManager()->LowerVolume();
				InvokeAction(Extra::ActionType::e_start, m_atomId, nextActorScript, NULL);
			}

			break;
		default:
			m_numAnimsRun--;
			return;
		}
	}
	else {
#endif
		// This part doesn't match BETA10 perfectly, but it's the closest we get without hundreds of #ifdef's
		switch (p_actionType) {
		case LookupTableActionType::e_introduction0:
			m_lastActorScript = g_actorScripts[GetLookupIndex()].m_introduction0;
			StartActorScript(m_lastActorScript);
			break;
		case LookupTableActionType::e_introduction1:
			m_lastActorScript = g_actorScripts[GetLookupIndex()].m_introduction1;
			StartActorScript(m_lastActorScript);

			if (m_carId == DuneBugy_Actor) {
				m_lastActorScript = 0;
			}

			break;
		case LookupTableActionType::e_introduction2:
			m_lastActorScript = g_actorScripts[GetLookupIndex()].m_introduction2;
			StartActorScript(m_lastActorScript);

			if (m_carId != Jetski_Actor) {
				m_lastActorScript = 0;
			}

			break;
		case LookupTableActionType::e_introduction3:
			StartActorScript(g_actorScripts[GetLookupIndex()].m_introduction3);
			break;
		case LookupTableActionType::e_leaveUnfinished:
			StartActorScript(g_actorScripts[GetLookupIndex()].m_leaveUnfinished);
			break;
		case LookupTableActionType::e_completed:
			StartActorScript(g_actorScripts[GetLookupIndex()].m_completed);
			break;
		case LookupTableActionType::e_shortExplanation:
			m_lastActorScript = g_actorScripts[GetLookupIndex()].m_shortExplanation;
			StartActorScript(m_lastActorScript);
			break;
		default:
			assert(0);
			m_numAnimsRun--;

			// Weird: This assertion can never be executed. The `assert(0)` above was probably introduced later.
			assert(m_numAnimsRun >= 0);
			return;
		}
#ifndef BETA10
	}
#endif

	if (m_lastActorScript != 0) {
		m_lastActorScriptStartTime = timeGetTime();
	}
}

// FUNCTION: LEGO1 0x10025d10
// FUNCTION: BETA10 0x10070490
void LegoCarBuild::StartActorScript(MxS32 p_streamId)
{
	// this function has a different signature and partially different body in BETA10, but it is called in the same
	// places
	if (m_playingActorScript != DS_NOT_A_STREAM) {
		InvokeAction(Extra::ActionType::e_stop, m_atomId, m_playingActorScript, NULL);
		m_playingActorScript = DS_NOT_A_STREAM;
	}

	if (p_streamId != DS_NOT_A_STREAM) {
		m_playingActorScript = p_streamId;
		BackgroundAudioManager()->LowerVolume();
		InvokeAction(Extra::ActionType::e_start, m_atomId, p_streamId, NULL);
	}
}

// FUNCTION: LEGO1 0x10025d70
MxS32 LegoCarBuild::GetNextIntroduction()
{
	switch (m_buildState->m_introductionCounter % 3) {
	case 1:
		return LookupTableActionType::e_introduction1;
	case 2:
		return LookupTableActionType::e_introduction2;
	case 3:
		return LookupTableActionType::e_introduction3;
	default:
		return LookupTableActionType::e_introduction0;
	}
}

// FUNCTION: LEGO1 0x10025db0
// FUNCTION: BETA10 0x1006ed18
void LegoCarBuild::TickleControl(const char* p_controlName, MxULong p_time)
{
	m_tickledControl = (MxControlPresenter*) Find("MxControlPresenter", p_controlName);

	MxS16 expectedState = 1 - ((p_time / 5) & 1);

	if (m_Yellow_Ctl == m_tickledControl) {
		if (expectedState != g_lastTickleState) {
			ToggleColorControlsEnabled();
			g_lastTickleState = expectedState;
		}
	}
	else {
		if (m_tickledControl->GetEnabledChild() != expectedState) {
			m_tickledControl->UpdateEnabledChild(expectedState);
		}

		g_lastTickleState = -1;
		SetColorControlsEnabled(m_presentersEnabled);
	}
}

// FUNCTION: LEGO1 0x10025e40
void LegoCarBuild::HandleEndAnim()
{
	SetColorControlsEnabled(m_presentersEnabled);
	if (m_tickledControl && m_Yellow_Ctl != m_tickledControl) {
		m_tickledControl->UpdateEnabledChild(0);
	}
}

// FUNCTION: LEGO1 0x10025e70
MxBool LegoCarBuild::Escape()
{
	BackgroundAudioManager()->Init();
	MxS32 targetEntityId = GetBuildMovieId(m_carId);
	InvokeAction(Extra::ActionType::e_stop, *g_jukeboxScript, targetEntityId, NULL);
	DeleteObjects(&m_atomId, 500, 999);

	m_buildState->m_animationState = LegoVehicleBuildState::e_none;
	m_destLocation = LegoGameState::e_infomain;
	return TRUE;
}

// FUNCTION: LEGO1 0x10025ee0
MxS32 LegoCarBuild::GetBuildMovieId(MxS32 p_carId)
{
	switch (p_carId) {
	case Helicopter_Actor:
		return JukeboxScript::c_HelicopterBuild_Movie;
	case DuneBugy_Actor:
		return JukeboxScript::c_DuneCarBuild_Movie;
	case Jetski_Actor:
		return JukeboxScript::c_JetskiBuild_Movie;
	case RaceCar_Actor:
		return JukeboxScript::c_RaceCarBuild_Movie;
	default:
		return -1;
	}
}

// FUNCTION: LEGO1 0x10025f30
LegoVehicleBuildState::LegoVehicleBuildState(const char* p_classType)
{
	m_className = p_classType;
	m_introductionCounter = 0;
	m_finishedBuild = FALSE;
	m_playedExitScript = FALSE;
	m_placedPartCount = 0;
}

// FUNCTION: LEGO1 0x10026120
// FUNCTION: BETA10 0x1006eef0
MxResult LegoVehicleBuildState::Serialize(LegoStorage* p_storage)
{
	LegoState::Serialize(p_storage);

	if (p_storage->IsReadMode()) {
		p_storage->ReadU8(m_introductionCounter);
		p_storage->ReadU8(m_finishedBuild);
		p_storage->ReadU8(m_playedExitScript);
#ifndef BETA10
		p_storage->ReadU8(m_placedPartCount);
#endif
	}
	else {
		p_storage->WriteU8(m_introductionCounter);
		p_storage->WriteU8(m_finishedBuild);
		p_storage->WriteU8(m_playedExitScript);
#ifndef BETA10
		p_storage->WriteU8(m_placedPartCount);
#endif
	}

	return SUCCESS;
}
