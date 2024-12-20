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
LegoCarBuild::LookupTableActions LegoCarBuild::g_unk0x100d65b0[] = {
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
MxFloat LegoCarBuild::g_unk0x100d65a4 = -0.1f;

// GLOBAL: LEGO1 0x100d65a8
MxFloat LegoCarBuild::g_rotationAngleStepYAxis = 0.07;

// GLOBAL: LEGO1 0x100f11cc
MxS16 LegoCarBuild::g_unk0x100f11cc = -1;

// FUNCTION: LEGO1 0x100226d0
// FUNCTION: BETA10 0x1006ac10
LegoCarBuild::LegoCarBuild()
{
	m_unk0x100 = 0;
	m_unk0x110 = 0;
	m_unk0xf8 = c_unknownminusone;
	m_unk0x2d4 = FALSE;
	m_unk0x258 = 0;
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
	m_unk0x33c = NULL;
	m_buildState = NULL;
	m_unk0x104 = 0;
	m_unk0x109 = 0;
	m_numAnimsRun = 0;
	m_unk0x338 = 0;
	m_destLocation = LegoGameState::e_undefined;
	m_unk0x344 = DS_NOT_A_STREAM;
	m_unk0x174 = 0;
	NotificationManager()->Register(this);
}

// FUNCTION: LEGO1 0x10022930
// FUNCTION: BETA10 0x10070070
MxBool LegoCarBuild::VTable0x5c()
{
	return TRUE;
}

// FUNCTION: LEGO1 0x10022a80
// FUNCTION: BETA10 0x1006aea3
LegoCarBuild::~LegoCarBuild()
{
	m_unk0x100 = 0;
	m_unk0x110 = NULL;

	if (m_unk0x258) {
		m_unk0x258->SetUnknown0xbc(0);
		m_unk0x258->SetTickleState(MxPresenter::e_idle);
		m_unk0x258 = NULL;
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
		m_unk0x174 = m_buildState->m_unk0x4d;

		GameState()->StopArea(LegoGameState::e_previousArea);

		m_buildState->m_animationState = LegoVehicleBuildState::e_entering;
		m_unk0x100 = 0;

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
	assert(m_Decal_Bitmap);
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
void LegoCarBuild::FUN_10022f00()
{
	if (m_unk0x110) {
		VTable0x6c();
		m_unk0x258->SetUnknown0xbc(0);
		m_unk0x100 = 5;
	}
}

// FUNCTION: LEGO1 0x10022f30
// FUNCTION: BETA10 0x1006b835
void LegoCarBuild::FUN_10022f30()
{
	if (m_unk0x110) {
		FUN_10024f70(FALSE);
		FUN_100250e0(FALSE);

		if (m_unk0x258->PartIsPlaced(m_unk0x110->GetName())) {
			m_PlaceBrick_Sound->Enable(FALSE);
			m_PlaceBrick_Sound->Enable(TRUE);
		}

		m_unk0x258->SetUnknown0xbc(1);
		m_unk0x258->PutFrame();
		m_unk0x110 = NULL;
		m_unk0x100 = 0;
	}
}

// FUNCTION: LEGO1 0x10022fc0
// FUNCTION: BETA10 0x1006b90b
void LegoCarBuild::VTable0x6c()
{
	m_unk0x178 = m_unk0x1c0;
	m_unk0x110->WrappedSetLocalTransform(m_unk0x178);
	m_unk0x2a4 = Vector4(m_unk0x110->GetWorldPosition());

	VTable0x70();
}

// FUNCTION: LEGO1 0x10023020
// FUNCTION: BETA10 0x1006b991
void LegoCarBuild::VTable0x70()
{
	MxFloat worldPos[3];
	MxFloat screenPos[4];

	worldPos[0] = m_unk0x2a4[0];
	worldPos[1] = m_unk0x2a4[1];
	worldPos[2] = m_unk0x2a4[2];

	TransformWorldToScreen(worldPos, screenPos);

	m_unk0x290[0] = screenPos[0] / screenPos[3];
	m_unk0x290[1] = screenPos[1] / screenPos[3];

	worldPos[0] = m_unk0x2bc[0];
	worldPos[1] = m_unk0x2bc[1];
	worldPos[2] = m_unk0x2bc[2];

	TransformWorldToScreen(worldPos, screenPos);

	m_unk0x298[0] = screenPos[0] / screenPos[3];
	m_unk0x298[1] = screenPos[1] / screenPos[3];

	m_unk0x2a0 = sqrt((MxDouble) DISTSQRD2(m_unk0x290, m_unk0x298));

	m_unk0x25c.BETA_1004a9b0(m_unk0x178, m_unk0x208);
}

// FUNCTION: LEGO1 0x10023130
// FUNCTION: BETA10 0x1006bb22
void LegoCarBuild::FUN_10023130(MxLong p_x, MxLong p_y)
{
	if (m_unk0x110) {
		MxFloat pfVar3[2];
		MxFloat local30[3];
		MxFloat local84[3];

		p_x += (m_unk0x290[0] - m_unk0x250[0]);
		p_y += (m_unk0x290[1] - m_unk0x250[1]);

		pfVar3[0] = p_x;
		pfVar3[1] = p_y;

		if (FUN_1003ded0(pfVar3, local30, local84)) {
			MxFloat local18[3];
			MxFloat local8c[2];

			local8c[0] = p_x;
			local8c[1] = p_y;

			local18[0] = 0;
			local18[1] = 0;
			local18[2] = 0;

			MxMatrix local78;

			if (p_y < m_unk0x290[1]) {
				VTable0x74(local8c, local18);
			}
			else if (p_y > m_unk0x298[1]) {
				VTable0x7c(local8c, local18);
			}
			else if (p_y >= m_unk0x290[1]) {
				VTable0x78(local8c, local18);
			}

			MxS32 local20[2];

			local20[0] = p_x - m_unk0x290[0];
			local20[1] = p_y - m_unk0x290[1];

			MxFloat local1c = sqrt((double) (NORMSQRD2(local20))) / m_unk0x2a0;

			m_unk0x25c.BETA_1004aaa0(local78, local1c);

			local78[3][0] = m_unk0x178[3][0] + local18[0];
			local78[3][1] = m_unk0x178[3][1] + local18[1];
			local78[3][2] = m_unk0x178[3][2] + local18[2];
			local78[3][3] = 1.0;

			m_unk0x110->WrappedSetLocalTransform(local78);
		}
	}
}

// FUNCTION: LEGO1 0x10023500
// FUNCTION: BETA10 0x1006bdf6
void LegoCarBuild::VTable0x74(MxFloat p_param1[2], MxFloat p_param2[3])
{
	MxFloat fVar1;
	MxFloat local20[3];
	MxFloat local14[3];

	FUN_1003ded0(p_param1, local14, local20);

	fVar1 = (m_unk0x2a4[2] - local20[2]) / local14[2];
	p_param2[0] = (fVar1 * local14[0] + local20[0]) - m_unk0x2a4[0];
	p_param2[1] = (fVar1 * local14[1] + local20[1]) - m_unk0x2a4[1];
	p_param2[2] = 0.0;
}

// FUNCTION: LEGO1 0x10023570
// FUNCTION: BETA10 0x1006be91
void LegoCarBuild::VTable0x78(MxFloat p_param1[2], MxFloat p_param2[3])
{
	MxFloat fVar1;
	MxFloat local18[3];
	MxFloat localc[3];

	FUN_1003ded0(p_param1, local18, localc);

	p_param2[2] = m_unk0x2a4[2] +
				  (m_unk0x2bc[2] - m_unk0x2a4[2]) * ((p_param1[1] - m_unk0x290[1]) / (m_unk0x298[1] - m_unk0x290[1]));
	fVar1 = (p_param2[2] - localc[2]) / local18[2];
	p_param2[0] = fVar1 * local18[0] - m_unk0x2a4[0] + localc[0];
	p_param2[1] = fVar1 * local18[1] - m_unk0x2a4[1] + localc[1];
	p_param2[2] = p_param2[2] - m_unk0x2a4[2];
}

// FUNCTION: LEGO1 0x10023620
// FUNCTION: BETA10 0x1006bfb5
void LegoCarBuild::VTable0x7c(MxFloat p_param1[2], MxFloat p_param2[3])
{
	MxFloat local18[3];
	MxFloat localc[3];
	FUN_1003ded0(p_param1, local18, localc);

	MxFloat fVar1 = (m_unk0x2bc[1] - localc[1]) / local18[1];
	p_param2[0] = fVar1 * local18[0] - m_unk0x2a4[0] + localc[0];
	p_param2[1] = m_unk0x2bc[1] - m_unk0x2a4[1];
	p_param2[2] = fVar1 * local18[2] - m_unk0x2a4[2] + localc[2];
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
void LegoCarBuild::FUN_100236d0()
{
	MxS32 pLVar2;

	FUN_10024f70(FALSE);
	FUN_100250e0(FALSE);
	m_unk0x258->FUN_10079790(m_unk0x110->GetName());
	m_unk0x258->SetUnknown0xbc(1);
	m_unk0x110 = NULL;
	m_unk0x100 = 0;

	if (m_unk0x258->AllPartsPlaced()) {
		// Note the code duplication with LEGO1 0x10025ee0
		switch (m_carId) {
		case 1:
			pLVar2 = 0x2f;
			break;
		case 2:
			pLVar2 = 0x31;
			break;
		case 3:
			pLVar2 = 0x33;
			break;
		case 4:
			pLVar2 = 0x35;
		}

		BackgroundAudioManager()->Init();
		InvokeAction(Extra::e_stop, *g_jukeboxScript, pLVar2, NULL);

		if (m_numAnimsRun > 0) {
			DeleteObjects(&m_atomId, 500, 510);
		}

		if (GameState()->GetCurrentAct() == LegoGameState::e_act2) {
			FUN_100243a0();
		}
		else {
			m_buildState->m_unk0x4d = TRUE;
			InvokeAction(Extra::e_start, m_atomId, m_carId, NULL);
			NotificationManager()->Send(this, MxNotificationParam());
			m_buildState->m_animationState = LegoVehicleBuildState::e_unknown4;
			m_buildState->m_placedPartCount = 0;
		}
	}
}

#define LEGOCARBUILD_TICKLE_CASE(subtract, start, end, str)                                                            \
	if (start < dTime && dTime < end) {                                                                                \
		FUN_10025db0(str, dTime - subtract);                                                                           \
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

	if (m_unk0xf8 == c_unknown8) {
		if (m_unk0xfc == 1) {
			FUN_10024f50();
		}

		if (m_unk0x110) {
			if (m_unk0x258->PartIsPlaced(m_unk0x110->GetName())) {
				FUN_10022f30();
			}
		}
	}

	if (m_unk0x100 == 5 && m_unk0x110) {
		RotateY(m_unk0x110, g_unk0x100d65a4);
	}

	if (m_unk0x10a) {
		DWORD time = timeGetTime();
		DWORD dTime = (time - m_unk0x10c) / 100;

		if (m_carId == RaceCar_Actor) {
			switch (m_unk0x10a) {
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
			switch (m_unk0x10a) {
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
			switch (m_unk0x10a) {
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
			switch (m_unk0x10a) {
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
			FUN_10024c20((LegoEventNotificationParam*) &p_param);
			result = 1;
			break;
		case c_notificationEndAction:
			result = FUN_10024480((MxActionNotificationParam*) &p_param);
			break;
		case c_notificationKeyPress:
			result = FUN_10024250((LegoEventNotificationParam*) &p_param);
			break;
		case c_notificationButtonUp:
			result = FUN_100246e0(
				((LegoEventNotificationParam&) p_param).GetX(),
				((LegoEventNotificationParam&) p_param).GetY()
			);

			if (result || m_unk0x10a || m_buildState->m_animationState == 4 || m_buildState->m_animationState == 6) {
				m_unk0x109 = 0;
				break;
			}

			if (++m_unk0x109 > 2) {
				FUN_10025720(6);
				m_unk0x109 = 0;
			}

			break;
		case c_notificationButtonDown:
			assert(m_buildState);
			if (((m_buildState->m_animationState != 4) && (m_buildState->m_animationState != 6)) &&
				(m_buildState->m_animationState != 2)) {
				m_buildState->m_animationState = LegoVehicleBuildState::e_unknown0;
				result = FUN_100244e0(
					((LegoEventNotificationParam&) p_param).GetX(),
					((LegoEventNotificationParam&) p_param).GetY()
				);
			}

			break;
		case c_notificationMouseMove:
			result = FUN_10024850(
				((LegoEventNotificationParam&) p_param).GetX(),
				((LegoEventNotificationParam&) p_param).GetY()
			);

			if (result == 1) {
				m_unk0x109 = 0;
			}

			break;
		case c_notificationControl:
			result = FUN_10024890(&p_param);

			if (result == 1) {
				m_unk0x109 = 0;
			}

			break;
		case c_notificationEndAnim:
			if (m_numAnimsRun > 0) {
				m_numAnimsRun -= 1;
			}

			FUN_10025e40();
			m_unk0x10a = 0;
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
undefined4 LegoCarBuild::FUN_10024250(LegoEventNotificationParam* p_param)
{
	if (p_param->GetKey() == ' ' && m_buildState->m_animationState != 4 && m_buildState->m_animationState != 2) {
		if (m_numAnimsRun > 0) {
			DeleteObjects(&m_atomId, 500, 0x1fe);
			BackgroundAudioManager()->RaiseVolume();
			m_unk0x109 = 0;
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
		InvokeAction(Extra::ActionType::e_start, *g_jukeboxScript, FUN_10025ee0(m_carId), NULL);
		m_buildState->m_animationState = LegoVehicleBuildState::e_unknown2;
		NotificationManager()->Send(this, MxNotificationParam());
	}
	else {
		FUN_10024ef0();
	}
}

// FUNCTION: LEGO1 0x100243a0
void LegoCarBuild::FUN_100243a0()
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
		m_destLocation = LegoGameState::Area::e_unk17;
		TransitionManager()->StartTransition(MxTransitionManager::TransitionType::e_mosaic, 50, FALSE, FALSE);
		break;
	case RaceCar_Actor:
		m_destLocation = LegoGameState::Area::e_unk20;
		TransitionManager()->StartTransition(MxTransitionManager::TransitionType::e_mosaic, 50, FALSE, FALSE);
	}
}

// FUNCTION: LEGO1 0x10024480
undefined4 LegoCarBuild::FUN_10024480(MxActionNotificationParam* p_param)
{
	MxS32 result = 0;

	switch (m_buildState->m_animationState) {
	case 3:
		BackgroundAudioManager()->RaiseVolume();
		m_buildState->m_animationState = LegoVehicleBuildState::e_unknown0;
		result = 1;
		break;
	case 6:
		if (p_param->GetAction()->GetObjectId() == m_unk0x344) {
			FUN_100243a0();
			result = 1;
			break;
		}
	}

	return result;
}

// FUNCTION: LEGO1 0x100244e0
// FUNCTION: BETA10 0x1006cfb6
undefined4 LegoCarBuild::FUN_100244e0(MxLong p_x, MxLong p_y)
{
	m_unk0x250[0] = p_x;
	m_unk0x250[1] = p_y;

	LegoROI* roi = PickROI(p_x, p_y);

	if (!roi || !m_unk0x258->StringEndsOnYOrN(roi->GetName())) {
		return 0;
	}

	if (m_unk0x110 != roi) {
		FUN_10022f30();
		m_unk0x110 = roi;
		FUN_10024f70(TRUE);
		FUN_100250e0(TRUE);
	}

	if (m_unk0x100 == 5 && m_unk0x258->PartIsPlaced(m_unk0x110->GetName())) {
		m_unk0x2d4 = TRUE;
	}
	else {
		m_unk0x2d4 = FALSE;
	}
	FUN_10025450();
	VTable0x70();

	if (m_unk0x258->PartIsPlaced(m_unk0x110->GetName())) {
		if (m_unk0x100 != 5) {
			m_unk0x250[0] += m_unk0x290[0] - m_unk0x298[0];
			m_unk0x250[1] += m_unk0x290[1] - m_unk0x298[1];
		}

		if (m_unk0x100 == 0) {
			m_unk0x114 = m_unk0x110->GetWorldBoundingSphere();
		}
	}
	else {
		if (m_unk0x258->FUN_10079c30(m_unk0x110->GetName())) {
			m_unk0x114 = m_unk0x258->FUN_10079e20();
		}
	}

	switch (m_unk0x100) {
	case 0:
		m_unk0x100 = 4;
		break;
	case 5:
		m_unk0x100 = 3;
		break;
	}

	m_GetBrick_Sound->Enable(FALSE);
	m_GetBrick_Sound->Enable(TRUE);

	m_unk0x258->SetUnknown0xbc(0);
	return 1;
}

// FUNCTION: LEGO1 0x100246e0
undefined4 LegoCarBuild::FUN_100246e0(MxLong p_x, MxLong p_y)
{
	switch (m_unk0x100) {
	case 3:
		FUN_10022f30();
		return 1;
	case 4:
		FUN_10022f00();
		return 1;
	case 6:
		if (m_unk0x258->PartIsPlaced(m_unk0x110->GetName())) {
			if (SpheresIntersect(m_unk0x114, m_unk0x110->GetWorldBoundingSphere())) {
				FUN_10024f70(FALSE);
				FUN_100250e0(FALSE);
				m_unk0x100 = 0;
				m_unk0x110 = NULL;
				m_PlaceBrick_Sound->Enable(FALSE);
				m_PlaceBrick_Sound->Enable(TRUE);
				m_unk0x258->SetUnknown0xbc(1);
				return 1;
			}
		}

		if (m_unk0x258->FUN_10079c30(m_unk0x110->GetName())) {
			if (SpheresIntersect(m_unk0x114, m_unk0x110->GetWorldBoundingSphere())) {
				m_PlaceBrick_Sound->Enable(FALSE);
				m_PlaceBrick_Sound->Enable(TRUE);
				FUN_100236d0();
				return 1;
			}

			VTable0x6c();
			m_unk0x100 = 5;
			return 1;
		}

		VTable0x6c();
		m_unk0x100 = 5;
		return 1;
	default:
		return 0;
	}
}

// FUNCTION: LEGO1 0x10024850
// FUNCTION: BETA10 0x1006d48e
MxS32 LegoCarBuild::FUN_10024850(MxLong p_x, MxLong p_y)
{
	MxS32 result = 0;

	switch (m_unk0x100) {
	case 3:
	case 4:
		m_unk0x100 = 6;
	case 6:
		FUN_10023130(p_x, p_y);
		result = 1;
		break;
	}

	return result;
}

#ifdef NDEBUG

// FUNCTION: LEGO1 0x10024890
undefined4 LegoCarBuild::FUN_10024890(MxParam* p_param)
{
	undefined4 result = 0;
	LegoControlManagerNotificationParam* param = (LegoControlManagerNotificationParam*) p_param;
	assert(m_buildState);

	if (param->m_unk0x28) {
		switch (param->m_clickedObjectId) {
		// The enum values are all identical between CopterScript, DunecarScript, JetskiScript, and RacecarScript
		case CopterScript::c_Info_Ctl:
			if (m_buildState->m_animationState != LegoVehicleBuildState::e_unknown4 &&
				m_buildState->m_animationState != LegoVehicleBuildState::e_unknown2 &&
				m_buildState->m_animationState != LegoVehicleBuildState::e_exiting &&
				GameState()->GetCurrentAct() != LegoGameState::e_act2) {
				if (m_numAnimsRun > 0) {
					DeleteObjects(&m_atomId, 500, 510);
				}

				m_unk0x258->SetUnknown0xbc(0);
				m_destLocation = LegoGameState::e_infomain;
				TransitionManager()->StartTransition(MxTransitionManager::e_mosaic, 50, FALSE, FALSE);
				result = 1;
			}

			break;
		case CopterScript::c_Exit_Ctl:
			if (m_buildState->m_animationState != LegoVehicleBuildState::e_exiting &&
				m_buildState->m_animationState != LegoVehicleBuildState::e_unknown4) {
				if (m_numAnimsRun > 0) {
					DeleteObjects(&m_atomId, 500, 510);
				}

				m_unk0x258->SetUnknown0xbc(0);

				if (GameState()->GetCurrentAct() == LegoGameState::e_act2) {
					FUN_100243a0();
				}
				else if (m_unk0x258->AllPartsPlaced() || m_buildState->m_unk0x4d) {
					m_buildState->m_unk0x4d = TRUE;
					InvokeAction(Extra::e_start, m_atomId, m_carId, NULL);

					NotificationManager()->Send(this, MxNotificationParam());

					m_buildState->m_animationState = LegoVehicleBuildState::e_unknown4;
				}
				else {
					FUN_10025720(4);
					m_buildState->m_animationState = LegoVehicleBuildState::e_exiting;
				}

				result = 1;
			}
			break;
		case CopterScript::c_ShelfUp_Ctl:
			FUN_10024f30();
			m_Shelf_Sound->Enable(FALSE);
			m_Shelf_Sound->Enable(TRUE);
			result = 1;
			break;
		case CopterScript::c_Platform_Ctl:
			FUN_10024f50();
			m_unk0xf8 = c_unknown8;
			m_unk0xfc = param->m_unk0x28;
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
				m_unk0x258->SetPartObjectIdByName(m_unk0x110->GetName(), param->m_clickedObjectId);
				m_Decal_Sound->Enable(FALSE);
				m_Decal_Sound->Enable(TRUE);
			}
			else {
				FUN_10025350(param->m_clickedObjectId);
			}

			result = 1;
		}
	}
	else {
		m_unk0xf8 = c_unknownminusone;
		m_unk0xfc = -1;
	}

	// It is a bit unexpected that LEGO1 and BETA10 match so well with the `return 1`
	// and ignoring the `result` variable, but the match is hard to argue with
	return 1;
}

#else

// FUNCTION: BETA10 0x1006d512
undefined4 LegoCarBuild::FUN_10024890(MxParam* p_param)
{
	undefined4 result = 0;
	LegoControlManagerNotificationParam* param = (LegoControlManagerNotificationParam*) p_param;
	assert(m_buildState);

	if (param->m_unk0x28) {
		switch (param->m_clickedObjectId) {
		case CopterScript::c_Info_Ctl:
			m_unk0x258->SetUnknown0xbc(0);
			m_destLocation = LegoGameState::e_infomain;
			TransitionManager()->StartTransition(MxTransitionManager::e_mosaic, 50, FALSE, FALSE);
			result = 1;
			break;
		case CopterScript::c_Exit_Ctl:
			if (m_buildState->m_animationState != LegoVehicleBuildState::e_exiting) {
				m_unk0x258->SetUnknown0xbc(0);

				if (m_unk0x258->AllPartsPlaced() || m_buildState->m_unk0x4d) {
					m_buildState->m_unk0x4d = TRUE;

					// GameState()->GetCurrentAct() returns an MxS16 in BETA10
					if (GameState()->GetCurrentAct() == 0) {
						InvokeAction(Extra::e_start, m_atomId, m_carId, NULL);

						NotificationManager()->Send(this, MxNotificationParam());

						assert(m_buildState);
						m_buildState->m_animationState = LegoVehicleBuildState::e_unknown4;
					}

					else {
						FUN_10025720(5);
						m_buildState->m_animationState = LegoVehicleBuildState::e_exiting;
					}
				}
				else {
					FUN_10025720(4);
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
			FUN_10024f30();
			m_Shelf_Sound->Enable(FALSE);
			m_Shelf_Sound->Enable(TRUE);
			result = 1;
			break;
		case CopterScript::c_Platform_Ctl:
			FUN_10024f50();
			m_unk0xf8 = c_unknown8;
			m_unk0xfc = param->m_unk0x28;
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
				m_unk0x258->SetPartObjectIdByName(m_unk0x110->GetName(), param->m_clickedObjectId);
				m_Decal_Sound->Enable(FALSE);
				m_Decal_Sound->Enable(TRUE);
			}
			else {
				FUN_10025350(param->m_clickedObjectId);
			}
			result = 1;
		}
	}
	else {
		m_unk0xf8 = c_unknownminusone;
		m_unk0xfc = -1;
	}

	return 1;
}

#endif

// FUNCTION: LEGO1 0x10024c20
// FUNCTION: BETA10 0x1006db21
undefined4 LegoCarBuild::FUN_10024c20(LegoEventNotificationParam* p_param)
{
	LegoEntity* entity;
	assert(m_buildState);

	switch (m_buildState->m_animationState) {
	case 4:
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

			if (m_unk0x258->AllPartsPlaced()) {
				FUN_100243a0();
			}
			else {
				FUN_10025720(5);
			}
		}
		else {
			MxNotificationParam param;
			NotificationManager()->Send(this, param);
		}
		break;
	case 2:
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

		m_unk0x338 = SoundManager()->FUN_100aebd0(*g_jukeboxScript, jukeboxScript);

		if (m_unk0x338) {
			BackgroundAudioManager()->FUN_1007f610(m_unk0x338, 5, MxPresenter::e_repeating);
			FUN_10024ef0();
		}
		else {
			MxNotificationParam p;
			// In BETA10, NotificationManager->Send() also takes __FILE__ and __LINE__ arguments
			NotificationManager()->Send(this, p);
		}
		break;
	}

	return 1;
}

// FUNCTION: LEGO1 0x10024ef0
void LegoCarBuild::FUN_10024ef0()
{
	FUN_1003eda0();
	m_buildState->m_animationState = LegoVehicleBuildState::e_cutscene;
	FUN_10025720(FUN_10025d70());
	m_buildState->m_unk0x4c += 1;
	FUN_10015820(FALSE, LegoOmni::c_disableInput | LegoOmni::c_disable3d | LegoOmni::c_clearScreen);
}

// FUNCTION: LEGO1 0x10024f30
// FUNCTION: BETA10 0x1006dfa0
void LegoCarBuild::FUN_10024f30()
{
	FUN_10022f30();
	m_unk0x258->SetUnknown0xbc(2);
}

// FUNCTION: LEGO1 0x10024f50
// FUNCTION: BETA10 0x1006dfce
void LegoCarBuild::FUN_10024f50()
{
	m_unk0x2d4 = FALSE;
	m_unk0x258->RotateAroundYAxis(g_rotationAngleStepYAxis);
}

// FUNCTION: LEGO1 0x10024f70
// FUNCTION: BETA10 0x1006e002
void LegoCarBuild::FUN_10024f70(MxBool p_enabled)
{
	if (m_unk0x258->StringEndsOnY(m_unk0x110->GetName())) {
		SetPresentersEnabled(p_enabled);
	}
}

// FUNCTION: LEGO1 0x10024fa0
// FUNCTION: BETA10 0x1006e04f
void LegoCarBuild::SetPresentersEnabled(MxBool p_enabled)
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
void LegoCarBuild::TogglePresentersEnabled()
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
void LegoCarBuild::FUN_100250e0(MxBool p_enabled)
{
	if (m_unk0x258->StringDoesNotEndOnZero(m_unk0x110->GetName()) && m_Decals_Ctl) {
		if (strnicmp(m_unk0x110->GetName(), "JSFRNT", strlen("JSFRNT")) == 0) {
			m_Decal_Bitmap->Enable(p_enabled);
			m_Decals_Ctl->Enable(p_enabled);
			m_Decals_Ctl1->Enable(p_enabled);
			m_Decals_Ctl2->Enable(p_enabled);
			m_Decals_Ctl3->Enable(p_enabled);
		}
		else if (strnicmp(m_unk0x110->GetName(), "JSWNSH", strlen("JSWNSH")) == 0) {
			m_Decal_Bitmap->Enable(p_enabled);
			m_Decals_Ctl4->Enable(p_enabled);
			m_Decals_Ctl5->Enable(p_enabled);
			m_Decals_Ctl6->Enable(p_enabled);
			m_Decals_Ctl7->Enable(p_enabled);
		}
		else if (strnicmp(m_unk0x110->GetName(), "RCBACK", strlen("RCBACK")) == 0) {
			m_Decals_Ctl1->Enable(p_enabled);
		}
		else if (strnicmp(m_unk0x110->GetName(), "RCTAIL", strlen("RCTAIL")) == 0) {
			m_Decals_Ctl2->Enable(p_enabled);
		}
		else if (m_Decals_Ctl1 && strnicmp(m_unk0x110->GetName(), "chljety", strlen("chljety")) == 0) {
			m_Decals_Ctl1->Enable(p_enabled);
		}
		else if (m_Decals_Ctl2 && strnicmp(m_unk0x110->GetName(), "chrjety", strlen("chrjety")) == 0) {
			m_Decals_Ctl2->Enable(p_enabled);
		}
		else if (m_Decals_Ctl) {
			m_Decals_Ctl->Enable(p_enabled);
		}
	}
}

// FUNCTION: LEGO1 0x10025350
// FUNCTION: BETA10 0x1006e3c0
void LegoCarBuild::FUN_10025350(MxS32 p_objectId)
{
	const LegoChar* color;
	LegoChar buffer[256];

	if (!m_unk0x110) {
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
	m_unk0x110->FUN_100a93b0(color);
	sprintf(buffer, "c_%s", m_unk0x110->GetName());
	VariableTable()->SetVariable(buffer, color);
}

// FUNCTION: LEGO1 0x10025450
// FUNCTION: BETA10 0x1006e599
void LegoCarBuild::FUN_10025450()
{
	m_unk0x12c = m_unk0x110->GetLocal2World();
	m_unk0x1c0 = m_unk0x12c;

	Vector3 lastColumnOfUnk0x1c0(m_unk0x1c0[3]);
	lastColumnOfUnk0x1c0 = Vector3(m_unk0x258->GetUnknown0xe0()[3]);

	// This looks odd, but it improves the LEGO1 match while breaking the BETA10 match.
	// I don't know whether this is due to compiler entropy.
	// Feel free to replace unk0x178 -> m_unk0x178 and remove this variable if it improves the LEGO1 match
	// in the future.
	MxMatrix* unk0x178 = &m_unk0x178;
	*unk0x178 = m_unk0x12c;

	if (m_unk0x258->PartIsPlaced(m_unk0x110->GetName())) {
		m_unk0x2a4 = Vector4(m_unk0x110->GetWorldPosition());

		if (!m_unk0x2d4) {
			m_unk0x2bc = m_unk0x2a4;

			m_unk0x208 = m_unk0x12c;
			m_unk0x2a4[0] += m_unk0x1c0[3][0] - m_unk0x208[3][0];
			m_unk0x2a4[1] += m_unk0x1c0[3][1] - m_unk0x208[3][1];
			m_unk0x2a4[2] += m_unk0x1c0[3][2] - m_unk0x208[3][2];
		}

		*unk0x178 = m_unk0x1c0;
	}
	else {
		const LegoChar* wiredName;

		if (!m_unk0x258->FUN_10079c30(m_unk0x110->GetName())) {
			wiredName = m_unk0x258->GetWiredNameByPartName(m_unk0x110->GetName());
		}
		else {
			wiredName = m_unk0x258->GetWiredNameOfLastPlacedPart();
		}

		LegoROI* parentROI = (LegoROI*) m_unk0x110->GetParentROI();
		m_unk0x208 = parentROI->FindChildROI(wiredName, parentROI)->GetLocal2World();
		m_unk0x2bc = Vector4(parentROI->FindChildROI(wiredName, parentROI)->GetWorldPosition());
		m_unk0x2a4 = Vector4(m_unk0x110->GetWorldPosition());

		m_unk0x2a4[2] += (m_unk0x1c0[3][2] - m_unk0x12c[3][2]);
		m_unk0x178[3][2] = m_unk0x1c0[3][2];
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
inline MxU32 LegoCarBuild::Beta0x10070520()
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

inline void LegoCarBuild::StopActionIn0x344()
{
	// There is no direct evidence for this inline function in LEGO1,
	// but some code doesn't make much sense otherwise. For example,
	// sometimes `m_unk0x344` is set to another value right below this call,
	// which the original developer would likely have refactored.
	if (m_unk0x344 != DS_NOT_A_STREAM) {
		InvokeAction(Extra::ActionType::e_stop, m_atomId, m_unk0x344, NULL);
		m_unk0x344 = DS_NOT_A_STREAM;
	}
}

// FUNCTION: LEGO1 0x10025720
// FUNCTION: BETA10 0x1006e9df
void LegoCarBuild::FUN_10025720(undefined4 p_param)
{
	m_numAnimsRun++;
	m_unk0x10a = 0;
	MxS32 uVar6;

#ifdef NDEBUG

	if (GameState()->GetCurrentAct() == LegoGameState::e_act2) {
		// This is most likely related to the helicopter rebuild in Act 2
		switch (p_param) {
		case 0:
		case 1:
		case 2:
		case 3:
			switch (rand() % 3) {
			case 0:
				m_unk0x10a = CopterScript::c_ips004d2_RunAnim;
				StopActionIn0x344();
				m_unk0x344 = CopterScript::c_ips004d2_RunAnim;
				BackgroundAudioManager()->LowerVolume();
				InvokeAction(Extra::ActionType::e_start, m_atomId, CopterScript::c_ips004d2_RunAnim, NULL);
				break;
			case 1:
				m_unk0x10a = CopterScript::c_ips006d2_RunAnim;
				StopActionIn0x344();
				m_unk0x344 = CopterScript::c_ips006d2_RunAnim;
				BackgroundAudioManager()->LowerVolume();
				InvokeAction(Extra::ActionType::e_start, m_atomId, CopterScript::c_ips006d2_RunAnim, NULL);
				break;
			case 2:
				m_unk0x10a = CopterScript::c_slp01xd2_RunAnim;
				StopActionIn0x344();
				m_unk0x344 = CopterScript::c_slp01xd2_RunAnim;
				BackgroundAudioManager()->LowerVolume();
				InvokeAction(Extra::ActionType::e_start, m_atomId, CopterScript::c_slp01xd2_RunAnim, NULL);
				break;
			}
			break;
		case 4:
			FUN_10025d10(g_unk0x100d65b0[Beta0x10070520()].m_unk0x04);
			break;
		case 5:
			FUN_10025d10(g_unk0x100d65b0[Beta0x10070520()].m_unk0x08);
			break;
		case 6:
			m_unk0x10a = g_unk0x100d65b0[Beta0x10070520()].m_unk0x18;
			uVar6 = m_unk0x10a;
			StopActionIn0x344();

			if (uVar6 != DS_NOT_A_STREAM) {
				m_unk0x344 = uVar6;
				BackgroundAudioManager()->LowerVolume();
				InvokeAction(Extra::ActionType::e_start, m_atomId, uVar6, NULL);
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
		switch (p_param) {
		case 0:
			m_unk0x10a = g_unk0x100d65b0[Beta0x10070520()].m_unk0x00;
			FUN_10025d10(m_unk0x10a);
			break;
		case 1:
			m_unk0x10a = g_unk0x100d65b0[Beta0x10070520()].m_unk0x0c;
			FUN_10025d10(m_unk0x10a);

			if (m_carId == 2) {
				m_unk0x10a = 0;
			}

			break;
		case 2:
			m_unk0x10a = g_unk0x100d65b0[Beta0x10070520()].m_unk0x10;
			FUN_10025d10(m_unk0x10a);

			if (m_carId != 3) {
				m_unk0x10a = 0;
			}

			break;
		case 3:
			FUN_10025d10(g_unk0x100d65b0[Beta0x10070520()].m_unk0x14);
			break;
		case 4:
			FUN_10025d10(g_unk0x100d65b0[Beta0x10070520()].m_unk0x04);
			break;
		case 5:
			FUN_10025d10(g_unk0x100d65b0[Beta0x10070520()].m_unk0x08);
			break;
		case 6:
			m_unk0x10a = g_unk0x100d65b0[Beta0x10070520()].m_unk0x18;
			FUN_10025d10(m_unk0x10a);
			break;
		default:
			assert(0);
			m_numAnimsRun--;

			// Weird: This assertion can never be executed. The `assert(0)` above was probably introduced later.
			assert(m_numAnimsRun >= 0);
			return;
		}
#ifdef NDEBUG
	}
#endif

	if (m_unk0x10a != 0) {
		m_unk0x10c = timeGetTime();
	}
}

// FUNCTION: LEGO1 0x10025d10
// FUNCTION: BETA10 0x10070490
void LegoCarBuild::FUN_10025d10(MxS32 p_param)
{
	// this function has a different signature and partially different body in BETA10, but it is called in the same
	// places
	if (m_unk0x344 != DS_NOT_A_STREAM) {
		InvokeAction(Extra::ActionType::e_stop, m_atomId, m_unk0x344, NULL);
		m_unk0x344 = DS_NOT_A_STREAM;
	}

	if (p_param != DS_NOT_A_STREAM) {
		m_unk0x344 = p_param;
		BackgroundAudioManager()->LowerVolume();
		InvokeAction(Extra::ActionType::e_start, m_atomId, p_param, NULL);
	}
}

// FUNCTION: LEGO1 0x10025d70
MxS32 LegoCarBuild::FUN_10025d70()
{
	switch (m_buildState->m_unk0x4c % 3) {
	case 1:
		return 1;
	case 2:
		return 2;
	case 3:
		return 3;
	default:
		return 0;
	}
}

// FUNCTION: LEGO1 0x10025db0
// FUNCTION: BETA10 0x1006ed18
void LegoCarBuild::FUN_10025db0(const char* p_param1, undefined4 p_param2)
{
	m_unk0x33c = (MxControlPresenter*) Find("MxControlPresenter", p_param1);

	MxS16 sVar3 = 1 - ((p_param2 / 5) & 1);

	if (m_Yellow_Ctl == m_unk0x33c) {
		if (sVar3 != g_unk0x100f11cc) {
			TogglePresentersEnabled();
			g_unk0x100f11cc = sVar3;
		}
	}
	else {
		if (m_unk0x33c->GetUnknown0x4e() != sVar3) {
			m_unk0x33c->VTable0x6c(sVar3);
		}

		g_unk0x100f11cc = -1;
		SetPresentersEnabled(m_presentersEnabled);
	}
}

// FUNCTION: LEGO1 0x10025e40
void LegoCarBuild::FUN_10025e40()
{
	SetPresentersEnabled(m_presentersEnabled);
	if (m_unk0x33c && m_Yellow_Ctl != m_unk0x33c) {
		m_unk0x33c->VTable0x6c(0);
	}
}

// FUNCTION: LEGO1 0x10025e70
MxBool LegoCarBuild::Escape()
{
	BackgroundAudioManager()->Init();
	MxS32 targetEntityId = FUN_10025ee0(m_carId);
	InvokeAction(Extra::ActionType::e_stop, *g_jukeboxScript, targetEntityId, NULL);
	DeleteObjects(&m_atomId, 500, 999);

	m_buildState->m_animationState = LegoVehicleBuildState::e_unknown0;
	m_destLocation = LegoGameState::e_infomain;
	return TRUE;
}

// FUNCTION: LEGO1 0x10025ee0
MxS32 LegoCarBuild::FUN_10025ee0(undefined4 p_param1)
{
	// TODO: Work out constants
	switch (p_param1) {
	case 1:
		return 0x2f;
	case 2:
		return 0x31;
	case 3:
		return 0x33;
	case 4:
		return 0x35;
	default:
		return -1;
	}
}

// FUNCTION: LEGO1 0x10025f30
LegoVehicleBuildState::LegoVehicleBuildState(const char* p_classType)
{
	m_className = p_classType;
	m_unk0x4c = 0;
	m_unk0x4d = FALSE;
	m_unk0x4e = FALSE;
	m_placedPartCount = 0;
}

// FUNCTION: LEGO1 0x10026120
MxResult LegoVehicleBuildState::Serialize(LegoFile* p_file)
{
	LegoState::Serialize(p_file);

	if (p_file->IsReadMode()) {
		Read(p_file, &m_unk0x4c);
		Read(p_file, &m_unk0x4d);
		Read(p_file, &m_unk0x4e);
		Read(p_file, &m_placedPartCount);
	}
	else {
		Write(p_file, m_unk0x4c);
		Write(p_file, m_unk0x4d);
		Write(p_file, m_unk0x4e);
		Write(p_file, m_placedPartCount);
	}

	return SUCCESS;
}
