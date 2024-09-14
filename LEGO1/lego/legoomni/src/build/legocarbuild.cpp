#include "legocarbuild.h"

#include "legocarbuildpresenter.h"
#include "legocontrolmanager.h"
#include "legogamestate.h"
#include "legoinputmanager.h"
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
#include "scripts.h"

#include <vec.h>

DECOMP_SIZE_ASSERT(LegoCarBuild, 0x34c)
DECOMP_SIZE_ASSERT(LegoVehicleBuildState, 0x50)

// GLOBAL: LEGO1 0x100d65a4
MxFloat LegoCarBuild::g_unk0x100d65a4 = -0.1f;

// GLOBAL: LEGO1 0x100d65a8
MxFloat LegoCarBuild::g_unk0x100d65a8 = 0.07;

// GLOBAL: LEGO1 0x100f11cc
MxS16 LegoCarBuild::g_unk0x100f11cc = -1;

// FUNCTION: LEGO1 0x100226d0
// FUNCTION: BETA10 0x1006ac10
LegoCarBuild::LegoCarBuild()
{
	m_unk0x100 = 0;
	m_unk0x110 = 0;
	m_unk0xf8 = 0xffffffff;
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
	m_unk0x108 = 0;
	m_unk0x338 = 0;
	m_destLocation = LegoGameState::e_undefined;
	m_unk0x344 = 0xffffffff;
	m_unk0x174 = 0;
	NotificationManager()->Register(this);
}

// FUNCTION: LEGO1 0x10022930
// FUNCTION: BETA10 0x10070070
MxBool LegoCarBuild::VTable0x5c()
{
	return TRUE;
}

// STUB: LEGO1 0x10022a80
// STUB: BETA10 0x1006aea3
LegoCarBuild::~LegoCarBuild()
{
	// TODO
	// ...
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
			GameState()->SetCurrentArea(LegoGameState::e_copterbuild);
			m_unk0x330 = 1;
		}
		else if (m_atomId == *g_dunecarScript) {
			buildStateClassName = "LegoDuneCarBuildState";
			GameState()->SetCurrentArea(LegoGameState::e_dunecarbuild);
			m_unk0x330 = 2;
		}
		else if (m_atomId == *g_jetskiScript) {
			buildStateClassName = "LegoJetskiBuildState";
			GameState()->SetCurrentArea(LegoGameState::e_jetskibuild);
			m_unk0x330 = 3;
		}
		else if (m_atomId == *g_racecarScript) {
			buildStateClassName = "LegoRaceCarBuildState";
			GameState()->SetCurrentArea(LegoGameState::e_racecarbuild);
			m_unk0x330 = 4;
		}

		LegoGameState* gameState = GameState();

		LegoVehicleBuildState* buildState = (LegoVehicleBuildState*) gameState->GetState(buildStateClassName);

		if (!buildState) {
			buildState = (LegoVehicleBuildState*) gameState->CreateState(buildStateClassName);
		}

		m_buildState = buildState;
		m_unk0x174 = m_buildState->m_unk0x4d;

		GameState()->StopArea(LegoGameState::e_previousArea);

		m_buildState->m_animationState = 1;
		m_unk0x100 = 0;

		BackgroundAudioManager()->Stop();
		EnableAnimations(FALSE);

		result = SUCCESS;
	}

	return result;
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

// FUNCTION: LEGO1 0x10022f30
// FUNCTION: BETA10 0x1006b835
void LegoCarBuild::FUN_10022f30()
{
	if (m_unk0x110) {
		FUN_10024f70(FALSE);
		FUN_100250e0(FALSE);

		if (m_unk0x258->FUN_10079ca0(m_unk0x110->GetName())) {
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

	m_unk0x25c.Unknown1(m_unk0x178, m_unk0x208);
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

			m_unk0x25c.Unknown6(local78, local1c);

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

#define LEGOCARBUILD_TICKLE_CASE(subtract, start, end, str)                                                            \
	if (start < dTime && dTime < end) {                                                                                \
		FUN_10025db0(str, dTime - subtract);                                                                           \
		return SUCCESS;                                                                                                \
	}

// FUNCTION: LEGO1 0x100238b0
// FUNCTION: BETA10 0x1006c18f
MxResult LegoCarBuild::Tickle()
{
	if (!m_worldStarted) {
		LegoWorld::Tickle();
		return SUCCESS;
	}

	if (m_unk0xf8 == 8) {
		if (m_unk0xfc == 1) {
			FUN_10024f50();
		}

		if (m_unk0x110) {
			if (m_unk0x258->FUN_10079ca0(m_unk0x110->GetName())) {
				FUN_10022f30();
			}
		}
	}

	if (m_unk0x100 == 5 && m_unk0x110) {
		FUN_1003dde0(m_unk0x110, g_unk0x100d65a4);
	}

	if (m_unk0x10a) {
		DWORD time = timeGetTime();
		DWORD dTime = (time - m_unk0x10c) / 100;

		if (m_unk0x330 == 4) {
			switch (m_unk0x10a) {
			// TODO: Work out constants
			case 500:
				LEGOCARBUILD_TICKLE_CASE(160, 160, 180, "Exit_Ctl")
				LEGOCARBUILD_TICKLE_CASE(260, 260, 280, "ShelfUp_Ctl")
				LEGOCARBUILD_TICKLE_CASE(330, 330, 340, "Yellow_Ctl")
				LEGOCARBUILD_TICKLE_CASE(340, 340, 360, "Platform_Ctl")
				LEGOCARBUILD_TICKLE_CASE(390, 390, 410, "Exit_Ctl")
			case 503:
				LEGOCARBUILD_TICKLE_CASE(50, 50, 60, "ShelfUp_Ctl")
				LEGOCARBUILD_TICKLE_CASE(63, 65, 70, "Yellow_Ctl")
				LEGOCARBUILD_TICKLE_CASE(70, 70, 80, "Platform_Ctl")
				LEGOCARBUILD_TICKLE_CASE(95, 95, 105, "Exit_Ctl")
			case 504:
				LEGOCARBUILD_TICKLE_CASE(22, 24, 29, "Exit_Ctl")
				LEGOCARBUILD_TICKLE_CASE(33, 35, 40, "ShelfUp_Ctl")
				LEGOCARBUILD_TICKLE_CASE(43, 45, 50, "Yellow_Ctl")
				LEGOCARBUILD_TICKLE_CASE(56, 58, 63, "Platform_Ctl")
			default:
				return SUCCESS;
			}
		}
		else if (m_unk0x330 == 3) {
			switch (m_unk0x10a) {
			case 500:
				LEGOCARBUILD_TICKLE_CASE(291, 291, 311, "Exit_Ctl")
				LEGOCARBUILD_TICKLE_CASE(311, 311, 331, "ShelfUp_Ctl")
				LEGOCARBUILD_TICKLE_CASE(412, 412, 432, "Yellow_Ctl")
				LEGOCARBUILD_TICKLE_CASE(437, 437, 457, "Platform_Ctl")
				LEGOCARBUILD_TICKLE_CASE(485, 485, 505, "Exit_Ctl")
			case 501:
				LEGOCARBUILD_TICKLE_CASE(32, 34, 39, "Exit_Ctl")
				LEGOCARBUILD_TICKLE_CASE(68, 70, 75, "ShelfUp_Ctl")
				LEGOCARBUILD_TICKLE_CASE(105, 105, 115, "Yellow_Ctl")
				LEGOCARBUILD_TICKLE_CASE(133, 135, 140, "Platform_Ctl")
			case 504:
				LEGOCARBUILD_TICKLE_CASE(78, 78, 98, "Exit_Ctl")
			case 505:
				LEGOCARBUILD_TICKLE_CASE(93, 93, 113, "Exit_Ctl")
				// default: // not sure if present
				// 	return SUCCESS;
			}
		}
		else if (m_unk0x330 == 2) {
			switch (m_unk0x10a) {
			case 500:
				LEGOCARBUILD_TICKLE_CASE(155, 155, 175, "Exit_Ctl")
				LEGOCARBUILD_TICKLE_CASE(215, 215, 235, "ShelfUp_Ctl")
				LEGOCARBUILD_TICKLE_CASE(285, 285, 305, "Yellow_Ctl")
				LEGOCARBUILD_TICKLE_CASE(300, 300, 320, "Platform_Ctl")
				LEGOCARBUILD_TICKLE_CASE(340, 340, 360, "Exit_Ctl")
			case 501:
				LEGOCARBUILD_TICKLE_CASE(23, 23, 33, "Exit_Ctl")
				LEGOCARBUILD_TICKLE_CASE(37, 39, 44, "ShelfUp_Ctl")
				LEGOCARBUILD_TICKLE_CASE(105, 105, 115, "Yellow_Ctl")
				LEGOCARBUILD_TICKLE_CASE(122, 124, 129, "Platform_Ctl")
			default:
				return SUCCESS;
			}
		}
		else if (m_unk0x330 == 1) {
			switch (m_unk0x10a) {
			case 500:
				LEGOCARBUILD_TICKLE_CASE(185, 185, 205, "Exit_Ctl")
				LEGOCARBUILD_TICKLE_CASE(235, 235, 255, "ShelfUp_Ctl")
				LEGOCARBUILD_TICKLE_CASE(292, 292, 312, "Yellow_Ctl")
				LEGOCARBUILD_TICKLE_CASE(315, 315, 335, "Platform_Ctl")
				LEGOCARBUILD_TICKLE_CASE(353, 353, 373, "Exit_Ctl")
			case 501:
				LEGOCARBUILD_TICKLE_CASE(43, 45, 50, "Exit_Ctl")
				LEGOCARBUILD_TICKLE_CASE(72, 74, 79, "ShelfUp_Ctl")
				LEGOCARBUILD_TICKLE_CASE(114, 116, 121, "Yellow_Ctl")
				LEGOCARBUILD_TICKLE_CASE(128, 130, 135, "Platform_Ctl")
			case 505:
				LEGOCARBUILD_TICKLE_CASE(30, 30, 40, "ShelfUp_Ctl")
				LEGOCARBUILD_TICKLE_CASE(60, 60, 70, "Yellow_Ctl")
				LEGOCARBUILD_TICKLE_CASE(48, 48, 58, "Platform_Ctl")
			default:
				return SUCCESS;
			}
		}
	}

	return 0;
}

// FUNCTION: LEGO1 0x10024050
// FUNCTION: BETA10 0x1006c976
MxLong LegoCarBuild::Notify(MxParam& p_param)
{
	MxLong result = LegoWorld::Notify(p_param);

	if (m_worldStarted) {
		switch (((MxNotificationParam*) &p_param)->GetNotification()) {
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
				m_buildState->m_animationState = 0;
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
			result = FUN_10024890((LegoEventNotificationParam*) &p_param);

			if (result == 1) {
				m_unk0x109 = 0;
			}

			break;
		case c_notificationEndAnim:
			if (m_unk0x108 > 0) {
				m_unk0x108 -= 1;
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
		if (m_unk0x108 > 0) {
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
		InvokeAction(Extra::ActionType::e_start, *g_jukeboxScript, FUN_10025ee0(m_unk0x330), NULL);
		m_buildState->m_animationState = 2;
		NotificationManager()->Send(this, MxNotificationParam());
	}
	else {
		FUN_10024ef0();
	}
}

// FUNCTION: LEGO1 0x100243a0
void LegoCarBuild::FUN_100243a0()
{
	switch (m_unk0x330) {
	case 1:
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
	case 2:
		m_destLocation = LegoGameState::Area::e_garadoor;
		TransitionManager()->StartTransition(MxTransitionManager::TransitionType::e_mosaic, 50, FALSE, FALSE);
		break;
	case 3:
		m_destLocation = LegoGameState::Area::e_unk17;
		TransitionManager()->StartTransition(MxTransitionManager::TransitionType::e_mosaic, 50, FALSE, FALSE);
		break;
	case 4:
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
		m_buildState->m_animationState = 0;
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

	if (m_unk0x100 == 5 && m_unk0x258->FUN_10079ca0(m_unk0x110->GetName())) {
		m_unk0x2d4 = TRUE;
	}
	else {
		m_unk0x2d4 = FALSE;
	}
	FUN_10025450();
	VTable0x70();

	if (m_unk0x258->FUN_10079ca0(m_unk0x110->GetName())) {
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

// STUB: LEGO1 0x100246e0
undefined4 LegoCarBuild::FUN_100246e0(MxLong p_x, MxLong p_y)
{
	// TODO
	return 0;
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

// STUB: LEGO1 0x10024890
// STUB: BETA10 0x1006d512
undefined4 LegoCarBuild::FUN_10024890(LegoEventNotificationParam* p_param)
{
	// TODO
	return 0;
}

// STUB: LEGO1 0x10024c20
// STUB: BETA10 0x1006db21
void LegoCarBuild::FUN_10024c20(LegoEventNotificationParam* p_param)
{
	// TODO
}

// FUNCTION: LEGO1 0x10024ef0
void LegoCarBuild::FUN_10024ef0()
{
	FUN_1003eda0();
	m_buildState->m_animationState = 3;
	FUN_10025720(FUN_10025d70());
	m_buildState->m_unk0x4c += 1;
	FUN_10015820(FALSE, 7);
}

// FUNCTION: LEGO1 0x10024f50
// FUNCTION: BETA10 0x1006dfce
void LegoCarBuild::FUN_10024f50()
{
	m_unk0x2d4 = FALSE;
	m_unk0x258->FUN_10079920(g_unk0x100d65a8);
}

// FUNCTION: LEGO1 0x10024f70
// FUNCTION: BETA10 0x1006e002
void LegoCarBuild::FUN_10024f70(MxBool p_enabled)
{
	if (m_unk0x258->FUN_10079cf0(m_unk0x110->GetName())) {
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

// STUB: LEGO1 0x100250e0
// STUB: BETA10 0x1006e124
void LegoCarBuild::FUN_100250e0(MxBool p_enabled)
{
	// TODO
}

// STUB: LEGO1 0x10025450
// STUB: BETA10 0x1006e599
void LegoCarBuild::FUN_10025450()
{
	// TODO
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

// STUB: LEGO1 0x10025720
undefined4 LegoCarBuild::FUN_10025720(undefined4 p_param1)
{
	// TODO
	return 0;
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
	MxS32 targetEntityId = FUN_10025ee0(m_unk0x330);
	InvokeAction(Extra::ActionType::e_stop, *g_jukeboxScript, targetEntityId, NULL);
	DeleteObjects(&m_atomId, 500, 999);

	m_buildState->m_animationState = 0;
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
