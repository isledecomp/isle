#include "legocarbuild.h"

#include "legocarbuildpresenter.h"
#include "legocontrolmanager.h"
#include "legogamestate.h"
#include "legoinputmanager.h"
#include "legoutils.h"
#include "misc.h"
#include "mxbackgroundaudiomanager.h"
#include "mxcontrolpresenter.h"
#include "mxmisc.h"
#include "mxnotificationmanager.h"
#include "mxsoundpresenter.h"
#include "mxstillpresenter.h"
#include "mxticklemanager.h"
#include "scripts.h"

DECOMP_SIZE_ASSERT(LegoCarBuild, 0x34c)
DECOMP_SIZE_ASSERT(LegoVehicleBuildState, 0x50)

// GLOBAL: LEGO1 0x100d65a4
MxFloat LegoCarBuild::g_unk0x100d65a4 = -0.1f;

// GLOBAL: LEGO1 0x100d65a8
MxFloat LegoCarBuild::g_unk0x100d65a8 = 0.07;

// GLOBAL: LEGO1 0x100f11cc
MxS16 LegoCarBuild::g_unk0x100f11cc = -1;

// STUB: LEGO1 0x100226d0
// FUNCTION: BETA10 0x1006ac10
LegoCarBuild::LegoCarBuild()
{
	// Not close yet - might be getting there when more of this class is implemented
	m_unk0x100 = 0;
	m_unk0x110 = 0;
	m_unk0xf8 = 0xffffffff;
	m_unk0x2d4 = '\0';
	m_unk0x258 = 0;
	m_colorBookBitmap = 0;
	m_yellowCtl = 0;
	m_redCtl = 0;
	m_blueCtl = 0;
	m_greenCtl = 0;
	m_grayCtl = 0;
	m_blackCtl = 0;
	m_shelfSound = 0;
	m_placeBrickSound = 0;
	m_getBrickSound = 0;
	m_paintSound = 0;
	m_decalSound = 0;
	m_decalBitmap = 0;
	m_decalsCtl0 = 0;
	m_decalsCtl1 = 0;
	m_decalsCtl2 = 0;
	m_decalsCtl3 = 0;
	m_decalsCtl4 = 0;
	m_decalsCtl5 = 0;
	m_decalsCtl6 = 0;
	m_decalsCtl7 = NULL;
	m_unk0x33c = 0;
	m_buildState = 0;
	m_unk0x104 = 0;
	m_unk0x109 = '\0';
	m_unk0x108 = '\0';
	m_unk0x338 = 0;
	m_unk0x334 = 0;
	m_unk0x344 = 0xffffffff;
	m_unk0x174 = '\0';
	NotificationManager()->Register(this);
}

// FUNCTION: LEGO1 0x10022930
// FUNCTION: BETA10 0x10070070
MxBool LegoCarBuild::VTable0x5c()
{
	return TRUE;
}

// STUB: LEGO1 0x10022a80
// FUNCTION: BETA10 0x1006aea3
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
			GameState()->SetCurrentArea(LegoGameState::Area::e_copterbuild);
			m_unk0x330 = 1;
		}
		else if (m_atomId == *g_dunecarScript) {
			buildStateClassName = "LegoDuneCarBuildState";
			GameState()->SetCurrentArea(LegoGameState::Area::e_dunecarbuild);
			m_unk0x330 = 2;
		}
		else if (m_atomId == *g_jetskiScript) {
			buildStateClassName = "LegoJetskiBuildState";
			GameState()->SetCurrentArea(LegoGameState::Area::e_jetskibuild);
			m_unk0x330 = 3;
		}
		else if (m_atomId == *g_racecarScript) {
			buildStateClassName = "LegoRaceCarBuildState";
			GameState()->SetCurrentArea(LegoGameState::Area::e_racecarbuild);
			m_unk0x330 = 4;
		}

		LegoGameState* gameState = GameState();

		LegoVehicleBuildState* buildState = (LegoVehicleBuildState*) gameState->GetState(buildStateClassName);

		if (!buildState) {
			buildState = (LegoVehicleBuildState*) gameState->CreateState(buildStateClassName);
		}

		m_buildState = buildState;
		m_unk0x174 = m_buildState->m_unk0x4d;

		GameState()->StopArea(LegoGameState::Area::e_previousArea);

		m_buildState->m_animationState = 1;
		m_unk0x100 = 0;

		BackgroundAudioManager()->Stop();
		EnableAnimations(FALSE);

		result = SUCCESS;
	}

	return result;
}

// FUNCTION: LEGO1 0x10022d10
void LegoCarBuild::InitPresenters()
{
	m_colorBookBitmap = (MxStillPresenter*) Find("MxStillPresenter", "ColorBook_Bitmap");
	m_yellowCtl = (MxControlPresenter*) Find("MxControlPresenter", "Yellow_Ctl");
	m_redCtl = (MxControlPresenter*) Find("MxControlPresenter", "Red_Ctl");
	m_blueCtl = (MxControlPresenter*) Find("MxControlPresenter", "Blue_Ctl");
	m_greenCtl = (MxControlPresenter*) Find("MxControlPresenter", "Green_Ctl");
	m_grayCtl = (MxControlPresenter*) Find("MxControlPresenter", "Gray_Ctl");
	m_blackCtl = (MxControlPresenter*) Find("MxControlPresenter", "Black_Ctl");
	m_shelfSound = (MxSoundPresenter*) Find("MxSoundPresenter", "Shelf_Sound");
	m_placeBrickSound = (MxSoundPresenter*) Find("MxSoundPresenter", "PlaceBrick_Sound");
	m_getBrickSound = (MxSoundPresenter*) Find("MxSoundPresenter", "GetBrick_Sound");
	m_paintSound = (MxSoundPresenter*) Find("MxSoundPresenter", "Paint_Sound");
	m_decalSound = (MxSoundPresenter*) Find("MxSoundPresenter", "Decal_Sound");
	m_decalsCtl0 = (MxControlPresenter*) Find("MxControlPresenter", "Decals_Ctl");
	m_decalsCtl1 = (MxControlPresenter*) Find("MxControlPresenter", "Decals_Ctl1");
	m_decalsCtl2 = (MxControlPresenter*) Find("MxControlPresenter", "Decals_Ctl2");
	m_decalBitmap = (MxStillPresenter*) Find("MxStillPresenter", "Decal_Bitmap");
	if (m_decalBitmap) {
		m_decalsCtl3 = (MxControlPresenter*) Find("MxControlPresenter", "Decals_Ctl3");
		m_decalsCtl4 = (MxControlPresenter*) Find("MxControlPresenter", "Decals_Ctl4");
		m_decalsCtl5 = (MxControlPresenter*) Find("MxControlPresenter", "Decals_Ctl5");
		m_decalsCtl6 = (MxControlPresenter*) Find("MxControlPresenter", "Decals_Ctl6");
		m_decalsCtl7 = (MxControlPresenter*) Find("MxControlPresenter", "Decals_Ctl7");
	}
	return;
}

// STUB: LEGO1 0x10022f30
// STUB: BETA10 0x1006b835
void LegoCarBuild::FUN_10022f30()
{
	// TODO
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

// STUB: LEGO1 0x10023020
// FUNCTION: BETA10 0x1006b991
void LegoCarBuild::VTable0x70()
{
	MxFloat worldPos[3];
	MxFloat screenPos[4];

	worldPos[0] = m_unk0x2a4[0];
	worldPos[1] = m_unk0x2a4[1];
	worldPos[2] = m_unk0x2a4[2];

	TransformWorldToScreen(worldPos, screenPos);

	m_unk0x290 = screenPos[0] / screenPos[3];
	m_unk0x294 = screenPos[1] / screenPos[3];

	worldPos[0] = m_unk0x2bc[0];
	worldPos[1] = m_unk0x2bc[1];
	worldPos[2] = m_unk0x2bc[2];

	TransformWorldToScreen(worldPos, screenPos);

	m_unk0x298 = screenPos[0] / screenPos[3];
	m_unk0x29c = screenPos[1] / screenPos[3];

	m_unk0x2a0 = sqrt(
		(MxFloat) (m_unk0x298 - m_unk0x290) * (m_unk0x298 - m_unk0x290) +
		(m_unk0x29c - m_unk0x294) * (m_unk0x29c - m_unk0x294)
	);

	m_unk0x25c.Unknown1(m_unk0x178, m_unk0x208);
}

// FUNCTION: LEGO1 0x10023500
// FUNCTION: BETA10 0x1006bdf6
void LegoCarBuild::VTable0x74(MxFloat p_param1[3], MxFloat p_param2[3])
{
	MxFloat fVar1;
	MxFloat local20[3];
	MxFloat local14[3];

	FUN_1003ded0(p_param1, local14, local20);

	fVar1 = (m_unk0x2a4[2] - local20[2]) / local14[2];
	p_param2[0] = (fVar1 * local14[0] + local20[0]) - m_unk0x2a4[0];
	p_param2[1] = (fVar1 * local14[1] + local20[1]) - m_unk0x2a4[1];
	p_param2[2] = 0.0;
	return;
}

// FUNCTION: LEGO1 0x10023570
// FUNCTION: BETA10 0x1006be91
void LegoCarBuild::VTable0x78(MxFloat p_param1[3], MxFloat p_param2[3])
{
	MxFloat fVar1;
	MxFloat local18[3];
	MxFloat localc[3];

	FUN_1003ded0(p_param1, local18, localc);

	p_param2[2] =
		m_unk0x2a4[2] + (m_unk0x2bc[2] - m_unk0x2a4[2]) * ((p_param1[1] - m_unk0x294) / (m_unk0x29c - m_unk0x294));
	fVar1 = (p_param2[2] - localc[2]) / local18[2];
	p_param2[0] = fVar1 * local18[0] - m_unk0x2a4[0] + localc[0];
	p_param2[1] = fVar1 * local18[1] - m_unk0x2a4[1] + localc[1];
	p_param2[2] = p_param2[2] - m_unk0x2a4[2];
}

// FUNCTION: LEGO1 0x10023620
// FUNCTION: BETA10 0x1006bfb5
void LegoCarBuild::VTable0x7c(MxFloat p_param1[3], MxFloat p_param2[3])
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

// STUB: LEGO1 0x10024050
// FUNCTION: BETA10 0x1006c976
MxLong LegoCarBuild::Notify(MxParam& p_param)
{
	// TODO
	return 0;
}

// STUB: LEGO1 0x100242c0
void LegoCarBuild::ReadyWorld()
{
	m_presentersEnabled = FALSE;
	InitPresenters();
	if (BackgroundAudioManager()->GetEnabled()) {
		InvokeAction(Extra::ActionType::e_start, *g_jukeboxScript, FUN_10025ee0(m_unk0x330), NULL);
		m_buildState->m_animationState = 2;
		MxNotificationParam param;
		param.SetNotification(c_notificationStartAction);
		NotificationManager()->Send(this, param);
	}
	else {
		FUN_10024ef0();
	}
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

// FUNCTION: LEGO1 0x10024fa0
// FUNCTION: BETA10 0x1006e04f
void LegoCarBuild::SetPresentersEnabled(MxBool p_enabled)
{
	m_presentersEnabled = p_enabled;
	m_colorBookBitmap->Enable(p_enabled);
	m_yellowCtl->Enable(p_enabled);
	m_redCtl->Enable(p_enabled);
	m_blueCtl->Enable(p_enabled);
	m_greenCtl->Enable(p_enabled);
	m_grayCtl->Enable(p_enabled);
	m_blackCtl->Enable(p_enabled);
}

// FUNCTION: LEGO1 0x10025010
void LegoCarBuild::TogglePresentersEnabled()
{
	m_colorBookBitmap->Enable(!m_colorBookBitmap->IsEnabled());
	m_yellowCtl->Enable(!m_yellowCtl->IsEnabled());
	m_redCtl->Enable(!m_redCtl->IsEnabled());
	m_blueCtl->Enable(!m_blueCtl->IsEnabled());
	m_greenCtl->Enable(!m_greenCtl->IsEnabled());
	m_grayCtl->Enable(!m_grayCtl->IsEnabled());
	m_blackCtl->Enable(!m_blackCtl->IsEnabled());
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

	if (m_yellowCtl == m_unk0x33c) {
		if (sVar3 != g_unk0x100f11cc) {
			TogglePresentersEnabled();
			g_unk0x100f11cc = sVar3;
			return;
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

// FUNCTION: LEGO1 0x10025e70
MxBool LegoCarBuild::Escape()
{
	BackgroundAudioManager()->Init();
	MxS32 targetEntityId = FUN_10025ee0(m_unk0x330);
	InvokeAction(Extra::ActionType::e_stop, *g_jukeboxScript, targetEntityId, NULL);
	DeleteObjects(&m_atomId, 500, 999);

	m_buildState->m_animationState = 0;
	m_unk0x334 = 2;
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
