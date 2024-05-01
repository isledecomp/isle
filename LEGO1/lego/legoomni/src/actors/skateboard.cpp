#include "skateboard.h"

#include "act1state.h"
#include "decomp.h"
#include "isle.h"
#include "isle_actions.h"
#include "jukebox_actions.h"
#include "legoanimationmanager.h"
#include "legoutils.h"
#include "misc.h"
#include "mxmisc.h"
#include "mxnotificationmanager.h"
#include "mxstillpresenter.h"
#include "mxtransitionmanager.h"
#include "pizza.h"

DECOMP_SIZE_ASSERT(SkateBoard, 0x168)

// FUNCTION: LEGO1 0x1000fd40
SkateBoard::SkateBoard()
{
	m_unk0x160 = FALSE;
	m_unk0x13c = 15.0;
	m_unk0x150 = 3.5;
	m_unk0x148 = 1;

	NotificationManager()->Register(this);
}

// FUNCTION: LEGO1 0x1000ff80
SkateBoard::~SkateBoard()
{
	ControlManager()->Unregister(this);
	NotificationManager()->Unregister(this);
}

// FUNCTION: LEGO1 0x10010000
MxResult SkateBoard::Create(MxDSAction& p_dsAction)
{
	MxResult result = IslePathActor::Create(p_dsAction);

	if (result == SUCCESS) {
		m_world = CurrentWorld();
		m_world->Add(this);

		Pizza* pizza = (Pizza*) CurrentWorld()->Find(*g_isleScript, IsleScript::c_Pizza_Actor);
		if (pizza) {
			pizza->SetSkateboard(this);
		}
	}

	return result;
}

// FUNCTION: LEGO1 0x10010050
void SkateBoard::VTable0xe4()
{
	if (m_act1state->m_unk0x018 == 3) {
		Pizza* pizza = (Pizza*) CurrentWorld()->Find(*g_isleScript, IsleScript::c_Pizza_Actor);
		pizza->FUN_10038380();
		pizza->FUN_100382b0();
		m_unk0x160 = FALSE;
	}

	IslePathActor::VTable0xe4();
	GameState()->m_currentArea = LegoGameState::Area::e_skateboard;
	RemoveFromCurrentWorld(*g_isleScript, IsleScript::c_SkateArms_Ctl);
	RemoveFromCurrentWorld(*g_isleScript, IsleScript::c_SkatePizza_Bitmap);
	ControlManager()->Unregister(this);
}

// FUNCTION: LEGO1 0x100100e0
MxU32 SkateBoard::VTable0xcc()
{
	Act1State* state = (Act1State*) GameState()->GetState("Act1State");

	if (!FUN_1003ef60() && state->m_unk0x018 != 3) {
		return 1;
	}

	FUN_10015820(TRUE, 0);

	((Isle*) CurrentWorld())->SetDestLocation(LegoGameState::Area::e_skateboard);
	TransitionManager()->StartTransition(MxTransitionManager::TransitionType::e_mosaic, 50, FALSE, TRUE);

	if (GameState()->GetActorId() != CurrentActor()->GetActorId()) {
		if (!CurrentActor()->IsA("SkateBoard")) {
			CurrentActor()->VTable0xe4();
		}
	}

	if (!CurrentActor()->IsA("SkateBoard")) {
		VTable0xe0();
		InvokeAction(Extra::ActionType::e_start, *g_isleScript, IsleScript::c_SkateDashboard, NULL);
		GetCurrentAction().SetObjectId(-1);
		ControlManager()->Register(this);
	}

	FUN_10010270(m_unk0x160);

	Vector3 position = m_roi->GetWorldPosition();
	AnimationManager()->FUN_10064670(&position);
	AnimationManager()->FUN_10064740(&position);
	return 1;
}

// FUNCTION: LEGO1 0x10010230
MxU32 SkateBoard::VTable0xd4(LegoControlManagerEvent& p_param)
{
	MxU32 result = 0;

	if (p_param.GetUnknown0x28() == 1 && p_param.GetClickedObjectId() == IsleScript::c_SkateArms_Ctl) {
		VTable0xe4();
		GameState()->m_currentArea = LegoGameState::Area::e_unk66;
		result = 1;
	}

	return result;
}

// FUNCTION: LEGO1 0x10010270
// FUNCTION: BETA10 0x100f5366
void SkateBoard::FUN_10010270(MxBool p_enable)
{
	m_act1state = (Act1State*) GameState()->GetState("Act1State");
	if (!m_act1state) {
		m_act1state = (Act1State*) GameState()->CreateState("Act1State");
	}

	MxStillPresenter* presenter = (MxStillPresenter*) m_world->Find(*g_isleScript, IsleScript::c_SkatePizza_Bitmap);
	if (presenter) {
		presenter->Enable(p_enable);
	}
	else if (m_unk0x160) {
		NotificationManager()->Send(this, MxNotificationParam(c_notificationType0, NULL));
	}
}

// FUNCTION: LEGO1 0x100104f0
// FUNCTION: BETA10 0x100f5472
MxU32 SkateBoard::VTable0xd0()
{
	FUN_10010270(m_unk0x160);
	return 1;
}

// FUNCTION: LEGO1 0x10010510
void SkateBoard::FUN_10010510()
{
	if (m_act1state->m_unk0x018 != 3) {
		PlayMusic(JukeboxScript::c_BeachBlvd_Music);

		if (!m_act1state->m_unk0x022) {
			m_act1state->m_unk0x022 = TRUE;

			MxMatrix mat(CurrentActor()->GetROI()->GetLocal2World());
			mat.TranslateBy(mat[2][0] * 2.5, mat[2][1] + 0.2, mat[2][2] * 2.5);

			AnimationManager()
				->FUN_10060dc0(IsleScript::c_sns008in_RunAnim, &mat, TRUE, FALSE, NULL, FALSE, TRUE, TRUE, TRUE);
		}
	}
}
