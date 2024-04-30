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
#include "mxtransitionmanager.h"
#include "pizza.h"

DECOMP_SIZE_ASSERT(SkateBoard, 0x168)

// FUNCTION: LEGO1 0x1000fd40
SkateBoard::SkateBoard()
{
	m_unk0x160 = 0;
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
		// The type `Pizza` is an educated guesss, inferred from VTable0xe4() below
		Pizza* findResult = (Pizza*) CurrentWorld()->Find(*g_isleScript, IsleScript::c_Pizza_Actor);
		if (findResult) {
			findResult->SetUnknown0x84((undefined*) this);
		}
	}

	return result;
}

// FUNCTION: LEGO1 0x10010050
void SkateBoard::VTable0xe4()
{
	// TODO: Work out what kind of structure this points to
	if (m_act1state->GetUnknown18() == 3) {
		Pizza* pizza = (Pizza*) CurrentWorld()->Find(*g_isleScript, IsleScript::c_Pizza_Actor);
		pizza->FUN_10038380();
		pizza->FUN_100382b0();
		m_unk0x160 = 0;
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
	Act1State* state = (Act1State*)GameState()->GetState("Act1State");
	if (FUN_1003ef60() && state->GetUnknown18() != 3) {
		return 1;
	}
	FUN_10015820(TRUE, 0);

	((Isle*)GetWorld())->SetDestLocation(LegoGameState::Area::e_skateboard);
	TransitionManager()->StartTransition(MxTransitionManager::TransitionType::e_mosaic, 0x32, FALSE, TRUE);
	if (GameState()->GetActorId() != CurrentActor()->GetActorId()) {
		if (!CurrentActor()->IsA("SkateBoard")) {
			CurrentActor()->VTable0xe4();
		}
	}
	if (!CurrentActor()->IsA("SkateBoard")) {
		InvokeAction(Extra::ActionType::e_start, *g_isleScript, 0xc1, NULL);
		GetCurrentAction().SetObjectId(-1);
		ControlManager()->Register(this);
	}
	FUN_10010270(this->m_unk0x160);
	// TODO: If this is correct, then the signature of the AnimationManager calls are wrong.
	MxBool puVar11 = (MxBool) 0xf4;
	AnimationManager()->FUN_10064670(puVar11);
	AnimationManager()->FUN_10064670(puVar11);
	return 1;
}

// FUNCTION: LEGO1 0x10010230
MxU32 SkateBoard::VTable0xd4(LegoControlManagerEvent& p_param)
{
	MxU32 result = 0;

	if (p_param.GetUnknown0x28() == 1 && p_param.GetClickedObjectId() == 0xc3) {
		VTable0xe4();
		GameState()->m_currentArea = LegoGameState::Area::e_unk66;
		result = 1;
	}

	return result;
}

// FUNCTION: LEGO1 0x10010270
void SkateBoard::FUN_10010270(undefined4 param_1)
{
	MxCore* pMVar3;

	m_act1state = (Act1State*) GameState()->GetState("Act1State");
	if (!m_act1state) {
		this->m_act1state = (Act1State*) GameState()->CreateState("Act1State");
	}
	if (pMVar3 = this->m_world->Find(*g_isleScript, IsleScript::c_SkatePizza_Bitmap)) {
		// I have no idea what this is. Need a call with vtable offset 0x54 and (likely) no argument.
		((LegoWorld*)pMVar3)->VTable0x54();

	} else {
		if (this->m_unk0x160 != '\0') {
			NotificationManager()->Send(this, MxNotificationParam(c_notificationType0, NULL));
		}
	}
}

// FUNCTION: LEGO1 0x100104f0
MxU32 SkateBoard::VTable0xd0()
{
	FUN_10010270(this->m_unk0x160);
	return 1;
}

// FUNCTION: LEGO1 0x10010510
void SkateBoard::FUN_10010510()
{
	if (m_act1state->GetUnknown18() != 3) {
		PlayMusic(JukeboxScript::c_BeachBlvd_Music);
		if (m_act1state->m_unk0x022 == '\0') {
			m_act1state->m_unk0x022 = 1;
			MxMatrix matrix = MxMatrix(CurrentActor()->GetROI()->GetLocal2World());
			matrix.TranslateBy(2.5 * matrix[2][0], 0.2 + matrix[2][1], 2.5 * matrix[2][2]);
			AnimationManager()
				->FUN_10060dc0(IsleScript::c_sns008in_RunAnim, &matrix, '\x01', '\0', NULL, 0, TRUE, TRUE, '\x01');
		}
	}
	return;
}
