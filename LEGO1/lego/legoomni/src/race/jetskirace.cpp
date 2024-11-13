#include "jetskirace.h"

#include "actions/jetrace_actions.h"
#include "actions/jukebox_actions.h"
#include "dunebuggy.h"
#include "isle.h"
#include "legoanimationmanager.h"
#include "legocontrolmanager.h"
#include "legohideanimpresenter.h"
#include "legomain.h"
#include "legopathstruct.h"
#include "legoracespecial.h"
#include "legoutils.h"
#include "misc.h"
#include "mxactionnotificationparam.h"
#include "mxbackgroundaudiomanager.h"
#include "mxmisc.h"
#include "mxstillpresenter.h"
#include "mxtransitionmanager.h"
#include "mxvariabletable.h"
#include "scripts.h"

// Defined in legopathstruct.cpp
extern MxBool g_unk0x100f119c;

// Defined in jetski.cpp
extern const char* g_varJSFRNTY5;
extern const char* g_varJSWNSHY5;

// Defined in legoracespecial.cpp
extern const char* g_raceState;
extern const char* g_racing;

// Defined in legopathactor.cpp
extern const char* g_strHIT_WALL_SOUND;

// GLOBAL: LEGO1 0x100f0bac
static undefined4 g_unk0x100f0bac = 0;

// GLOBAL: LEGO1 0x100f0bb0
static undefined4 g_unk0x100f0bb0 = 0;

DECOMP_SIZE_ASSERT(JetskiRace, 0x144)

// FUNCTION: LEGO1 0x100162c0
// FUNCTION: BETA10 0x100c7e6f
MxResult JetskiRace::Create(MxDSAction& p_dsAction)
{
	MxResult result = LegoRace::Create(p_dsAction);

	GameState()->m_currentArea = LegoGameState::e_jetrace;
	GameState()->StopArea(LegoGameState::e_undefined);
	LegoGameState* gameState = GameState();
	RaceState* jetskiRaceState = (RaceState*) gameState->GetState("JetskiRaceState");

	if (!jetskiRaceState) {
		jetskiRaceState = (RaceState*) gameState->CreateState("JetskiRaceState");
	}

	m_raceState = jetskiRaceState;

	if (!jetskiRaceState) {
		return FAILURE;
	}

	m_raceState->m_unk0x28 = 1;
	m_unk0x130.SetLeft(397);
	m_unk0x130.SetTop(317);
	m_unk0x130.SetRight(543);
	m_unk0x130.SetBottom(333);
	FUN_10013670();
	InvokeAction(
		Extra::e_start,
		m_atomId,
		DuneBuggy::GetColorOffset(g_varJSFRNTY5) + (DuneBuggy::GetColorOffset(g_varJSWNSHY5) * 5 + 0xf) * 2,
		NULL
	);
	InvokeAction(Extra::e_start, m_atomId, 0x61, NULL);
	g_unk0x100f119c = TRUE;

	return result;
}

// FUNCTION: LEGO1 0x10013670
void JetskiRace::FUN_10013670()
{
	g_unk0x100f0bac = (rand() & 0xc) >> 2;

	// Inlining the `rand()` causes this function to mismatch
	MxU32 uVar1 = rand();
	g_unk0x100f0bb0 = uVar1 % 0xc >> 2;
}

// FUNCTION: LEGO1 0x100163b0
// FUNCTION: BETA10 0x100c7f10
void JetskiRace::ReadyWorld()
{
	assert(m_hideAnim);
	LegoWorld::ReadyWorld();
	m_hideAnim->FUN_1006db40(0);

	MxDSAction action;
	action.SetAtomId(*g_jukeboxScript);
	action.SetObjectId(JukeboxScript::c_JetskiRace_Music);
	BackgroundAudioManager()->PlayMusic(action, 5, MxPresenter::e_repeating);

	AnimationManager()->Resume();

	m_unk0x128 = (MxStillPresenter*) Find("MxPresenter", "JetskiLocator2");
	m_unk0x128->SetPosition(m_unk0x130.GetLeft(), m_unk0x130.GetTop());
	m_unk0x12c = (MxStillPresenter*) Find("MxPresenter", "JetskiLocator3");
	m_unk0x12c->SetPosition(m_unk0x130.GetLeft(), m_unk0x130.GetTop());

	FUN_10015820(FALSE, LegoOmni::c_disableInput | LegoOmni::c_disable3d | LegoOmni::c_clearScreen);

	VariableTable()->SetVariable("DISTANCE", "0.036");

	InvokeAction(Extra::e_start, *g_jetraceScript, JetraceScript::c_AirHorn_PlayWav, NULL);
}

// FUNCTION: LEGO1 0x10016520
MxLong JetskiRace::HandleEndAction(MxEndActionNotificationParam& p_param)
{
	MxLong result = 0;

	if ((p_param.GetAction()) && (p_param.GetAction()->GetObjectId() == JetraceScript::c_AirHorn_PlayWav)) {
		m_unk0x110[0]->Mute(FALSE);
		m_unk0x110[1]->Mute(FALSE);
		m_unk0x110[2]->Mute(FALSE);

		VariableTable()->SetVariable(g_raceState, g_racing);
		result = 1;
	}

	return result;
}

// FUNCTION: LEGO1 0x100165a0
MxLong JetskiRace::HandleClick(LegoEventNotificationParam& p_param)
{
	MxLong result = 0;
	if (((LegoControlManagerNotificationParam*) &p_param)->m_unk0x28 == 1) {
		switch (((LegoControlManagerNotificationParam*) &p_param)->m_clickedObjectId) {
		case JetraceScript::c_JetskiArms_Ctl:
			m_act1State->m_unk0x018 = 0;
			VariableTable()->SetVariable(g_raceState, "");
			VariableTable()->SetVariable(g_strHIT_WALL_SOUND, "");
			LegoCarRaceActor::FUN_10012de0();
			m_destLocation = LegoGameState::e_jetraceExterior;
			TransitionManager()->StartTransition(MxTransitionManager::e_mosaic, 50, FALSE, FALSE);
			return 0;
		case JetraceScript::c_JetskiInfo_Ctl:
			m_act1State->m_unk0x018 = 0;
			VariableTable()->SetVariable(g_raceState, "");
			VariableTable()->SetVariable(g_strHIT_WALL_SOUND, "");
			LegoCarRaceActor::FUN_10012de0();
			m_destLocation = LegoGameState::e_infomain;
			result = 1;
			TransitionManager()->StartTransition(MxTransitionManager::e_mosaic, 50, FALSE, FALSE);
			break;
		default:
			return 0;
		}
	}
	return result;
}

// STUB: LEGO1 0x100166a0
MxLong JetskiRace::HandlePathStruct(LegoPathStructNotificationParam&)
{
	return 0;
}

// FUNCTION: LEGO1 0x10016a10
MxBool JetskiRace::Escape()
{
	AnimationManager()->FUN_10061010(FALSE);
	DeleteObjects(&m_atomId, 500, 999);
	m_act1State->m_unk0x018 = 0;
	VariableTable()->SetVariable(g_raceState, "");
	VariableTable()->SetVariable(g_strHIT_WALL_SOUND, "");
	m_destLocation = LegoGameState::e_infomain;
	LegoCarRaceActor::FUN_10012de0();
	return TRUE;
}
