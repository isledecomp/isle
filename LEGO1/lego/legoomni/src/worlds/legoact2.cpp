#include "legoact2.h"

#include "legoanimationmanager.h"
#include "legogamestate.h"
#include "legoinputmanager.h"
#include "misc.h"
#include "mxmisc.h"
#include "mxnotificationmanager.h"
#include "mxticklemanager.h"

DECOMP_SIZE_ASSERT(LegoAct2, 0x1154)
DECOMP_SIZE_ASSERT(LegoAct2State, 0x10)

// STUB: LEGO1 0x1004fce0
// STUB: BETA10 0x1003a5a0
LegoAct2::LegoAct2()
{
	// TODO
}

// FUNCTION: LEGO1 0x1004fe10
MxBool LegoAct2::VTable0x5c()
{
	return TRUE;
}

// FUNCTION: LEGO1 0x1004fe40
// FUNCTION: BETA10 0x1003a6f0
LegoAct2::~LegoAct2()
{
	if (m_unk0x10c2) {
		TickleManager()->UnregisterClient(this);
	}

	FUN_10051900();
	InputManager()->UnRegister(this);
	if (UserActor()) {
		Remove(UserActor());
	}

	NotificationManager()->Unregister(this);
}

// FUNCTION: LEGO1 0x1004ff20
// FUNCTION: BETA10 0x1003a7ff
MxResult LegoAct2::Create(MxDSAction& p_dsAction)
{
	GameState()->FindLoadedAct();

	MxResult result = LegoWorld::Create(p_dsAction);
	if (result == SUCCESS) {
		AnimationManager()->EnableCamAnims(FALSE);

		LegoGameState* gameState = GameState();
		LegoAct2State* state = (LegoAct2State*) gameState->GetState("LegoAct2State");

		if (state == NULL) {
			state = (LegoAct2State*) gameState->CreateState("LegoAct2State");
		}

		m_gameState = state;
		m_gameState->m_unk0x08 = 0;

		switch (GameState()->GetLoadedAct()) {
		case LegoGameState::e_act2:
			GameState()->StopArea(LegoGameState::e_infomain);
			GameState()->StopArea(LegoGameState::e_act2main);
			break;
		case LegoGameState::e_act3:
			GameState()->StopArea(LegoGameState::e_infomain);
			GameState()->StopArea(LegoGameState::e_act3script);
			break;
		case LegoGameState::e_act1:
		case LegoGameState::e_actNotFound:
			GameState()->StopArea(LegoGameState::e_undefined);
			if (GameState()->GetPreviousArea() == LegoGameState::e_infomain) {
				GameState()->StopArea(LegoGameState::e_isle);
			}
		}

		GameState()->m_currentArea = LegoGameState::e_act2main;
		GameState()->SetCurrentAct(LegoGameState::e_act2);
		InputManager()->Register(this);
		GameState()->SetDirty(TRUE);
	}

	return result;
}

// STUB: LEGO1 0x10050040
MxResult LegoAct2::Tickle()
{
	// TODO
	return SUCCESS;
}

// STUB: LEGO1 0x10050380
MxLong LegoAct2::Notify(MxParam& p_param)
{
	// TODO
	return 0;
}

// STUB: LEGO1 0x10050a80
void LegoAct2::ReadyWorld()
{
	// TODO
}

// STUB: LEGO1 0x10050cf0
void LegoAct2::Enable(MxBool p_enable)
{
	// TODO
}

// FUNCTION: LEGO1 0x10051900
// FUNCTION: BETA10 0x1003bed1
void LegoAct2::FUN_10051900()
{
	if (AnimationManager()) {
		AnimationManager()->Suspend();
		AnimationManager()->Resume();
		AnimationManager()->FUN_10060540(FALSE);
		AnimationManager()->FUN_100604d0(FALSE);
		AnimationManager()->EnableCamAnims(FALSE);
		AnimationManager()->FUN_1005f6d0(FALSE);
	}
}

// STUB: LEGO1 0x100519c0
void LegoAct2::VTable0x60()
{
	// TODO
}

// STUB: LEGO1 0x100519d0
MxBool LegoAct2::Escape()
{
	// TODO
	return FALSE;
}
