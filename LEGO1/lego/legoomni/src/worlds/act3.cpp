#include "act3.h"

#include "3dmanager/lego3dmanager.h"
#include "act3_actions.h"
#include "helicopter.h"
#include "legoanimationmanager.h"
#include "legobuildingmanager.h"
#include "legocontrolmanager.h"
#include "legomain.h"
#include "legonavcontroller.h"
#include "legoplantmanager.h"
#include "legovideomanager.h"
#include "misc.h"
#include "mxbackgroundaudiomanager.h"
#include "mxmisc.h"
#include "mxnotificationmanager.h"
#include "mxticklemanager.h"
#include "mxtransitionmanager.h"

DECOMP_SIZE_ASSERT(Act3, 0x4274)
DECOMP_SIZE_ASSERT(Act3State, 0x0c)
DECOMP_SIZE_ASSERT(Act3ListElement, 0x0c)
DECOMP_SIZE_ASSERT(Act3List, 0x10)

// GLOBAL: LEGO1 0x100d95e8
Act3Script::Script g_unk0x100d95e8[] =
	{Act3Script::c_tlp053in_RunAnim, Act3Script::c_tlp064la_RunAnim, Act3Script::c_tlp068in_RunAnim};

// FUNCTION: LEGO1 0x10072270
// FUNCTION: BETA10 0x10015470
Act3::Act3()
{
	m_gameState = NULL;
	m_unk0x41fc = 0;
	m_cop1 = NULL;
	m_cop2 = NULL;
	m_brickster = NULL;
	m_copter = NULL;
	m_shark = NULL;
	m_unk0x4214 = -1;
	m_unk0x421e = 0;

	memset(m_unk0x4230, 0, sizeof(m_unk0x4230));

	NavController()->ResetMaxLinearAccel(NavController()->GetMaxLinearAccel() * 30.0f);
	NavController()->ResetMaxLinearDeccel(NavController()->GetMaxLinearDeccel() * 30.0f);
	NotificationManager()->Register(this);
}

// FUNCTION: LEGO1 0x10072500
MxBool Act3::VTable0x5c()
{
	return TRUE;
}

// FUNCTION: LEGO1 0x100726a0
// FUNCTION: BETA10 0x100155da
Act3::~Act3()
{
	Destroy(TRUE);
	NotificationManager()->Unregister(this);
	TickleManager()->UnregisterClient(this);
}

// STUB: LEGO1 0x100727e0
MxBool Act3::FUN_100727e0(LegoPathController*, Mx3DPointFloat& p_loc, Mx3DPointFloat& p_dir, Mx3DPointFloat& p_up)
{
	return FALSE;
}

// STUB: LEGO1 0x10072980
MxBool Act3::FUN_10072980(LegoPathController*, Mx3DPointFloat& p_loc, Mx3DPointFloat& p_dir, Mx3DPointFloat& p_up)
{
	return FALSE;
}

// FUNCTION: LEGO1 0x10072c30
// FUNCTION: BETA10 0x100160fb
MxResult Act3::Create(MxDSAction& p_dsAction)
{
	GameState()->FindLoadedAct();

	MxResult result = LegoWorld::Create(p_dsAction);
	if (result == SUCCESS) {
		ControlManager()->Register(this);
		InputManager()->SetWorld(this);
		InputManager()->Register(this);

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

		LegoGameState* gameState = GameState();
		Act3State* state = (Act3State*) gameState->GetState("Act3State");

		if (state == NULL) {
			state = (Act3State*) gameState->CreateState("Act3State");
		}

		m_gameState = state;

		GameState()->m_currentArea = LegoGameState::e_act3script;
		GameState()->SetCurrentAct(LegoGameState::e_act3);
		GameState()->SetDirty(TRUE);
	}

	return result;
}

// FUNCTION: LEGO1 0x10072d50
// FUNCTION: BETA10 0x1001627f
void Act3::Destroy(MxBool p_fromDestructor)
{
	NavController()->Reset();
	ControlManager()->Unregister(this);

	if (InputManager()->GetWorld() == this) {
		InputManager()->ClearWorld();
	}

	InputManager()->UnRegister(this);

	if (UserActor() != NULL) {
		if ((IslePathActor*) UserActor() == m_copter) {
			((IslePathActor*) UserActor())->Exit();
		}

		Remove(UserActor());
	}

	if (!p_fromDestructor) {
		LegoWorld::Destroy(FALSE);
	}
}

// STUB: LEGO1 0x10072de0
// STUB: BETA10 0x10016322
MxLong Act3::Notify(MxParam& p_param)
{
	// TODO
	return 0;
}

// FUNCTION: LEGO1 0x10073270
void Act3::ReadyWorld()
{
	PlantManager()->FUN_10027200();
	BuildingManager()->FUN_10030800();
	AnimationManager()->FUN_1005f6d0(FALSE);
	VideoManager()->Get3DManager()->SetFrustrum(90.0f, 0.1f, 125.0f);

	m_unk0x426c = g_unk0x100d95e8[rand() % 3];
	AnimationManager()->FUN_10060dc0(m_unk0x426c, NULL, TRUE, FALSE, NULL, TRUE, FALSE, FALSE, FALSE);

	m_gameState->m_unk0x08 = 1;
}

// FUNCTION: LEGO1 0x10073300
MxResult Act3::Tickle()
{
	if (!m_worldStarted) {
		LegoWorld::Tickle();
		return SUCCESS;
	}

	if (m_unk0x426c != (Act3Script::Script) 0) {
		if (AnimationManager()->FUN_10064ee0(m_unk0x426c)) {
			FUN_10015820(FALSE, LegoOmni::c_disableInput | LegoOmni::c_disable3d | LegoOmni::c_clearScreen);
			TickleManager()->UnregisterClient(this);
			m_unk0x426c = (Act3Script::Script) 0;
		}
	}

	return SUCCESS;
}

// FUNCTION: LEGO1 0x10073400
void Act3::FUN_10073400()
{
	m_gameState->m_unk0x08 = 2;
	m_destLocation = LegoGameState::e_infomain;
	TransitionManager()->StartTransition(MxTransitionManager::e_mosaic, 50, FALSE, FALSE);
}

// FUNCTION: LEGO1 0x10073430
void Act3::FUN_10073430()
{
	m_gameState->m_unk0x08 = 3;
	m_destLocation = LegoGameState::e_infomain;
	TransitionManager()->StartTransition(MxTransitionManager::e_mosaic, 50, FALSE, FALSE);
}

// STUB: LEGO1 0x10073a90
void Act3::Enable(MxBool p_enable)
{
	// TODO
}

// FUNCTION: LEGO1 0x10073e40
void Act3::VTable0x60()
{
	// empty
}

// FUNCTION: LEGO1 0x10073e50
MxBool Act3::Escape()
{
	BackgroundAudioManager()->Stop();
	AnimationManager()->FUN_10061010(FALSE);
	DeleteObjects(&m_atomId, Act3Script::c_tlp053in_RunAnim, 999);
	m_destLocation = LegoGameState::e_infomain;
	return TRUE;
}
