#include "legoact2.h"

#include "act2actor.h"
#include "act2main_actions.h"
#include "actions/act2main_actions.h"
#include "islepathactor.h"
#include "legoanimationmanager.h"
#include "legogamestate.h"
#include "legoinputmanager.h"
#include "legomain.h"
#include "misc.h"
#include "mxbackgroundaudiomanager.h"
#include "mxmisc.h"
#include "mxnotificationmanager.h"
#include "mxticklemanager.h"

#include <vec.h>

DECOMP_SIZE_ASSERT(LegoAct2, 0x1154)
DECOMP_SIZE_ASSERT(LegoAct2State, 0x10)

// GLOBAL: LEGO1 0x100f4474
static undefined4 g_unk0x100f4474 = 0;

// GLOBAL: LEGO1 0x100f43f0
// GLOBAL: BETA10 0x101e14a8
static MxS32 g_unk0x100f43f0[] = {
	Act2mainScript::c_tns030bd_RunAnim,
	Act2mainScript::c_tns030pg_RunAnim,
	Act2mainScript::c_tns030rd_RunAnim,
	Act2mainScript::c_tns030sy_RunAnim,
	Act2mainScript::c_tns051in_RunAnim,
	Act2mainScript::c_tra045la_RunAnim,
	Act2mainScript::c_tns030bd_RunAnim,
	Act2mainScript::c_snsx48cl_RunAnim
};

// GLOBAL: LEGO1 0x100f4410
static LegoChar* g_unk0x100f4410[] = {"bd", "pg", "rd", "sy", "ro", "cl"};

// FUNCTION: LEGO1 0x1004fce0
// FUNCTION: BETA10 0x1003a5a0
LegoAct2::LegoAct2()
{
	m_unk0x10c4 = 0;
	m_gameState = NULL;
	m_unk0x10d8 = NULL;
	m_unk0x1128 = 0;
	m_unk0x10c2 = 0;
	m_unk0x1130 = 0;
	m_unk0x10c0 = 0;
	m_unk0x10c1 = 0;
	m_unk0x1138 = NULL;
	m_unk0x1140 = 0;
	m_unk0x1144 = 0;
	m_unk0x1150 = 0;
	m_unk0x10c8 = 0;
	m_unk0x10d4 = "";
	m_unk0x113c = 5;
	NotificationManager()->Register(this);
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

// FUNCTION: LEGO1 0x10050040
// FUNCTION: BETA10 0x1003a976
MxResult LegoAct2::Tickle()
{
	MxFloat distance;

	if (!m_worldStarted) {
		LegoWorld::Tickle();
		return 0;
	}

	switch (m_unk0x10c4) {
	case 0:
		m_unk0x10c4 = 1;
		break;
	case 1:
		((LegoPathActor*) m_unk0x10d8->GetEntity())->SetState(LegoPathActor::c_bit3);

		switch (rand() % 3) {
		case 0:
			g_unk0x100f4474 = Act2mainScript::c_tns002br_RunAnim;
			break;
		case 1:
			g_unk0x100f4474 = Act2mainScript::c_tns003br_RunAnim;
			break;
		case 2:
			g_unk0x100f4474 = Act2mainScript::c_tns004br_RunAnim;
			break;
		}

		FUN_10052560(g_unk0x100f4474, TRUE, TRUE, NULL, NULL, NULL);
		m_unk0x10d0 = 0;
		m_unk0x10c4 = 2;
		break;
	case 2:
		if (g_unk0x100f4474) {
			if (AnimationManager()->FUN_10064ee0(g_unk0x100f4474)) {
				FUN_10015820(FALSE, LegoOmni::c_disableInput | LegoOmni::c_disable3d | LegoOmni::c_clearScreen);
				g_unk0x100f4474 = 0;
			}
		}

		m_unk0x10d0 += 50;
		break;
	case 3:
		FUN_10015820(FALSE, LegoOmni::c_disableInput | LegoOmni::c_disable3d | LegoOmni::c_clearScreen);
		m_unk0x10d0 = 0;
		m_unk0x10c4 = 4;
		FUN_10052560(Act2mainScript::c_tja009ni_RunAnim, TRUE, TRUE, NULL, NULL, NULL);

		AnimationManager()->EnableCamAnims(TRUE);
		AnimationManager()->FUN_1005f6d0(TRUE);
		AnimationManager()->FUN_100604f0(&g_unk0x100f43f0[0], sizeOfArray(g_unk0x100f43f0));
		AnimationManager()->FUN_10060480(g_unk0x100f4410, sizeOfArray(g_unk0x100f4410));
		break;
	case 4:
		m_unk0x10d0 += 50;
		break;
	case 5:
		m_unk0x10d0 += 50;

		if (m_unk0x10d0 == 20000) {
			const MxFloat* pepperPosition = FindROI("pepper")->GetWorldPosition();
			MxFloat otherPoint[] = {-52.0f, 5.25f, -16.5f};

			distance = DISTSQRD3(pepperPosition, otherPoint);

			if (m_unk0x1144 == 0 && distance > 50.0f && pepperPosition[0] > -57.0f) {
				FUN_10052560(Act2mainScript::c_Avo906In_PlayWav, FALSE, FALSE, NULL, NULL, NULL);
				m_unk0x1144 = Act2mainScript::c_Avo906In_PlayWav;
			}
		}
		else if (m_unk0x10d0 >= 90000 && m_unk0x10d0 % 90000 == 0 && m_unk0x1144 == 0) {
			FUN_10052560(Act2mainScript::c_Avo908In_PlayWav, FALSE, FALSE, NULL, NULL, NULL);
			m_unk0x1144 = Act2mainScript::c_Avo908In_PlayWav;
		}

		break;
	case 6:
		m_unk0x10d0 += 50;
		break;
	case 9:
		m_unk0x10d0 += 50;

		if (m_unk0x10d0 >= 200) {
			if (m_unk0x10c0 < 5) {
				m_unk0x10c4 = 7;
			}
			else {
				m_unk0x10c4 = 10;
				m_unk0x10d0 = 0;
				m_unk0x1138->FUN_10019520();
			}
		}

		break;
	case 10:
		m_unk0x10d0 += 50;
		break;
	case 11:
		break;
	case 12:
		break;
	}

	return 0;
}

// STUB: LEGO1 0x10050380
// STUB: BETA10 0x1003b049
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
// STUB: BETA10 0x1003bb2d
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

// FUNCTION: LEGO1 0x100519c0
void LegoAct2::VTable0x60()
{
	// empty
}

// FUNCTION: LEGO1 0x100519d0
MxBool LegoAct2::Escape()
{
	BackgroundAudioManager()->Stop();
	AnimationManager()->FUN_10061010(FALSE);
	DeleteObjects(&m_atomId, Act2mainScript::c_snsx50bu_RunAnim, 999);

	if (UserActor() != NULL) {
		if (UserActor()->GetActorId() != GameState()->GetActorId()) {
			((IslePathActor*) UserActor())->Exit();
		}
	}

	if (m_gameState != NULL) {
		m_gameState->m_unk0x0c = 0;
	}

	m_unk0x1150 = 2;
	return TRUE;
}

// STUB: LEGO1 0x10052560
// STUB: BETA10 0x100145c6
undefined4 LegoAct2::FUN_10052560(
	undefined4 p_param1,
	MxBool p_param2,
	MxBool p_param3,
	Mx3DPointFloat* p_param4,
	Mx3DPointFloat* p_param5,
	Mx3DPointFloat* p_param6
)
{
	// TODO
	return 0;
}
