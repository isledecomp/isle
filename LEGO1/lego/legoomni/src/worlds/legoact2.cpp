#include "legoact2.h"

#include "act2actor.h"
#include "act2main_actions.h"
#include "actions/act2main_actions.h"
#include "islepathactor.h"
#include "legoanimationmanager.h"
#include "legocachesoundmanager.h"
#include "legogamestate.h"
#include "legoinputmanager.h"
#include "legomain.h"
#include "legopathstruct.h"
#include "legosoundmanager.h"
#include "misc.h"
#include "mxactionnotificationparam.h"
#include "mxbackgroundaudiomanager.h"
#include "mxdebug.h"
#include "mxmisc.h"
#include "mxnotificationmanager.h"
#include "mxticklemanager.h"

#include <vec.h>

DECOMP_SIZE_ASSERT(LegoAct2, 0x1154)
DECOMP_SIZE_ASSERT(LegoAct2State, 0x10)

// GLOBAL: LEGO1 0x100f4474
undefined4 g_unk0x100f4474 = 0;

// GLOBAL: LEGO1 0x100f43f0
// GLOBAL: BETA10 0x101e14a8
MxS32 g_unk0x100f43f0[] = {
	Act2mainScript::c_tns030bd_RunAnim,
	Act2mainScript::c_tns030pg_RunAnim,
	Act2mainScript::c_tns030rd_RunAnim,
	Act2mainScript::c_tns030sy_RunAnim,
	Act2mainScript::c_snsx35ro_RunAnim,
	Act2mainScript::c_snsx36ro_RunAnim,
	Act2mainScript::c_snsx37ro_RunAnim,
	Act2mainScript::c_snsx48cl_RunAnim
};

// GLOBAL: LEGO1 0x100f4410
LegoChar* g_unk0x100f4410[] = {"bd", "pg", "rd", "sy", "ro", "cl"};

// FUNCTION: LEGO1 0x1004fce0
// FUNCTION: BETA10 0x1003a5a0
LegoAct2::LegoAct2()
{
	m_unk0x10c4 = 0;
	m_gameState = NULL;
	m_unk0x10d8 = NULL;
	m_ambulance = NULL;
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
		return SUCCESS;
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
		AnimationManager()->FUN_100604f0(g_unk0x100f43f0, sizeOfArray(g_unk0x100f43f0));
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

	return SUCCESS;
}

// FUNCTION: LEGO1 0x10050380
// FUNCTION: BETA10 0x1003b049
MxLong LegoAct2::Notify(MxParam& p_param)
{
	MxNotificationParam& param = (MxNotificationParam&) p_param;
	MxLong result = 0;

	LegoWorld::Notify(p_param);

	if (m_worldStarted) {
		switch (param.GetNotification()) {
		case c_notificationEndAction:
			result = HandleEndAction((MxEndActionNotificationParam&) p_param);
			break;
		case c_notificationPathStruct: {
			MxTrace("trigger %d\n", ((LegoPathStructNotificationParam&) p_param).GetData());

			LegoPathStructNotificationParam& param = (LegoPathStructNotificationParam&) p_param;
			LegoEntity* entity = (LegoEntity*) param.GetSender();

			if (m_ambulance == NULL) {
				m_ambulance = FindROI("ambul");
			}

			if (entity->GetROI() == m_unk0x10d8) {
				HandlePathStruct(param);
			}

			result = 1;
			break;
		}
		case c_notificationType22:
			SoundManager()->GetCacheSoundManager()->Play("28bng", NULL, FALSE);

			m_unk0x10c1++;
			if (m_unk0x10c1 == 10 && m_unk0x10c4 == 13) {
				m_unk0x10c4 = 14;

				LegoEntity* entity = (LegoEntity*) param.GetSender();

				Mx3DPointFloat entityPosition(entity->GetROI()->GetWorldPosition());
				Mx3DPointFloat unk0x10d8Position(m_unk0x10d8->GetWorldPosition());
				Mx3DPointFloat locala4(unk0x10d8Position);

				((Vector3&) entityPosition).Sub(unk0x10d8Position);

				MxMatrix local2world(m_unk0x10d8->GetLocal2World());
				Vector3 local30(local2world[0]);
				Vector3 localac(local2world[1]);
				Vector3 local28(local2world[2]);

				local28 = entityPosition;
				local28.Unitize();

				Mx3DPointFloat local90(local28);
				((Vector3&) local90).Mul(1.25f);
				((Vector3&) locala4).Add(local90);
				locala4[1] += 0.25;
				local30.EqualsCross(&localac, &local28);
				local30.Unitize();

				Mx3DPointFloat locald4(local2world[2]);
				Mx3DPointFloat localc0(local2world[1]);
				FUN_10052560(Act2mainScript::c_tns051in_RunAnim, TRUE, TRUE, &localc0, &locald4, NULL);

				m_unk0x10c4 = 14;
				m_unk0x10d0 = 0;
				((LegoPathActor*) m_unk0x10d8->GetEntity())->SetState(LegoPathActor::c_bit3);
			}
			break;
		case c_notificationTransitioned:
			result = HandleTransitionEnd();
			break;
		}
	}

	return result;
}

// STUB: LEGO1 0x100506f0
MxLong LegoAct2::HandleEndAction(MxEndActionNotificationParam& p_param)
{
	// TODO
	return 0;
}

// STUB: LEGO1 0x10050a50
MxLong LegoAct2::HandleTransitionEnd()
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

// STUB: LEGO1 0x10051460
// STUB: BETA10 0x1003bb72
MxLong LegoAct2::HandlePathStruct(LegoPathStructNotificationParam& p_param)
{
	// TODO
	return 0;
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
