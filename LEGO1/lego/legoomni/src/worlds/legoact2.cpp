#include "legoact2.h"

#include "3dmanager/lego3dmanager.h"
#include "act2actor.h"
#include "act2main_actions.h"
#include "infomain_actions.h"
#include "islepathactor.h"
#include "jukebox_actions.h"
#include "legoanimationmanager.h"
#include "legocachesoundmanager.h"
#include "legogamestate.h"
#include "legoinputmanager.h"
#include "legolocomotionanimpresenter.h"
#include "legomain.h"
#include "legopathstruct.h"
#include "legosoundmanager.h"
#include "legoutils.h"
#include "legovideomanager.h"
#include "misc.h"
#include "mxactionnotificationparam.h"
#include "mxbackgroundaudiomanager.h"
#include "mxdebug.h"
#include "mxmisc.h"
#include "mxnotificationmanager.h"
#include "mxticklemanager.h"
#include "mxtransitionmanager.h"
#include "mxvariabletable.h"
#include "scripts.h"

#include <vec.h>

DECOMP_SIZE_ASSERT(LegoAct2, 0x1154)
DECOMP_SIZE_ASSERT(LegoAct2State, 0x10)

// GLOBAL: LEGO1 0x100f4474
Act2mainScript::Script g_unk0x100f4474 = (Act2mainScript::Script) 0;

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
const LegoChar* g_unk0x100f4410[] = {"bd", "pg", "rd", "sy", "ro", "cl"};

// GLOBAL: LEGO1 0x100f4428
MxS32 g_unk0x100f4428[] = {
	Act2mainScript::c_snsx07pa_RunAnim,
	Act2mainScript::c_snsx12ni_RunAnim,
	Act2mainScript::c_snsx15la_RunAnim,
	Act2mainScript::c_snsx47cl_RunAnim,
	Act2mainScript::c_snsx65pg_RunAnim,
	Act2mainScript::c_snsx68pg_RunAnim,
	Act2mainScript::c_snsx69rd_RunAnim,
	Act2mainScript::c_snsx72sy_RunAnim,
	0,
	0,
	0,
	0
};

// GLOBAL: LEGO1 0x100f4458
const LegoChar* g_unk0x100f4458[] = {"papa", "nick", "laura", "cl", "pg", "rd", "sy"};

// FUNCTION: LEGO1 0x1004fce0
// FUNCTION: BETA10 0x1003a5a0
LegoAct2::LegoAct2()
{
	m_unk0x10c4 = 0;
	m_gameState = NULL;
	m_pepper = NULL;
	m_ambulance = NULL;
	m_ready = FALSE;
	m_unk0x1130 = 0;
	m_nextBrick = 0;
	m_unk0x10c1 = 0;
	m_unk0x1138 = NULL;
	m_unk0x1140 = (Act2mainScript::Script) 0;
	m_unk0x1144 = (Act2mainScript::Script) 0;
	m_destLocation = LegoGameState::e_undefined;
	m_music = JukeboxScript::c_MusicTheme1;
	m_siFile = "";
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
	if (m_ready) {
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
		((LegoPathActor*) m_pepper->GetEntity())->SetActorState(LegoPathActor::c_disabled);

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
				g_unk0x100f4474 = (Act2mainScript::Script) 0;
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

			if (m_unk0x1144 == (Act2mainScript::Script) 0 && distance > 50.0f && pepperPosition[0] > -57.0f) {
				FUN_10052560(Act2mainScript::c_Avo906In_PlayWav, FALSE, FALSE, NULL, NULL, NULL);
				m_unk0x1144 = Act2mainScript::c_Avo906In_PlayWav;
			}
		}
		else if (m_unk0x10d0 >= 90000 && m_unk0x10d0 % 90000 == 0 && m_unk0x1144 == (Act2mainScript::Script) 0) {
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
			if (m_nextBrick < 5) {
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

			if (entity->GetROI() == m_pepper) {
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

				Mx3DPointFloat local20(entity->GetROI()->GetWorldPosition());
				Mx3DPointFloat locale8(m_pepper->GetWorldPosition());
				Mx3DPointFloat locala4(locale8);

				local20 -= locale8;

				MxMatrix local2world(m_pepper->GetLocal2World());
				Vector3 local30(local2world[0]);
				Vector3 localac(local2world[1]);
				Vector3 local28(local2world[2]);

				local28 = local20;
				local28.Unitize();

				Mx3DPointFloat local90(local28);
				local90 *= 1.25f;
				locala4 += local90;
				locala4[1] += 0.25;
				local30.EqualsCross(&localac, &local28);
				local30.Unitize();

				Mx3DPointFloat locald4(local2world[2]);
				Mx3DPointFloat localc0(local2world[1]);
				FUN_10052560(Act2mainScript::c_tns051in_RunAnim, TRUE, TRUE, &locala4, &locald4, NULL);

				m_unk0x10c4 = 14;
				m_unk0x10d0 = 0;
				((LegoPathActor*) m_pepper->GetEntity())->SetActorState(LegoPathActor::c_disabled);
			}
			break;
		case c_notificationTransitioned:
			result = HandleTransitionEnd();
			break;
		}
	}

	return result;
}

// FUNCTION: LEGO1 0x100506f0
MxLong LegoAct2::HandleEndAction(MxEndActionNotificationParam& p_param)
{
	if (m_gameState->m_enabled && p_param.GetAction() != NULL) {
		MxU32 objectId = p_param.GetAction()->GetObjectId();

		if (m_unk0x10c4 == 5 && m_unk0x1144 == objectId) {
			m_unk0x1144 = (Act2mainScript::Script) 0;
			return 0;
		}

		if (m_unk0x1140 != objectId) {
			return 0;
		}

		m_unk0x1140 = (Act2mainScript::Script) 0;

		switch (m_unk0x10c4) {
		case 2:
			m_unk0x10c4 = 3;
			break;
		case 4:
			FUN_10051960();
			m_unk0x10c4 = 5;
			m_unk0x10d0 = 0;
			break;
		case 6: {
			LegoROI* roi;

			roi = FindROI("nick");
			if (roi != NULL) {
				roi->SetVisibility(FALSE);
			}

			roi = FindROI("laura");
			if (roi != NULL) {
				roi->SetVisibility(FALSE);
			}

			roi = FindROI("motoni");
			if (roi != NULL) {
				roi->SetVisibility(FALSE);
			}

			roi = FindROI("motola");
			if (roi != NULL) {
				roi->SetVisibility(FALSE);
			}

			roi = FindROI("Block01");
			RemoveActor((LegoPathActor*) roi->GetEntity());
			roi->SetVisibility(FALSE);

			roi = FindROI("Block02");
			RemoveActor((LegoPathActor*) roi->GetEntity());
			roi->SetVisibility(FALSE);

			VariableTable()->SetVariable("ACTOR_01", "brickstr");
			FUN_10052800();
			m_unk0x10c4 = 7;
			PlayMusic(JukeboxScript::c_BrickstrChase);
			break;
		}
		case 11:
			m_bricks[m_nextBrick - 1].Mute(TRUE);
			m_unk0x10c4 = 12;
			m_unk0x10d0 = 0;

			FUN_10052560(Act2mainScript::c_tra045la_RunAnim, TRUE, TRUE, NULL, NULL, NULL);
			((LegoPathActor*) m_pepper->GetEntity())->SetActorState(LegoPathActor::c_disabled);
			AnimationManager()->EnableCamAnims(TRUE);
			AnimationManager()->FUN_1005f6d0(TRUE);
			AnimationManager()->FUN_100604f0(g_unk0x100f4428, sizeOfArray(g_unk0x100f4428));
			AnimationManager()->FUN_10060480(g_unk0x100f4458, sizeOfArray(g_unk0x100f4458));
			break;
		case 12: {
			LegoROI* roi;

			roi = FindROI("nick");
			if (roi != NULL) {
				roi->SetVisibility(FALSE);
			}

			roi = FindROI("laura");
			if (roi != NULL) {
				roi->SetVisibility(FALSE);
			}

			roi = FindROI("motoni");
			if (roi != NULL) {
				roi->SetVisibility(FALSE);
			}

			roi = FindROI("motola");
			if (roi != NULL) {
				roi->SetVisibility(FALSE);
			}

			m_bricks[m_nextBrick - 1].Mute(FALSE);
			m_unk0x10c4 = 13;
			SpawnBricks();
			PlayMusic(JukeboxScript::c_BrickHunt);
			((LegoPathActor*) m_pepper->GetEntity())->SetActorState(LegoPathActor::c_initial);
			break;
		}
		case 14:
			for (MxS32 i = 0; i < (MxS32) sizeOfArray(m_bricks); i++) {
				m_bricks[i].Remove();
			}

			FUN_10051900();
			m_destLocation = LegoGameState::e_copterbuild;
			TransitionManager()->StartTransition(MxTransitionManager::e_mosaic, 50, FALSE, FALSE);
			break;
		}
	}

	return 0;
}

// FUNCTION: LEGO1 0x10050a50
MxLong LegoAct2::HandleTransitionEnd()
{
	if (m_destLocation != LegoGameState::e_undefined) {
		GameState()->SwitchArea(m_destLocation);
		m_destLocation = LegoGameState::e_undefined;
	}

	return 1;
}

// FUNCTION: LEGO1 0x10050a80
void LegoAct2::ReadyWorld()
{
	LegoWorld::ReadyWorld();

	AnimationManager()->Resume();
	TickleManager()->RegisterClient(this, 20);

	m_ready = TRUE;
	m_siFile = VariableTable()->GetVariable("ACT2_ANIMS_FILE");

	GameState()->SetActor(LegoActor::c_pepper);
	m_pepper = FindROI("pepper");
	IslePathActor* pepper = (IslePathActor*) m_pepper->GetEntity();
	pepper->SpawnPlayer(
		LegoGameState::e_unk50,
		TRUE,
		IslePathActor::c_spawnBit1 | IslePathActor::c_playMusic | IslePathActor::c_spawnBit3
	);

	LegoROI* roi = FindROI("Block01");
	BoundingSphere sphere = roi->GetBoundingSphere();
	sphere.Radius() *= 1.5;
	roi->SetBoundingSphere(sphere);
	LegoPathActor* actor = (LegoPathActor*) roi->GetEntity();
	PlaceActor(actor, "EDG01_04", 1, 0.5f, 3, 0.5f);

	MxMatrix local2world = roi->GetLocal2World();
	local2world[3][0] -= 1.5;
	roi->FUN_100a58f0(local2world);
	roi->VTable0x14();

	roi = FindROI("Block02");
	sphere = roi->GetBoundingSphere();
	sphere.Radius() *= 1.5;
	roi->SetBoundingSphere(sphere);
	actor = (LegoPathActor*) roi->GetEntity();
	PlaceActor(actor, "EDG00_149", 0, 0.5f, 2, 0.5f);

	PlayMusic(JukeboxScript::c_Jail_Music);
	FUN_10051900();
	VideoManager()->Get3DManager()->SetFrustrum(90.0f, 0.1f, 250.f);
	m_gameState->m_enabled = TRUE;
}

// FUNCTION: LEGO1 0x10050cf0
// FUNCTION: BETA10 0x1003bb2d
void LegoAct2::Enable(MxBool p_enable)
{
	if ((MxBool) m_set0xd0.empty() == p_enable) {
		return;
	}

	LegoWorld::Enable(p_enable);

	if (p_enable) {
		m_gameState->m_enabled = TRUE;

		GameState()->SetActor(LegoActor::c_pepper);
		m_pepper = FindROI("pepper");

		((IslePathActor*) m_pepper->GetEntity())->VTable0xec(m_unk0x10dc, m_unk0x1124, TRUE);

		if (GameState()->GetPreviousArea() == LegoGameState::e_infomain) {
			GameState()->StopArea(LegoGameState::e_infomain);
		}

		FUN_10015820(FALSE, LegoOmni::c_disableInput | LegoOmni::c_disable3d | LegoOmni::c_clearScreen);

		if (m_unk0x10c4 != 6 && m_unk0x10c4 != 12) {
			PlayMusic(m_music);
		}

		if (m_unk0x10c4 == 10 && m_nextBrick == 6 && m_bricks[5].GetROI() != NULL) {
			m_bricks[5].PlayWhistleSound();
		}
		else if (m_unk0x10c4 == 13) {
			InitBricks();
		}

		TickleManager()->RegisterClient(this, 20);
		SetAppCursor(e_cursorArrow);

		if (m_unk0x10c4 == 2 || m_unk0x10c4 == 4 || m_unk0x10c4 == 6 || m_unk0x10c4 == 11 || m_unk0x10c4 == 12 ||
			m_unk0x10c4 == 14) {
			MxDSAction action;
			MxEndActionNotificationParam param(c_notificationEndAction, NULL, &action, FALSE);

			m_unk0x1140 = (Act2mainScript::Script) 0;
			action.SetObjectId(0);
			HandleEndAction(param);
		}

		GameState()->m_isDirty = TRUE;
	}
	else {
		m_unk0x10dc = m_pepper->GetLocal2World();
		m_unk0x1124 = ((LegoPathActor*) m_pepper->GetEntity())->GetBoundary();

		FUN_10051900();
		BackgroundAudioManager()->Stop();
		UninitBricks();
		DeleteObjects(&m_atomId, Act2mainScript::c_VOhead0_PlayWav, Act2mainScript::c_VOhide_PlayWav);

		if (m_unk0x1144 != (Act2mainScript::Script) 0) {
			MxDSAction action;
			action.SetAtomId(m_atomId);
			action.SetUnknown24(-2);
			action.SetObjectId(m_unk0x1144);
			DeleteObject(action);
			m_unk0x1144 = (Act2mainScript::Script) 0;
		}

		TickleManager()->UnregisterClient(this);
	}
}

// FUNCTION: LEGO1 0x10051460
// FUNCTION: BETA10 0x1003bb72
MxLong LegoAct2::HandlePathStruct(LegoPathStructNotificationParam& p_param)
{
	if (m_unk0x10c4 == 5 && p_param.GetData() == 0x32) {
		LegoPathActor* actor = (LegoPathActor*) m_pepper->GetEntity();
		actor->SetActorState(LegoPathActor::c_disabled);
		actor->SetWorldSpeed(0.0f);
		FUN_10051900();

		if (m_unk0x10d0 < 90000) {
			FUN_10052560(Act2mainScript::c_tra031ni_RunAnim, TRUE, TRUE, NULL, NULL, NULL);
		}
		else {
			FUN_10052560(Act2mainScript::c_tra032ni_RunAnim, TRUE, TRUE, NULL, NULL, NULL);
		}

		m_unk0x112c = 50;
		m_unk0x10c4 = 6;
		m_unk0x10d0 = 0;
	}
	else if (m_unk0x10c4 == 5 && p_param.GetData() == 0x2a) {
		if (m_unk0x1144 == (Act2mainScript::Script) 0) {
			FUN_10052560(Act2mainScript::c_Avo907In_PlayWav, FALSE, FALSE, NULL, NULL, NULL);
			m_unk0x1144 = Act2mainScript::c_Avo907In_PlayWav;
		}
	}
	else if (m_unk0x10c4 == 5) {
		FUN_100521f0(p_param.GetData());
	}
	else if (m_unk0x10c4 == 7) {
		FUN_10051fa0(p_param.GetData());
	}
	else if (m_unk0x10c4 == 10 && p_param.GetData() == 0x165) {
		((LegoPathActor*) m_pepper->GetEntity())->SetActorState(LegoPathActor::c_disabled);

		if (FUN_10052560(Act2mainScript::c_VOhide_PlayWav, FALSE, TRUE, NULL, NULL, NULL) == SUCCESS) {
			m_unk0x1140 = Act2mainScript::c_VOhide_PlayWav;
		}

		m_unk0x1138->FUN_10019560();

		m_unk0x10c4 = 11;
		m_unk0x10d0 = 0;

		if (m_nextBrick < 6) {
			m_bricks[m_nextBrick].Create(m_nextBrick);
			m_nextBrick++;
		}

		MxMatrix local2world = m_ambulance->GetLocal2World();
		MxMatrix local2world2 = local2world;

		LegoPathBoundary* boundary = m_unk0x1138->GetBoundary();
		local2world[3][1] += 1.5;
		local2world2[3][1] -= 0.1;

		m_bricks[m_nextBrick - 1].FUN_1007a670(local2world, local2world2, boundary);
	}

	return 0;
}

// FUNCTION: LEGO1 0x100516b0
// FUNCTION: BETA10 0x1003bcbc
MxResult LegoAct2::FUN_100516b0()
{
	if (m_nextBrick > 4) {
		return FAILURE;
	}

	Act2Brick& brick = m_bricks[m_nextBrick];
	brick.Create(m_nextBrick);

	MxMatrix local2world = m_ambulance->GetLocal2World();
	MxMatrix local2world2 = local2world;

	LegoPathBoundary* boundary = m_unk0x1138->GetBoundary();
	local2world[3][1] += 1.3;
	local2world2[3][1] -= 0.1;

	brick.FUN_1007a670(local2world, local2world2, boundary);
	m_nextBrick++;
	m_unk0x10c4 = 9;
	m_unk0x10d0 = 0;
	return SUCCESS;
}

// FUNCTION: LEGO1 0x100517b0
void LegoAct2::FUN_100517b0()
{
	Act2Brick& brick = m_bricks[m_nextBrick];
	brick.Create(m_nextBrick);

	MxMatrix local2world = m_ambulance->GetLocal2World();
	local2world[3][1] += 1.5;

	LegoROI* roi = brick.GetROI();
	roi->FUN_100a58f0(local2world);
	roi->VTable0x14();
	brick.PlayWhistleSound();
	m_nextBrick++;
}

// FUNCTION: LEGO1 0x10051840
void LegoAct2::PlayMusic(JukeboxScript::Script p_objectId)
{
	MxDSAction action;
	action.SetAtomId(*g_jukeboxScript);
	action.SetObjectId(p_objectId);

	BackgroundAudioManager()->PlayMusic(action, 5, MxPresenter::e_repeating);
	m_music = p_objectId;
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

// FUNCTION: LEGO1 0x10051960
// FUNCTION: BETA10 0x1003bf2c
void LegoAct2::FUN_10051960()
{
	LegoROI* roi;

	roi = FindROI("mama");
	if (roi != NULL) {
		roi->SetVisibility(FALSE);
	}

	roi = FindROI("papa");
	if (roi != NULL) {
		roi->SetVisibility(FALSE);
	}

	roi = FindROI("infoman");
	if (roi != NULL) {
		roi->SetVisibility(FALSE);
	}

	((LegoPathActor*) m_pepper->GetEntity())->SetActorState(LegoPathActor::c_initial);
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
		m_gameState->m_enabled = FALSE;
	}

	m_destLocation = LegoGameState::e_infomain;
	return TRUE;
}

// FUNCTION: LEGO1 0x10051a60
void LegoAct2::InitBricks()
{
	for (MxS32 i = 0; i < (MxS32) sizeOfArray(m_bricks); i++) {
		if (m_bricks[i].GetROI() != NULL && m_bricks[i].GetROI()->GetVisibility()) {
			m_bricks[i].PlayWhistleSound();
		}
	}
}

// FUNCTION: LEGO1 0x10051a90
void LegoAct2::UninitBricks()
{
	for (MxS32 i = 0; i < (MxS32) sizeOfArray(m_bricks); i++) {
		if (m_bricks[i].GetROI() != NULL) {
			m_bricks[i].StopWhistleSound();
		}
	}
}

// FUNCTION: LEGO1 0x10051ac0
// FUNCTION: BETA10 0x100138c0
void LegoAct2::SpawnBricks()
{
	MxFloat infobridge[] = {79.0625f, 0.5f, -19.75f};
	MxFloat palmTreeInPark[] = {67.62728f, 0.917197f, 11.49833f};
	MxFloat store[] = {-53.9328f, 2.372259f, -61.2073f};
	MxFloat postOffice[] = {-30.9856f, 0.30453f, -47.4378f};
	MxFloat h3[] = {-71.2397f, 7.319758f, -23.0f};
	MxFloat ht[] = {-59.5102f, 14.37329f, 24.70311f};
	MxFloat posta[] = {74.0625f, 1.5f, -91.125f};
	MxFloat ptree[] = {-20.4375f, 0.5f, -82.5625f};
	MxFloat jail[] = {80.46174f, 0.6f, -59.50533f};
	MxFloat hospital[] = {84.0f, 4.5f, 26.0f};

	InitBricks();

	Act2Brick* brick = &m_bricks[m_nextBrick];
	brick->Create(m_nextBrick);
	LegoROI* roi = brick->GetROI();
	MxMatrix local2world = roi->GetLocal2World();
	MxFloat* location;

	// Unused but present in BETA
	LegoEntity* entity;

	if ((MxS16) (rand() % 2) == 1) {
		m_firstBrick = 0;
		location = infobridge;
		MxTrace("infobridge\n");
	}
	else {
		m_firstBrick = 1;
		location = palmTreeInPark;
		MxTrace("palm tree in park\n");
	}

	SET3(local2world[3], location);
	roi->FUN_100a58f0(local2world);
	roi->SetVisibility(TRUE);
	roi->VTable0x14();
	entity = roi->GetEntity();
	brick->PlayWhistleSound();
	m_nextBrick++;

	brick = &m_bricks[m_nextBrick];
	brick->Create(m_nextBrick);
	roi = brick->GetROI();
	local2world = roi->GetLocal2World();

	if ((MxS16) (rand() % 2) == 1) {
		m_secondBrick = 2;
		location = store;
		MxTrace("store\n");
	}
	else {
		m_secondBrick = 3;
		location = postOffice;
		MxTrace("p.o.\n");
	}

	SET3(local2world[3], location);
	roi->FUN_100a58f0(local2world);
	roi->SetVisibility(TRUE);
	roi->VTable0x14();
	entity = roi->GetEntity();
	brick->PlayWhistleSound();
	m_nextBrick++;

	brick = &m_bricks[m_nextBrick];
	brick->Create(m_nextBrick);
	roi = brick->GetROI();
	local2world = roi->GetLocal2World();

	if ((MxS16) (rand() % 2) == 1) {
		m_thirdBrick = 4;
		location = h3;
		MxTrace("h3\n");
	}
	else {
		m_thirdBrick = 5;
		location = ht;
		MxTrace("ht\n");
	}

	SET3(local2world[3], location);
	roi->FUN_100a58f0(local2world);
	roi->SetVisibility(TRUE);
	roi->VTable0x14();
	entity = roi->GetEntity();
	brick->PlayWhistleSound();
	m_nextBrick++;

	brick = &m_bricks[m_nextBrick];
	brick->Create(m_nextBrick);
	roi = brick->GetROI();
	local2world = roi->GetLocal2World();

	if ((MxS16) (rand() % 2) == 1) {
		if ((MxS16) (rand() % 2) == 1) {
			m_fourthBrick = 6;
			location = posta;
			MxTrace("po.sta.\n");
		}
		else {
			m_fourthBrick = 7;
			location = ptree;
			MxTrace("p.tree\n");
		}
	}
	else {
		if ((MxS16) (rand() % 2) == 1) {
			m_fourthBrick = 8;
			location = jail;
			MxTrace("jail\n");
		}
		else {
			m_fourthBrick = 9;
			location = hospital;
			MxTrace("hospi\n");
		}
	}

	SET3(local2world[3], location);
	roi->FUN_100a58f0(local2world);
	roi->SetVisibility(TRUE);
	roi->VTable0x14();
	entity = roi->GetEntity();
	brick->PlayWhistleSound();
	m_nextBrick++;
}

// FUNCTION: LEGO1 0x10051f20
// FUNCTION: BETA10 0x10013f48
MxResult LegoAct2::BadEnding()
{
	for (MxS32 i = 0; i < (MxS32) sizeOfArray(m_bricks); i++) {
		m_bricks[i].Remove();
	}

	LegoPathActor* actor = m_unk0x1138;
	actor->SetActorState(LegoPathActor::c_disabled);

	m_gameState->SetUnknown0x08(104);
	m_destLocation = LegoGameState::e_infomain;
	TransitionManager()->StartTransition(MxTransitionManager::e_mosaic, 50, FALSE, FALSE);

	MxTrace("Bad End of Act2\n");
	m_unk0x10c4 = 14;
	return SUCCESS;
}

// FUNCTION: LEGO1 0x10051fa0
// FUNCTION: BETA10 0x10013fd3
void LegoAct2::FUN_10051fa0(MxS32 p_param1)
{
	MxU8 randN = rand() / (RAND_MAX / 3);
	randN++;

	switch (p_param1) {
	case 2:
		if (randN == 1) {
			FUN_10052560(Act2mainScript::c_snsx50bu_RunAnim, TRUE, FALSE, NULL, NULL, NULL);
		}
		else {
			FUN_10052560(Act2mainScript::c_snsx51bu_RunAnim, TRUE, FALSE, NULL, NULL, NULL);
		}
		break;
	case 8:
		if (randN == 1) {
			FUN_10052560(Act2mainScript::c_snsx29nu_RunAnim, TRUE, FALSE, NULL, NULL, NULL);
		}
		else {
			FUN_10052560(Act2mainScript::c_snsx30nu_RunAnim, TRUE, FALSE, NULL, NULL, NULL);
		}
		break;
	case 9:
		if (randN == 1) {
			FUN_10052560(Act2mainScript::c_snsx33na_RunAnim, TRUE, FALSE, NULL, NULL, NULL);
		}
		else {
			FUN_10052560(Act2mainScript::c_snsx34na_RunAnim, TRUE, FALSE, NULL, NULL, NULL);
		}
		break;
	case 14:
		if (randN == 1) {
			FUN_10052560(Act2mainScript::c_snsx46cl_RunAnim, TRUE, FALSE, NULL, NULL, NULL);
		}
		else {
			FUN_10052560(Act2mainScript::c_snsx48cl_RunAnim, TRUE, FALSE, NULL, NULL, NULL);
		}
		break;
	case 23:
		if (randN == 1) {
			FUN_10052560(Act2mainScript::c_snsx58va_RunAnim, TRUE, FALSE, NULL, NULL, NULL);
		}
		else {
			FUN_10052560(Act2mainScript::c_snsx60va_RunAnim, TRUE, FALSE, NULL, NULL, NULL);
		}
		break;
	case 24:
	case 25:
		FUN_10052560(Act2mainScript::c_snsx31sh_RunAnim, TRUE, FALSE, NULL, NULL, NULL);
		break;
	case 26:
		if (randN == 1) {
			FUN_10052560(Act2mainScript::c_snsx52sn_RunAnim, TRUE, FALSE, NULL, NULL, NULL);
		}
		else {
			FUN_10052560(Act2mainScript::c_snsx53sn_RunAnim, TRUE, FALSE, NULL, NULL, NULL);
		}
		break;
	case 34:
		if (randN == 1) {
			FUN_10052560(Act2mainScript::c_snsx15la_RunAnim, TRUE, FALSE, NULL, NULL, NULL);
		}
		else {
			FUN_10052560(Act2mainScript::c_snsx16la_RunAnim, TRUE, FALSE, NULL, NULL, NULL);
		}
		break;
	case 36:
		if (randN == 1) {
			FUN_10052560(Act2mainScript::c_snsx10ni_RunAnim, TRUE, FALSE, NULL, NULL, NULL);
		}
		else {
			FUN_10052560(Act2mainScript::c_snsx11ni_RunAnim, TRUE, FALSE, NULL, NULL, NULL);
		}
		break;
	case 38:
	case 42:
		if (randN == 1) {
			FUN_10052560(Act2mainScript::c_snsx03ma_RunAnim, TRUE, FALSE, NULL, NULL, NULL);
		}
		else {
			FUN_10052560(Act2mainScript::c_snsx04ma_RunAnim, TRUE, FALSE, NULL, NULL, NULL);
		}
		break;
	}
}

// FUNCTION: LEGO1 0x100521f0
// FUNCTION: BETA10 0x100142f1
void LegoAct2::FUN_100521f0(MxS32 p_param1)
{
	Act2mainScript::Script objectId = (Act2mainScript::Script) 0;
	Mx3DPointFloat vec;

	switch (p_param1) {
	case 0x02: {
		vec = Mx3DPointFloat(-9.1f, 0.0f, -16.5f);
		VariableTable()->SetVariable("ACTOR_01", "bd");
		objectId = Act2mainScript::c_tns030bd_RunAnim;
		break;
	}
	case 0x2a: {
		vec = Mx3DPointFloat(-9.67f, 0.0f, -44.3f);
		VariableTable()->SetVariable("ACTOR_01", "rd");
		objectId = Act2mainScript::c_tns030rd_RunAnim;
		break;
	}
	case 0x133: {
		vec = Mx3DPointFloat(25.75f, 0.0f, -13.0f);
		VariableTable()->SetVariable("ACTOR_01", "pg");
		objectId = Act2mainScript::c_tns030pg_RunAnim;
		break;
	}
	case 0x134: {
		vec = Mx3DPointFloat(43.63f, 0.0f, -46.33f);
		VariableTable()->SetVariable("ACTOR_01", "sy");
		objectId = Act2mainScript::c_tns030sy_RunAnim;
		break;
	}
	case 0x135: {
		vec = Mx3DPointFloat(50.0f, 0.0f, -34.6f);
		VariableTable()->SetVariable("ACTOR_01", "rd");
		objectId = Act2mainScript::c_tns030rd_RunAnim;
		break;
	}
	case 0x138: {
		vec = Mx3DPointFloat(-41.15f, 4.0f, 31.0f);
		VariableTable()->SetVariable("ACTOR_01", "sy");
		objectId = Act2mainScript::c_tns030sy_RunAnim;
		break;
	}
	}

	if (objectId != (Act2mainScript::Script) 0) {
		Mx3DPointFloat local30(vec);
		Mx3DPointFloat position(m_pepper->GetWorldPosition());
		local30 -= position;
		Mx3DPointFloat local44 = local30;
		local30.Unitize();
		FUN_10052560(objectId, TRUE, TRUE, &vec, &local30, NULL);
	}
}

// FUNCTION: LEGO1 0x10052560
// FUNCTION: BETA10 0x100145c6
MxResult LegoAct2::FUN_10052560(
	Act2mainScript::Script p_objectId,
	MxBool p_param2,
	MxBool p_param3,
	Mx3DPointFloat* p_location,
	Mx3DPointFloat* p_direction,
	Mx3DPointFloat* p_param6
)
{
	if (m_unk0x1140 == (Act2mainScript::Script) 0 || p_param3) {
		assert(strlen(m_siFile));

		if (!p_param2) {
			MxDSAction action;

			action.SetObjectId(p_objectId);
			// World index: see LegoOmni::RegisterWorlds
			action.SetAtomId(*Lego()->GetWorldAtom(LegoOmni::e_act2));

			if (p_location) {
				action.SetUp(Mx3DPointFloat(0.0f, 1.0f, 0.0f));
				action.SetLocation(*p_location);
			}

			if (p_direction) {
				action.SetDirection(*p_direction);
			}

			StartActionIfUnknown0x13c(action);
		}
		else {
			MxMatrix matrix;

			matrix.SetIdentity();
			MxBool oneVectorNotNull = FALSE;

			if (p_location) {
				matrix[3][0] = (*p_location)[0];
				matrix[3][1] = (*p_location)[1];
				matrix[3][2] = (*p_location)[2];
				oneVectorNotNull = TRUE;
			}

			if (p_direction) {
				matrix[2][0] = (*p_direction)[0];
				matrix[2][1] = (*p_direction)[1];
				matrix[2][2] = (*p_direction)[2];
				oneVectorNotNull = TRUE;
			}

			if (p_param6) {
				matrix[1][0] = (*p_param6)[0];
				matrix[1][1] = (*p_param6)[1];
				matrix[1][2] = (*p_param6)[2];
				oneVectorNotNull = TRUE;
			}

			Vector3 firstColumn(matrix[0]);
			Vector3 secondColumn(matrix[1]);
			Vector3 thirdColumn(matrix[2]);

			firstColumn.EqualsCross(&secondColumn, &thirdColumn);
			firstColumn.Unitize();

			MxMatrix* pmatrix = NULL;

			if (oneVectorNotNull) {
				pmatrix = &matrix;
			}

			MxResult result;

			if (p_objectId == Act2mainScript::c_tja009ni_RunAnim) {
				result = AnimationManager()->FUN_10060dc0(
					p_objectId,
					pmatrix,
					TRUE,
					LegoAnimationManager::e_unk0,
					NULL,
					TRUE,
					TRUE,
					TRUE,
					TRUE
				);
			}
			else {
				result = AnimationManager()->FUN_10060dc0(
					p_objectId,
					pmatrix,
					TRUE,
					LegoAnimationManager::e_unk0,
					NULL,
					TRUE,
					TRUE,
					TRUE,
					FALSE
				);
			}

			if (result == SUCCESS) {
				m_unk0x1140 = p_objectId;
			}
		}
	}

	return SUCCESS;
}

// FUNCTION: LEGO1 0x10052800
// FUNCTION: BETA10 0x10014aa8
MxResult LegoAct2::FUN_10052800()
{
	LegoPathActor* actor = m_unk0x1138;
	LegoLocomotionAnimPresenter* ap;

	PlaceActor(actor, "EDG01_27", 2, 0.5f, 0, 0.5f);

	ap = (LegoLocomotionAnimPresenter*) Find("LegoAnimPresenter", "Ambul_Anim0");
	assert(ap);
	ap->FUN_1006d680(m_unk0x1138, 0.0f);

	ap = (LegoLocomotionAnimPresenter*) Find("LegoAnimPresenter", "Ambul_Anim2");
	assert(ap);
	ap->FUN_1006d680(m_unk0x1138, 6.0f);

	ap = (LegoLocomotionAnimPresenter*) Find("LegoAnimPresenter", "Ambul_Anim3");
	assert(ap);
	ap->FUN_1006d680(m_unk0x1138, 3.0f);

	ap = (LegoLocomotionAnimPresenter*) Find("LegoAnimPresenter", "BrShoot");
	assert(ap);
	ap->FUN_1006d680(m_unk0x1138, -1.0f);

	actor->SetWorldSpeed(0.0f);
	m_unk0x1138->FUN_10018980();
	return SUCCESS;
}
