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
LegoChar* g_unk0x100f4410[] = {"bd", "pg", "rd", "sy", "ro", "cl"};

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
LegoChar* g_unk0x100f4458[] = {"papa", "nick", "laura", "cl", "pg", "rd", "sy"};

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
	m_unk0x10c0 = 0;
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
		((LegoPathActor*) m_pepper->GetEntity())->SetState(LegoPathActor::c_bit3);

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

				Mx3DPointFloat entityPosition(entity->GetROI()->GetWorldPosition());
				Mx3DPointFloat unk0x10d8(m_pepper->GetWorldPosition());
				Mx3DPointFloat locala4(unk0x10d8);

				((Vector3&) entityPosition).Sub(unk0x10d8);

				MxMatrix local2world(m_pepper->GetLocal2World());
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

				Mx3DPointFloat direction(local2world[2]);
				Mx3DPointFloat location(local2world[1]);
				FUN_10052560(Act2mainScript::c_tns051in_RunAnim, TRUE, TRUE, &location, &direction, NULL);

				m_unk0x10c4 = 14;
				m_unk0x10d0 = 0;
				((LegoPathActor*) m_pepper->GetEntity())->SetState(LegoPathActor::c_bit3);
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
			m_bricks[m_unk0x10c0 - 1].Mute(TRUE);
			m_unk0x10c4 = 12;
			m_unk0x10d0 = 0;

			FUN_10052560(Act2mainScript::c_tra045la_RunAnim, TRUE, TRUE, NULL, NULL, NULL);
			((LegoPathActor*) m_pepper->GetEntity())->SetState(LegoPathActor::c_bit3);
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

			m_bricks[m_unk0x10c0 - 1].Mute(FALSE);
			m_unk0x10c4 = 13;
			FUN_10051ac0();
			PlayMusic(JukeboxScript::c_BrickHunt);
			((LegoPathActor*) m_pepper->GetEntity())->SetState(0);
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

		if (m_unk0x10c4 == 10 && m_unk0x10c0 == 6 && m_bricks[5].GetROI() != NULL) {
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

// STUB: LEGO1 0x10051460
// STUB: BETA10 0x1003bb72
MxLong LegoAct2::HandlePathStruct(LegoPathStructNotificationParam& p_param)
{
	// TODO
	return 0;
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

	((LegoPathActor*) m_pepper->GetEntity())->SetState(0);
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

// STUB: LEGO1 0x10051ac0
// STUB: BETA10 0x100138c0
void LegoAct2::FUN_10051ac0()
{
	// TODO
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
			action.SetAtomId(*Lego()->GetWorldAtom(15));

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
				result =
					AnimationManager()->FUN_10060dc0(p_objectId, pmatrix, TRUE, FALSE, NULL, TRUE, TRUE, TRUE, TRUE);
			}
			else {
				result =
					AnimationManager()->FUN_10060dc0(p_objectId, pmatrix, TRUE, FALSE, NULL, TRUE, TRUE, TRUE, FALSE);
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
