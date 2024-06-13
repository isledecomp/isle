#include "ambulance.h"

#include "decomp.h"
#include "isle.h"
#include "isle_actions.h"
#include "jukebox_actions.h"
#include "legoanimationmanager.h"
#include "legocontrolmanager.h"
#include "legogamestate.h"
#include "legonavcontroller.h"
#include "legoutils.h"
#include "legovariables.h"
#include "legoworld.h"
#include "misc.h"
#include "mxactionnotificationparam.h"
#include "mxbackgroundaudiomanager.h"
#include "mxmisc.h"
#include "mxticklemanager.h"
#include "mxtimer.h"
#include "mxtransitionmanager.h"
#include "mxvariabletable.h"
#include "scripts.h"

DECOMP_SIZE_ASSERT(Ambulance, 0x184)
DECOMP_SIZE_ASSERT(AmbulanceMissionState, 0x24)

// FUNCTION: LEGO1 0x10035ee0
// FUNCTION: BETA10 0x10022820
Ambulance::Ambulance()
{
	m_maxLinearVel = 40.0;
	m_state = NULL;
	m_unk0x168 = 0;
	m_unk0x16a = -1;
	m_unk0x16c = 0;
	m_unk0x16e = 0;
	m_unk0x170 = 0;
	m_lastAction = IsleScript::c_noneIsle;
	m_unk0x172 = 0;
	m_lastAnimation = IsleScript::c_noneIsle;
	m_fuel = 1.0;
}

// FUNCTION: LEGO1 0x10035f90
void Ambulance::Destroy(MxBool p_fromDestructor)
{
}

// FUNCTION: LEGO1 0x10036150
// FUNCTION: BETA10 0x100228fe
Ambulance::~Ambulance()
{
	ControlManager()->Unregister(this);
	TickleManager()->UnregisterClient(this);
}

// FUNCTION: LEGO1 0x100361d0
// FUNCTION: BETA10 0x10022993
MxResult Ambulance::Create(MxDSAction& p_dsAction)
{
	MxResult result = IslePathActor::Create(p_dsAction);

	if (result == SUCCESS) {
		m_world = CurrentWorld();

		if (m_world) {
			m_world->Add(this);
		}

		m_state = (AmbulanceMissionState*) GameState()->GetState("AmbulanceMissionState");
		if (!m_state) {
			m_state = new AmbulanceMissionState();
			m_state->m_unk0x08 = 0;
			GameState()->RegisterState(m_state);
		}
	}

	VariableTable()->SetVariable(g_varAMBULFUEL, "1.0");
	m_fuel = 1.0;
	m_time = Timer()->GetTime();
	return result;
}

// FUNCTION: LEGO1 0x10036300
void Ambulance::VTable0x70(float p_time)
{
	IslePathActor::VTable0x70(p_time);

	if (UserActor() == this) {
		char buf[200];
		float speed = abs(m_worldSpeed);
		float maxLinearVel = NavController()->GetMaxLinearVel();

		sprintf(buf, "%g", speed / maxLinearVel);
		VariableTable()->SetVariable(g_varAMBULSPEED, buf);

		m_fuel += (p_time - m_time) * -3.333333333e-06f;
		if (m_fuel < 0) {
			m_fuel = 0;
		}

		m_time = p_time;

		sprintf(buf, "%g", m_fuel);
		VariableTable()->SetVariable(g_varAMBULFUEL, buf);
	}
}

// FUNCTION: LEGO1 0x100363f0
// FUNCTION: BETA10 0x10022b2a
void Ambulance::CreateState()
{
	LegoGameState* gameState = GameState();
	AmbulanceMissionState* state = (AmbulanceMissionState*) gameState->GetState("AmbulanceMissionState");

	if (state == NULL) {
		state = (AmbulanceMissionState*) gameState->CreateState("AmbulanceMissionState");
	}

	m_state = state;
}

// FUNCTION: LEGO1 0x10036420
// FUNCTION: BETA10 0x10022b84
MxLong Ambulance::Notify(MxParam& p_param)
{
	MxLong result = 0;

	switch (((MxNotificationParam&) p_param).GetType()) {
	case c_notificationType0:
		result = HandleNotification0();
		break;
	case c_notificationEndAction:
		result = HandleEndAction((MxEndActionNotificationParam&) p_param);
		break;
	case c_notificationButtonDown:
		result = HandleButtonDown((LegoControlManagerEvent&) p_param);
		break;
	case c_notificationClick:
		result = HandleClick();
		break;
	case c_notificationControl:
		result = HandleControl((LegoControlManagerEvent&) p_param);
		break;
	case c_notificationType19:
		result = HandleNotification19((MxType19NotificationParam&) p_param);
		break;
	}

	return result;
}

// FUNCTION: LEGO1 0x100364d0
// FUNCTION: BETA10 0x10022cc2
MxLong Ambulance::HandleEndAction(MxEndActionNotificationParam& p_param)
{
	if (p_param.GetAction() != NULL) {
		IsleScript::Script objectId = (IsleScript::Script) p_param.GetAction()->GetObjectId();

		if (m_lastAnimation == objectId) {
			m_lastAnimation = IsleScript::c_noneIsle;
		}

		if (m_lastAction == objectId) {
			if (m_lastAnimation == IsleScript::c_noneIsle) {
				BackgroundAudioManager()->RaiseVolume();
			}

			m_lastAction = IsleScript::c_noneIsle;
		}
		else if (objectId == IsleScript::c_hho027en_RunAnim) {
			m_state->m_unk0x08 = 1;
			CurrentWorld()->PlaceActor(UserActor());
			HandleClick();
			m_unk0x172 = 0;
			TickleManager()->RegisterClient(this, 40000);
		}
		else if (objectId == IsleScript::c_hpz047pe_RunAnim || objectId == IsleScript::c_hpz048pe_RunAnim || objectId == IsleScript::c_hpz049bd_RunAnim || objectId == IsleScript::c_hpz053pa_RunAnim) {
			if (m_unk0x170 == 3) {
				PlayAnimation(IsleScript::c_hpz055pa_RunAnim);
				m_unk0x170 = 0;
			}
			else {
				PlayAnimation(IsleScript::c_hpz053pa_RunAnim);
			}
		}
		else if (objectId == IsleScript::c_hpz050bd_RunAnim || objectId == IsleScript::c_hpz052ma_RunAnim) {
			if (m_unk0x170 == 3) {
				PlayAnimation(IsleScript::c_hpz057ma_RunAnim);
				m_unk0x170 = 0;
			}
			else {
				PlayAnimation(IsleScript::c_hpz052ma_RunAnim);
			}
		}
		else if (objectId == IsleScript::c_hpz055pa_RunAnim || objectId == IsleScript::c_hpz057ma_RunAnim) {
			CurrentWorld()->PlaceActor(UserActor());
			HandleClick();
			SpawnPlayer(LegoGameState::e_pizzeriaExterior, TRUE, 0);
			m_unk0x172 = 0;
			TickleManager()->RegisterClient(this, 40000);

			if (m_unk0x16c != 0) {
				StopActions();
			}
		}
		else if (objectId == IsleScript::c_hps116bd_RunAnim || objectId == IsleScript::c_hps118re_RunAnim) {
			if (objectId == IsleScript::c_hps116bd_RunAnim && m_unk0x170 != 3) {
				PlayAction(IsleScript::c_Avo923In_PlayWav);
			}

			if (m_unk0x170 == 3) {
				PlayAnimation(IsleScript::c_hps117bd_RunAnim);
				m_unk0x170 = 0;
			}
			else {
				PlayAnimation(IsleScript::c_hps118re_RunAnim);
			}
		}
		else if (objectId == IsleScript::c_hps117bd_RunAnim) {
			CurrentWorld()->PlaceActor(UserActor());
			HandleClick();
			SpawnPlayer(LegoGameState::e_unk33, TRUE, 0);
			m_unk0x172 = 0;
			TickleManager()->RegisterClient(this, 40000);

			if (m_unk0x16e != 0) {
				StopActions();
			}
		}
		else if (objectId == IsleScript::c_hho142cl_RunAnim || objectId == IsleScript::c_hho143cl_RunAnim || objectId == IsleScript::c_hho144cl_RunAnim) {
			FUN_10037250();
		}
	}

	return 1;
}

// STUB: LEGO1 0x100367c0
MxLong Ambulance::HandleButtonDown(LegoControlManagerEvent& p_param)
{
	// TODO
	return 0;
}

// STUB: LEGO1 0x10036860
MxLong Ambulance::HandleNotification19(MxType19NotificationParam& p_param)
{
	// TODO
	return 0;
}

// FUNCTION: LEGO1 0x10036ce0
// FUNCTION: BETA10 0x10023506
MxLong Ambulance::HandleClick()
{
	if (((Act1State*) GameState()->GetState("Act1State"))->m_unk0x018 != 10) {
		return 1;
	}

	if (m_state->m_unk0x08 == 2) {
		return 1;
	}

	FUN_10015820(TRUE, 0);
	((Isle*) CurrentWorld())->SetDestLocation(LegoGameState::e_ambulance);
	TransitionManager()->StartTransition(MxTransitionManager::e_mosaic, 50, FALSE, FALSE);

	if (UserActor()->GetActorId() != GameState()->GetActorId()) {
		((IslePathActor*) UserActor())->Exit();
	}

	m_time = Timer()->GetTime();
	m_unk0x16a = UserActor()->GetActorId();

	Enter();
	InvokeAction(Extra::e_start, *g_isleScript, IsleScript::c_AmbulanceDashboard, NULL);
	ControlManager()->Register(this);

	if (m_state->m_unk0x08 == 1) {
		SpawnPlayer(LegoGameState::e_unk31, TRUE, 0);
		m_state->m_unk0x0c = Timer()->GetTime();
		InvokeAction(Extra::e_start, *g_isleScript, IsleScript::c_pns018rd_RunAnim, NULL);
	}

	return 1;
}

// FUNCTION: LEGO1 0x10036e60
// FUNCTION: BETA10 0x100236bb
void Ambulance::FUN_10036e60()
{
	m_state->m_unk0x08 = 2;
	PlayAnimation(IsleScript::c_hho027en_RunAnim);
	m_lastAction = IsleScript::c_noneIsle;
	m_lastAnimation = IsleScript::c_noneIsle;
}

// STUB: LEGO1 0x10036e90
void Ambulance::Exit()
{
	// TODO
}

// STUB: LEGO1 0x10036f90
MxLong Ambulance::HandleControl(LegoControlManagerEvent& p_param)
{
	// TODO
	return 0;
}

// FUNCTION: LEGO1 0x10037060
void Ambulance::ActivateSceneActions()
{
	PlayMusic(JukeboxScript::c_Hospital_Music);

	if (m_state->m_unk0x08 == 1) {
		m_state->m_unk0x08 = 0;
		PlayAction(IsleScript::c_ham033cl_PlayWav);
	}
	else if (m_unk0x16c != 0 && m_unk0x16e != 0) {
		IsleScript::Script objectId;

		switch (rand() % 2) {
		case 0:
			objectId = IsleScript::c_ham076cl_PlayWav;
			break;
		case 1:
			objectId = IsleScript::c_ham088cl_PlayWav;
			break;
		}

		if (m_lastAction != IsleScript::c_noneIsle) {
			InvokeAction(Extra::e_stop, *g_isleScript, m_lastAction, NULL);
		}

		PlayAction(objectId);
	}
	else {
		IsleScript::Script objectId;

		switch (rand() % 2) {
		case 0:
			objectId = IsleScript::c_ham075cl_PlayWav;
			break;
		case 1:
			objectId = IsleScript::c_ham113cl_PlayWav;
			break;
		}

		if (m_lastAction != IsleScript::c_noneIsle) {
			InvokeAction(Extra::e_stop, *g_isleScript, m_lastAction, NULL);
		}

		PlayAction(objectId);
	}
}

// FUNCTION: LEGO1 0x10037160
// FUNCTION: BETA10 0x100237df
MxResult Ambulance::Tickle()
{
	if (m_unk0x172 == 0) {
		m_unk0x172 = 1;
	}
	else if (m_lastAction == IsleScript::c_noneIsle) {
		IsleScript::Script objectId;

		switch ((rand() % 12) + 1) {
		case 1:
			objectId = IsleScript::c_ham034ra_PlayWav;
			break;
		case 2:
			objectId = IsleScript::c_ham035ra_PlayWav;
			break;
		case 3:
			objectId = IsleScript::c_ham036ra_PlayWav;
			break;
		case 4:
			objectId = IsleScript::c_hpz037ma_PlayWav;
			break;
		case 5:
			objectId = IsleScript::c_sns078pa_PlayWav;
			break;
		case 6:
			objectId = IsleScript::c_ham039ra_PlayWav;
			break;
		case 7:
			objectId = IsleScript::c_ham040cl_PlayWav;
			break;
		case 8:
			objectId = IsleScript::c_ham041cl_PlayWav;
			break;
		case 9:
			objectId = IsleScript::c_ham042cl_PlayWav;
			break;
		case 10:
			objectId = IsleScript::c_ham043cl_PlayWav;
			break;
		case 11:
			objectId = IsleScript::c_ham044cl_PlayWav;
			break;
		case 12:
			objectId = IsleScript::c_ham045cl_PlayWav;
			break;
		}

		PlayAction(objectId);
	}

	return SUCCESS;
}

// FUNCTION: LEGO1 0x10037240
void Ambulance::StopActions()
{
	StopAction(IsleScript::c_pns018rd_RunAnim);
}

// STUB: LEGO1 0x10037250
void Ambulance::FUN_10037250()
{
	// TODO
}

// FUNCTION: LEGO1 0x100372e0
// FUNCTION: BETA10 0x100241a0
void Ambulance::PlayAnimation(IsleScript::Script p_objectId)
{
	AnimationManager()->FUN_10060dc0(p_objectId, NULL, TRUE, FALSE, NULL, FALSE, FALSE, FALSE, TRUE);
	m_lastAnimation = p_objectId;
}

// FUNCTION: LEGO1 0x10037340
void Ambulance::StopAction(IsleScript::Script p_objectId)
{
	if (p_objectId != -1) {
		InvokeAction(Extra::e_stop, *g_isleScript, p_objectId, NULL);
	}
}

// FUNCTION: LEGO1 0x10037360
void Ambulance::PlayAction(IsleScript::Script p_objectId)
{
	if (p_objectId != -1) {
		InvokeAction(Extra::e_start, *g_isleScript, p_objectId, NULL);
	}

	m_lastAction = p_objectId;
	BackgroundAudioManager()->LowerVolume();
}

// FUNCTION: LEGO1 0x100373a0
AmbulanceMissionState::AmbulanceMissionState()
{
	m_unk0x10 = 0;
	m_unk0x12 = 0;
	m_unk0x14 = 0;
	m_unk0x08 = 0;
	m_unk0x16 = 0;
	m_unk0x0c = 0;
	m_unk0x18 = 0;
	m_score1 = 0;
	m_score2 = 0;
	m_score3 = 0;
	m_score4 = 0;
	m_score5 = 0;
}

// STUB: LEGO1 0x10037440
MxResult AmbulanceMissionState::Serialize(LegoFile* p_legoFile)
{
	// TODO
	return LegoState::Serialize(p_legoFile);
}
