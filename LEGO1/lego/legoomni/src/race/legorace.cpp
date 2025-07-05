#include "legorace.h"

#include "isle.h"
#include "legocontrolmanager.h"
#include "legonavcontroller.h"
#include "misc.h"
#include "mxmisc.h"
#include "mxnotificationmanager.h"

DECOMP_SIZE_ASSERT(LegoRace, 0x144)
DECOMP_SIZE_ASSERT(RaceState::Entry, 0x06)
DECOMP_SIZE_ASSERT(RaceState, 0x2c)

// Defined in legopathstruct.cpp
extern MxBool g_unk0x100f119c;

// FUNCTION: LEGO1 0x10015aa0
LegoRace::LegoRace()
{
	m_unk0xf8 = 0;
	m_unk0xfc = 0;
	m_unk0x100 = 0;
	m_unk0x104 = 0;
	m_unk0x108 = 0;
	m_unk0x10c = 0;
	m_raceState = NULL;
	m_maps[0] = NULL;
	m_maps[1] = NULL;
	m_maps[2] = NULL;
	m_unk0x128 = 0;
	m_unk0x12c = 0;
	m_pathActor = 0;
	m_act1State = NULL;
	m_destLocation = LegoGameState::e_undefined;
	NotificationManager()->Register(this);
}

// FUNCTION: LEGO1 0x10015ce0
// FUNCTION: BETA10 0x100c7a71
MxResult LegoRace::Create(MxDSAction& p_dsAction)
{
	MxResult result = LegoWorld::Create(p_dsAction);

	if (result == SUCCESS) {
		m_act1State = (Act1State*) GameState()->GetState("Act1State");
		ControlManager()->Register(this);
		m_pathActor = UserActor();
		m_pathActor->SetWorldSpeed(0);
		SetUserActor(NULL);
	}

	return result;
}

// FUNCTION: LEGO1 0x10015d40
LegoRace::~LegoRace()
{
	g_unk0x100f119c = FALSE;
	if (m_pathActor) {
		SetUserActor(m_pathActor);
		NavController()->ResetMaxLinearVel(m_pathActor->GetMaxLinearVel());
		m_pathActor = NULL;
	}

	ControlManager()->Unregister(this);
	NotificationManager()->Unregister(this);
}

// FUNCTION: LEGO1 0x10015e00
// FUNCTION: BETA10 0x100c7b3d
MxLong LegoRace::Notify(MxParam& p_param)
{
	LegoWorld::Notify(p_param);
	MxNotificationParam& param = (MxNotificationParam&) p_param;

	MxLong result = 0;
	if (m_worldStarted) {
		switch (param.GetNotification()) {
		case c_notificationType0:
			HandleType0Notification((MxNotificationParam&) p_param);
			break;
		case c_notificationEndAction:
			result = HandleEndAction((MxEndActionNotificationParam&) p_param);
			break;
		case c_notificationControl:
			result = HandleControl((LegoControlManagerNotificationParam&) p_param);
			break;
		case c_notificationPathStruct:
			result = HandlePathStruct((LegoPathStructNotificationParam&) p_param);
			break;
		case c_notificationTransitioned:
			GameState()->SwitchArea(m_destLocation);
			break;
		}
	}

	return result;
}

// FUNCTION: LEGO1 0x10015ed0
// FUNCTION: BETA10 0x100c7c3f
void LegoRace::Enable(MxBool p_enable)
{
	if (NoDisabledObjects() != p_enable && !p_enable) {
		Remove(UserActor());

		MxU8 oldActorId = GameState()->GetActorId();
		GameState()->RemoveActor();
		GameState()->SetActorId(oldActorId);
	}

	LegoWorld::Enable(p_enable);
}

// FUNCTION: LEGO1 0x10015f30
RaceState::RaceState()
{
	m_state[0].m_id = 1;
	m_state[0].m_unk0x02 = 0;
	m_state[0].m_score = 0;
	m_state[1].m_id = 2;
	m_state[1].m_unk0x02 = 0;
	m_state[1].m_score = 0;
	m_state[2].m_id = 3;
	m_state[2].m_unk0x02 = 0;
	m_state[2].m_score = 0;
	m_state[3].m_id = 4;
	m_state[3].m_unk0x02 = 0;
	m_state[3].m_score = 0;
	m_state[4].m_id = 5;
	m_state[4].m_unk0x02 = 0;
	m_state[4].m_score = 0;
	m_unk0x28 = 0;
}

// FUNCTION: LEGO1 0x10016140
// FUNCTION: BETA10 0x100c7d9f
MxResult RaceState::Serialize(LegoStorage* p_storage)
{
	LegoState::Serialize(p_storage);

	for (MxS16 i = 0; i < 5; i++) {
		m_state[i].Serialize(p_storage);
	}

	return SUCCESS;
}

// FUNCTION: LEGO1 0x10016280
// FUNCTION: BETA10 0x100c7dfd
RaceState::Entry* RaceState::GetState(MxU8 p_id)
{
	for (MxS16 i = 0;; i++) {
		if (i >= 5) {
			return NULL;
		}

		if (m_state[i].m_id == p_id) {
			return m_state + i;
		}
	}
}
