#include "legopathstruct.h"

#include "isle.h"
#include "jukebox.h"
#include "jukebox_actions.h"
#include "legoanimpresenter.h"
#include "legopathactor.h"
#include "legoutils.h"
#include "misc.h"
#include "mxbackgroundaudiomanager.h"
#include "mxmisc.h"
#include "mxnotificationmanager.h"
#include "scripts.h"

DECOMP_SIZE_ASSERT(LegoPathStructBase, 0x0c)
DECOMP_SIZE_ASSERT(LegoPathStruct, 0x14)

// Flags used in isle.cpp
extern MxU32 g_isleFlags;

// GLOBAL: LEGO1 0x100f119c
// GLOBAL: BETA10 0x100f119c
MxBool g_unk0x100f119c = FALSE;

// FUNCTION: LEGO1 0x1001b700
void LegoPathStruct::HandleTrigger(LegoPathActor* p_actor, MxBool p_direction, MxU32 p_data)
{
	if (!HandleTrigger(p_actor, p_direction, p_data, FALSE) && g_unk0x100f119c) {
		HandleTrigger(p_actor, p_direction, p_data, TRUE);
	}
}

// FUNCTION: LEGO1 0x1001b740
// FUNCTION: BETA10 0x100c26c5
MxBool LegoPathStruct::HandleTrigger(LegoPathActor* p_actor, MxBool p_direction, MxU32 p_data, MxBool p_bool)
{
	MxBool triggered = FALSE;
	MxBool bool2 = p_bool ? !p_direction : p_direction;

	MxU32 flags = bool2 ? c_bit5 : c_bit6;
	flags |= p_actor->GetCameraFlag() ? c_bit1 : (c_bit2 | c_bit3 | c_bit4);

	if ((m_flags & flags & (c_bit5 | c_bit6 | c_bit7)) && (m_flags & flags & (c_bit1 | c_bit2 | c_bit3 | c_bit4))) {
		triggered = TRUE;

		switch (m_name[2]) {
		case c_camAnim:
			if (g_isleFlags & Isle::c_playCamAnims) {
				PlayCamAnim(p_actor, bool2, p_data, TRUE);
			}
			break;
		case c_d: {
			p_actor->VTable0x58(p_data);

			LegoPathStructNotificationParam param(c_notificationPathStruct, p_actor, m_name[2], p_data);
			p_actor->Notify(param);

			LegoWorld* world = CurrentWorld();
			if (world != NULL) {
				NotificationManager()->Send(world, param);
			}
			break;
		}
		case c_e:
			FUN_1001bc40(m_name, p_data, !(p_bool == FALSE));
			break;
		case c_g:
			break;
		case c_h: {
			LegoHideAnimPresenter* presenter = m_world->GetHideAnimPresenter();
			if (presenter != NULL) {
				presenter->FUN_1006db40(p_data * 100);
			}
			break;
		}
		case c_music:
			if (g_isleFlags & Isle::c_playMusic) {
				PlayMusic(p_direction, p_data);
			}
			break;
		case c_s: {
			LegoWorld* world = CurrentWorld();
			if (world != NULL) {
				LegoPathStructNotificationParam param(c_notificationPathStruct, p_actor, m_name[2], p_data);

				if (world->Notify(param) != 0) {
					break;
				}
			}

			FUN_1001bc40(m_name, p_data, p_bool == FALSE);
			break;
		}
		case c_w: {
			LegoWorld* world = CurrentWorld();
			if (world != NULL) {
				LegoPathStructNotificationParam param(c_notificationPathStruct, p_actor, m_name[2], p_data);
				NotificationManager()->Send(world, param);
			}
			break;
		}
		}
	}

	return triggered;
}

// FUNCTION: LEGO1 0x1001bc40
// FUNCTION: BETA10 0x100c2a6c
void LegoPathStruct::FUN_1001bc40(const char* p_name, MxU32 p_data, MxBool p_bool)
{
	MxDSAction action;
	action.SetObjectId(p_data);
	action.SetAtomId(m_atomId);

	if (p_bool) {
		action.SetUnknown24(-1);
		Start(&action);
	}
	else {
		action.SetUnknown24(-2);
		DeleteObject(action);
	}
}

// FUNCTION: LEGO1 0x1001bd10
// FUNCTION: BETA10 0x100c2b4a
void LegoPathStruct::PlayMusic(MxBool p_direction, MxU32 p_data)
{
	JukeBoxState* state = (JukeBoxState*) GameState()->GetState("JukeBoxState");
	if (state != NULL && state->m_active) {
		return;
	}

	JukeboxScript::Script music[] = {
		JukeboxScript::c_ResidentalArea_Music,
		JukeboxScript::c_BeachBlvd_Music,
		JukeboxScript::c_Cave_Music,
		JukeboxScript::c_CentralRoads_Music,
		JukeboxScript::c_Jail_Music,
		JukeboxScript::c_Hospital_Music,
		JukeboxScript::c_InformationCenter_Music,
		JukeboxScript::c_PoliceStation_Music,
		JukeboxScript::c_Park_Music,
		JukeboxScript::c_CentralNorthRoad_Music,
		JukeboxScript::c_GarageArea_Music,
		JukeboxScript::c_RaceTrackRoad_Music,
		JukeboxScript::c_Beach_Music,
		JukeboxScript::c_Quiet_Audio
	};

	MxS16 triggersReff[24][2] = {{11, 10}, {6, 10}, {3, 1},  {4, 1},   {1, 4},   {1, 4},   {13, 2}, {13, 2},
								 {13, 2},  {4, 10}, {11, 9}, {9, 7},   {8, 7},   {8, 5},   {5, 2},  {2, 4},
								 {4, 2},   {4, 5},  {11, 4}, {12, 10}, {10, 12}, {10, 12}, {14, 2}, {14, 2}};

	MxDSAction action;
	action.SetAtomId(*g_jukeboxScript);
	action.SetUnknown24(-1);

	if (p_data <= sizeOfArray(triggersReff)) {
		action.SetObjectId(music[triggersReff[p_data - 1][p_direction == FALSE] - 1]);
	}

	if (action.GetObjectId() != -1) {
		BackgroundAudioManager()->PlayMusic(action, 5, MxPresenter::e_repeating);
	}
}
