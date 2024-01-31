#include "infocenterdoor.h"

#include "infocenterstate.h"
#include "jukebox.h"
#include "legocontrolmanager.h"
#include "legogamestate.h"
#include "legoinputmanager.h"
#include "legoomni.h"
#include "mxactionnotificationparam.h"
#include "mxbackgroundaudiomanager.h"
#include "mxnotificationmanager.h"
#include "mxtransitionmanager.h"

DECOMP_SIZE_ASSERT(InfocenterDoor, 0xfc)

// FUNCTION: LEGO1 0x10037730
InfocenterDoor::InfocenterDoor()
{
	m_unk0xf8 = 0;

	NotificationManager()->Register(this);
}

// FUNCTION: LEGO1 0x100378f0
InfocenterDoor::~InfocenterDoor()
{
	if (InputManager()->GetWorld() == this) {
		InputManager()->ClearWorld();
	}

	ControlManager()->Unregister(this);
	NotificationManager()->Unregister(this);
}

// FUNCTION: LEGO1 0x10037980
MxResult InfocenterDoor::Create(MxDSAction& p_dsAction)
{
	MxResult result = LegoWorld::Create(p_dsAction);
	if (result == SUCCESS) {
		InputManager()->SetWorld(this);
		ControlManager()->Register(this);
	}

	SetIsWorldActive(FALSE);

	GameState()->SetUnknown424(3);
	GameState()->FUN_1003a720(0);

	return result;
}

// FUNCTION: LEGO1 0x100379e0
MxLong InfocenterDoor::Notify(MxParam& p_param)
{
	MxLong result = 0;
	LegoWorld::Notify(p_param);

	if (m_worldStarted) {
		switch (((MxNotificationParam&) p_param).GetType()) {
		case c_notificationEndAction:
			if (((MxEndActionNotificationParam&) p_param).GetAction()->GetAtomId() == m_atom) {
				BackgroundAudioManager()->RaiseVolume();
				result = 1;
			}
			break;
		case c_notificationType17:
			result = HandleClick((LegoControlManagerEvent&) p_param);
			break;
		case c_notificationTransitioned:
			GameState()->HandleAction(m_unk0xf8);
			result = 1;
			break;
		}
	}

	return result;
}

// FUNCTION: LEGO1 0x10037a90
MxLong InfocenterDoor::HandleClick(LegoControlManagerEvent& p_param)
{
	if (p_param.GetUnknown0x28() == 1) {
		DeleteObjects(&m_atom, 500, 510);

		switch (p_param.GetClickedObjectId()) {
		case 1:
			m_unk0xf8 = 13;
			break;
		case 2:
			m_unk0xf8 = 5;
			break;
		case 3:
			m_unk0xf8 = 2;
			break;
		case 4:
			if (GameState()->GetUnknownC()) {
				InfocenterState* state = (InfocenterState*) GameState()->GetState("InfocenterState");
				if (state->GetInfocenterBufferElement(0) != NULL) {
					m_unk0xf8 = 4;
				}
				else {
					MxDSAction action;
					action.SetObjectId(503);
					action.SetAtomId(*g_infodoorScript);
					BackgroundAudioManager()->LowerVolume();
					Start(&action);
					return 1;
				}
			}
			else {
				MxDSAction action;
				action.SetObjectId(500);
				action.SetAtomId(*g_infodoorScript);
				BackgroundAudioManager()->LowerVolume();
				Start(&action);
				return 1;
			}
		default:
			return 0;
		}
		TransitionManager()->StartTransition(MxTransitionManager::e_pixelation, 50, FALSE, FALSE);
	}

	return 1;
}

// FUNCTION: LEGO1 0x10037a70
void InfocenterDoor::ReadyWorld()
{
	LegoWorld::ReadyWorld();
	PlayMusic(JukeBox::e_informationCenter);
	FUN_10015820(FALSE, LegoOmni::c_disableInput | LegoOmni::c_disable3d | LegoOmni::c_clearScreen);
}

// FUNCTION: LEGO1 0x10037c80
void InfocenterDoor::VTable0x68(MxBool p_add)
{
	LegoWorld::VTable0x68(p_add);

	if (p_add) {
		InputManager()->SetWorld(this);
		SetIsWorldActive(FALSE);
	}
	else {
		if (InputManager()->GetWorld() == this) {
			InputManager()->ClearWorld();
		}
	}
}

// FUNCTION: LEGO1 0x10037cd0
MxBool InfocenterDoor::VTable0x64()
{
	DeleteObjects(&m_atom, 500, 510);
	m_unk0xf8 = 2;
	return TRUE;
}
