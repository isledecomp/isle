#include "jukebox.h"

#include "jukeboxstate.h"
#include "legocontrolmanager.h"
#include "legogamestate.h"
#include "legoinputmanager.h"
#include "legoomni.h"
#include "mxnotificationmanager.h"
#include "mxomni.h"
#include "mxstillpresenter.h"
#include "mxticklemanager.h"
#include "mxvideopresenter.h"

DECOMP_SIZE_ASSERT(JukeBox, 0x104)

// FUNCTION: LEGO1 0x1005d660
JukeBox::JukeBox()
{
	m_unk0x100 = 0;
	m_jukeBoxState = NULL;
	NotificationManager()->Register(this);
}

// FUNCTION: LEGO1 0x1005d6e0
MxBool JukeBox::VTable0x5c()
{
	return TRUE;
}

// FUNCTION: LEGO1 0x1005d8d0
MxResult JukeBox::Create(MxDSAction& p_dsAction)
{
	MxResult ret = LegoWorld::Create(p_dsAction);
	if (ret == SUCCESS) {
		InputManager()->SetWorld(this);
		ControlManager()->Register(this);
	}

	InputManager()->SetCamera(NULL);

	LegoGameState* gameState = GameState();
	JukeBoxState* jukeBoxState = (JukeBoxState*) gameState->GetState("JukeBoxState");
	if (!jukeBoxState) {
		jukeBoxState = (JukeBoxState*) gameState->CreateState("JukeBoxState");
		jukeBoxState->SetState(0);
	}

	m_jukeBoxState = jukeBoxState;
	GameState()->SetCurrentArea(LegoGameState::e_jukeboxw);
	GameState()->StopArea(LegoGameState::e_previousArea);
	TickleManager()->RegisterClient(this, 2000);
	return ret;
}

// FUNCTION: LEGO1 0x1005d980
MxLong JukeBox::Notify(MxParam& p_param)
{
	MxLong result = 0;
	LegoWorld::Notify(p_param);

	if (m_worldStarted) {
		switch (((MxNotificationParam&) p_param).GetNotification()) {
		case c_notificationClick:
			result = HandleClick((LegoControlManagerEvent&) p_param);
			break;
		case c_notificationTransitioned:
			GameState()->SwitchArea(m_transitionDestination);
			break;
		}
	}

	return result;
}

// FUNCTION: LEGO1 0x1005d9f0
void JukeBox::ReadyWorld()
{
	MxStillPresenter* bg;
	char* objectName;

	switch (m_jukeBoxState->GetState()) {
	case 1:
		objectName = "Right_Bitmap";
		break;
	case 2:
		objectName = "Decal_Bitmap";
		break;
	case 3:
		objectName = "Wallis_Bitmap";
		break;
	case 4:
		objectName = "Nelson_Bitmap";
		break;
	case 5:
		objectName = "Torpedos_Bitmap";
		break;
	default:
		goto done;
	}
	bg = (MxStillPresenter*) Find("MxStillPresenter", objectName);
done:
	if (bg) {
		bg->Enable(TRUE);
	}
	m_unk0x100 = 1;
}

// FUNCTION: LEGO1 0x1005da70
MxBool JukeBox::HandleClick(LegoControlManagerEvent& p_param)
{
	// TODO
	return true;
}

// FUNCTION: LEGO1 0x1005dde0
void JukeBox::Enable(MxBool p_enable)
{
	LegoWorld::Enable(p_enable);

	if (p_enable) {
		InputManager()->SetWorld(this);
		InputManager()->SetCamera(NULL);
	}
	else {
		if (InputManager()->GetWorld() == this) {
			InputManager()->ClearWorld();
		}
	}
}

// FUNCTION: LEGO1 0x1005de30
MxResult JukeBox::Tickle()
{
	if (m_worldStarted == FALSE) {
		LegoWorld::Tickle();
		return SUCCESS;
	}

	if (m_unk0x100 == 1) {
		m_unk0x100 = 0;
		FUN_10015820(FALSE, 7);
	}

	return SUCCESS;
}

// FUNCTION: LEGO1 0x1005de70
MxBool JukeBox::VTable0x64()
{
	m_transitionDestination = LegoGameState::e_infomain;
	return TRUE;
}
