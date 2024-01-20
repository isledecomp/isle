#include "elevatorbottom.h"

#include "jukebox.h"
#include "legocontrolmanager.h"
#include "legogamestate.h"
#include "legoinputmanager.h"
#include "legoomni.h"
#include "mxnotificationmanager.h"
#include "mxomni.h"

DECOMP_SIZE_ASSERT(ElevatorBottom, 0xfc)

// FUNCTION: LEGO1 0x10017e90
ElevatorBottom::ElevatorBottom()
{
	NotificationManager()->Register(this);
	this->m_unk0xf8 = 0;
}

// FUNCTION: LEGO1 0x10018060
ElevatorBottom::~ElevatorBottom()
{
	if (InputManager()->GetWorld() == this) {
		InputManager()->ClearWorld();
	}
	ControlManager()->Unregister(this);
	NotificationManager()->Unregister(this);
}

// FUNCTION: LEGO1 0x100180f0
MxResult ElevatorBottom::Create(MxDSAction& p_dsAction)
{
	MxResult result = LegoWorld::Create(p_dsAction);
	if (result == SUCCESS) {
		InputManager()->SetWorld(this);
		ControlManager()->Register(this);
	}

	SetIsWorldActive(FALSE);

	GameState()->SetUnknown424(5);
	GameState()->FUN_1003a720(0);

	return result;
}

// FUNCTION: LEGO1 0x10018150
MxLong ElevatorBottom::Notify(MxParam& p_param)
{
	MxLong ret = 0;
	LegoWorld::Notify(p_param);

	if (m_worldStarted) {
		switch (((MxNotificationParam&) p_param).GetType()) {
		case c_notificationType17:
			ret = HandleNotification17(p_param);
			break;
		case c_notificationTransitioned:
			GameState()->HandleAction(m_unk0xf8);
			break;
		}
	}

	return ret;
}

// FUNCTION: LEGO1 0x100181b0
void ElevatorBottom::VTable0x50()
{
	LegoWorld::VTable0x50();
	PlayMusic(JukeBox::e_informationCenter);
	FUN_10015820(FALSE, LegoOmni::c_disableInput | LegoOmni::c_disable3d | LegoOmni::c_clearScreen);
}

// STUB: LEGO1 0x100181d0
MxLong ElevatorBottom::HandleNotification17(MxParam& p_param)
{
	return 0;
}

// FUNCTION: LEGO1 0x100182c0
void ElevatorBottom::VTable0x68(MxBool p_add)
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

// FUNCTION: LEGO1 0x10018310
MxBool ElevatorBottom::VTable0x64()
{
	DeleteObjects(&m_atom, 500, 999);
	m_unk0xf8 = 2;
	return TRUE;
}
