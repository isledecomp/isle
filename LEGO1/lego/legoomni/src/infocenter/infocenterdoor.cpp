#include "infocenterdoor.h"

#include "jukebox.h"
#include "legocontrolmanager.h"
#include "legogamestate.h"
#include "legoinputmanager.h"
#include "legoomni.h"
#include "mxnotificationmanager.h"

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

// STUB: LEGO1 0x100379e0
MxLong InfocenterDoor::Notify(MxParam& p_param)
{
	// TODO
	return LegoWorld::Notify(p_param);
}

// FUNCTION: LEGO1 0x10037a70
void InfocenterDoor::VTable0x50()
{
	LegoWorld::VTable0x50();
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
