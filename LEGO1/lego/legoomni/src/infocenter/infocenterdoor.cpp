#include "infocenterdoor.h"

#include "legoinputmanager.h"
#include "legoomni.h"

// STUB: LEGO1 0x10037730
InfocenterDoor::InfocenterDoor()
{
	// TODO
}

// STUB: LEGO1 0x100378f0
InfocenterDoor::~InfocenterDoor()
{
	// TODO
}

// STUB: LEGO1 0x10037980
MxResult InfocenterDoor::Create(MxDSAction& p_dsAction)
{
	return SUCCESS;
}

// STUB: LEGO1 0x100379e0
MxLong InfocenterDoor::Notify(MxParam& p_param)
{
	// TODO
	return LegoWorld::Notify(p_param);
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

// FUNCTION: LEGO1 0x10037a70
void InfocenterDoor::VTable0x50()
{
	LegoWorld::VTable0x50();
	PlayMusic(11);
	FUN_10015820(FALSE, LegoOmni::c_disableInput | LegoOmni::c_disable3d | LegoOmni::c_clearScreen);
}

// STUB: LEGO1 0x10037cd0
MxBool InfocenterDoor::VTable0x64()
{
	return TRUE;
}
