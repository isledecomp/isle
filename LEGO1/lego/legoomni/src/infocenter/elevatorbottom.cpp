#include "elevatorbottom.h"

DECOMP_SIZE_ASSERT(ElevatorBottom, 0xfc)

#include "legocontrolmanager.h"
#include "legoinputmanager.h"
#include "legoomni.h"
#include "mxnotificationmanager.h"
#include "mxomni.h"

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

// STUB: LEGO1 0x10018150
MxLong ElevatorBottom::Notify(MxParam& p_param)
{
	// TODO

	return 0;
}
