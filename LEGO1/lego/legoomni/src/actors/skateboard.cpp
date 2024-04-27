#include "skateboard.h"

#include "decomp.h"
#include "misc.h"
#include "mxmisc.h"
#include "mxnotificationmanager.h"

DECOMP_SIZE_ASSERT(SkateBoard, 0x168)

// FUNCTION: LEGO1 0x1000fd40
SkateBoard::SkateBoard()
{
	this->m_unk0x160 = 0;
	this->m_unk0x13c = 15.0;
	this->m_unk0x150 = 3.5;
	this->m_unk0x148 = 1;

	NotificationManager()->Register(this);
}

// FUNCTION: LEGO1 0x1000ff80
SkateBoard::~SkateBoard()
{
	ControlManager()->Unregister(this);
	NotificationManager()->Unregister(this);
}

// STUB: LEGO1 0x10010000
MxResult SkateBoard::Create(MxDSAction& p_dsAction)
{
	// TODO
	return SUCCESS;
}

// STUB: LEGO1 0x10010050
void SkateBoard::VTable0xe4()
{
	// TODO
	// Add a stub so the call in VTable0xd4 is not optimized away
	ControlManager()->Unregister(this);
}

// STUB: LEGO1 0x100100e0
MxU32 SkateBoard::VTable0xcc()
{
	// TODO
	return 0;
}

// FUNCTION: LEGO1 0x10010230
MxU32 SkateBoard::VTable0xd4(LegoControlManagerEvent& p_param)
{
	MxU32 result = 0;
	if (p_param.m_unk0x28 == 1 && p_param.m_clickedObjectId == 0xc3) {
		VTable0xe4();
		// current area (?) Ghidra says "currentActionId"
		GameState()->m_currentArea = LegoGameState::Area::e_unk66;
		result = 1;
	}
	return result;
}

// STUB: LEGO1 0x100104f0
MxU32 SkateBoard::VTable0xd0()
{
	// TODO
	return 0;
}

// STUB: LEGO1 0x10010510
void SkateBoard::FUN_10010510()
{
	// TODO
}
