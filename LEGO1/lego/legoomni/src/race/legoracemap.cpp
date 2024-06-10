#include "legoracemap.h"

#include "legocontrolmanager.h"
#include "misc.h"

DECOMP_SIZE_ASSERT(LegoRaceMap, 0x1b4)

// FUNCTION: LEGO1 0x1005d0d0
LegoRaceMap::LegoRaceMap()
{
	m_unk0x08 = FALSE;
	m_unk0x0c = NULL;
	m_unk0x10 = 0;
	ControlManager()->Register(this);
}

// STUB: LEGO1 0x1005d2b0
LegoRaceMap::~LegoRaceMap()
{
	// TODO
}

// STUB: LEGO1 0x1005d310
void LegoRaceMap::ParseAction(char* p_extra)
{
	// TODO
}

// FUNCTION: LEGO1 0x1005d4b0
void LegoRaceMap::FUN_1005d4b0()
{
	// TODO
}

// STUB: LEGO1 0x1005d550
MxLong LegoRaceMap::Notify(MxParam& p_param)
{
	// TODO
	return 0;
}
