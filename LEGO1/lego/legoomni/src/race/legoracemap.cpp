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

// FUNCTION: LEGO1 0x1005d4b0
void LegoRaceMap::FUN_1005d4b0()
{
	// TODO
}
