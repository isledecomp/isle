#include "racecar.h"

#include "legocontrolmanager.h"
#include "misc.h"

DECOMP_SIZE_ASSERT(RaceCar, 0x164)

// FUNCTION: LEGO1 0x10028200
RaceCar::RaceCar()
{
	m_unk0x13c = 40.0;
}

// FUNCTION: LEGO1 0x10028420
RaceCar::~RaceCar()
{
	ControlManager()->Unregister(this);
	VTable0xe4();
}

// STUB: LEGO1 0x10028490
MxResult RaceCar::Create(MxDSAction& p_dsAction)
{
	// TODO
	return SUCCESS;
}

// STUB: LEGO1 0x100284d0
MxU32 RaceCar::VTable0xcc()
{
	// TODO
	return 0;
}
