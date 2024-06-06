#include "racecar.h"

#include "legocontrolmanager.h"
#include "misc.h"

DECOMP_SIZE_ASSERT(RaceCar, 0x164)

// FUNCTION: LEGO1 0x10028200
RaceCar::RaceCar()
{
	m_maxLinearVel = 40.0;
}

// FUNCTION: LEGO1 0x10028420
RaceCar::~RaceCar()
{
	ControlManager()->Unregister(this);
	Exit();
}

// STUB: LEGO1 0x10028490
MxResult RaceCar::Create(MxDSAction& p_dsAction)
{
	// TODO
	return SUCCESS;
}

// STUB: LEGO1 0x100284d0
MxU32 RaceCar::HandleClick()
{
	// TODO
	return 0;
}
