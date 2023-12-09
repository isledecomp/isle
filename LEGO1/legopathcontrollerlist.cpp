#include "legopathcontrollerlist.h"

#include "decomp.h"
#include "legopathcontroller.h"

DECOMP_SIZE_ASSERT(LegoPathControllerList, 0x18);

// FUNCTION: LEGO1 0x1001d210
MxS8 LegoPathControllerList::Compare(LegoPathController* p_a, LegoPathController* p_b)
{
	return p_a == p_b ? 0 : p_a < p_b ? -1 : 1;
}

// FUNCTION: LEGO1 0x1001d3c0
void LegoPathControllerList::Destroy(LegoPathController* p_controller)
{
	delete p_controller;
}
