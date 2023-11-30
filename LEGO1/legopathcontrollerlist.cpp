#include "legopathcontrollerlist.h"

#include "decomp.h"
#include "legopathcontroller.h"

DECOMP_SIZE_ASSERT(LegoPathControllerList, 0x18);

// FUNCTION: LEGO1 0x1001d210
MxS8 LegoPathControllerList::Compare(LegoPathController* p_a, LegoPathController* p_b)
{
	return p_a == p_b ? 0 : p_a < p_b ? -1 : 1;
}

// TEMPLATE: LEGO1 0x1001d230
// MxCollection<LegoPathController *>::Compare

// TEMPLATE: LEGO1 0x1001d240
// MxList<LegoPathController *>::MxList<LegoPathController *>

// TEMPLATE: LEGO1 0x1001d2d0
// MxCollection<LegoPathController *>::~MxCollection<LegoPathController *>

// TEMPLATE: LEGO1 0x1001d320
// MxCollection<LegoPathController *>::Destroy

// TEMPLATE: LEGO1 0x1001d330
// MxList<LegoPathController *>::~MxList<LegoPathController *>

// FUNCTION: LEGO1 0x1001d3c0
void LegoPathControllerList::Destroy(LegoPathController* p_controller)
{
	delete p_controller;
}

// SYNTHETIC: LEGO1 0x1001d490
// MxCollection<LegoPathController *>::`scalar deleting destructor'

// SYNTHETIC: LEGO1 0x1001d500
// MxList<LegoPathController *>::`scalar deleting destructor'

// SYNTHETIC: LEGO1 0x1001d5b0
// MxPtrList<LegoPathController>::`scalar deleting destructor'
