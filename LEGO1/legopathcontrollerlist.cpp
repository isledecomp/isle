#include "legopathcontrollerlist.h"

#include "decomp.h"
#include "legopathcontroller.h"

DECOMP_SIZE_ASSERT(LegoPathControllerList, 0x18);

// OFFSET: LEGO1 0x1001d210
MxS8 LegoPathControllerList::Compare(LegoPathController* p_a, LegoPathController* p_b)
{
	return p_a == p_b ? 0 : p_a < p_b ? -1 : 1;
}

// OFFSET: LEGO1 0x1001d230 TEMPLATE
// MxCollection<LegoPathController *>::Compare

// OFFSET: LEGO1 0x1001d240 TEMPLATE
// MxList<LegoPathController *>::MxList<LegoPathController *>

// OFFSET: LEGO1 0x1001d2d0 TEMPLATE
// MxCollection<LegoPathController *>::~MxCollection<LegoPathController *>

// OFFSET: LEGO1 0x1001d320 TEMPLATE
// MxCollection<LegoPathController *>::Destroy

// OFFSET: LEGO1 0x1001d330 TEMPLATE
// MxList<LegoPathController *>::~MxList<LegoPathController *>

// OFFSET: LEGO1 0x1001d3c0
void LegoPathControllerList::Destroy(LegoPathController* p_controller)
{
	delete p_controller;
}

// OFFSET: LEGO1 0x1001d490 TEMPLATE
// MxCollection<LegoPathController *>::`scalar deleting destructor'

// OFFSET: LEGO1 0x1001d500 TEMPLATE
// MxList<LegoPathController *>::`scalar deleting destructor'

// OFFSET: LEGO1 0x1001d5b0 TEMPLATE
// MxPtrList<LegoPathController>::`scalar deleting destructor'
