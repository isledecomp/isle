#include "legopathcontrollerlist.h"

#include "decomp.h"
#include "legopathcontroller.h"

DECOMP_SIZE_ASSERT(LegoPathControllerList, 0x18);

// FUNCTION: LEGO1 0x1001d210
MxS8 LegoPathControllerList::Compare(LegoPathController* p_a, LegoPathController* p_b)
{
	return p_a == p_b ? 0 : p_a < p_b ? -1 : 1;
}

// FUNCTION: LEGO1 0x1001d230 SYNTHETIC
// MxCollection<LegoPathController *>::Compare

// FUNCTION: LEGO1 0x1001d240 SYNTHETIC
// MxList<LegoPathController *>::MxList<LegoPathController *>

// FUNCTION: LEGO1 0x1001d2d0 SYNTHETIC
// MxCollection<LegoPathController *>::~MxCollection<LegoPathController *>

// FUNCTION: LEGO1 0x1001d320 SYNTHETIC
// MxCollection<LegoPathController *>::Destroy

// FUNCTION: LEGO1 0x1001d330 SYNTHETIC
// MxList<LegoPathController *>::~MxList<LegoPathController *>

// FUNCTION: LEGO1 0x1001d3c0
void LegoPathControllerList::Destroy(LegoPathController* p_controller)
{
	delete p_controller;
}

// FUNCTION: LEGO1 0x1001d490 SYNTHETIC
// MxCollection<LegoPathController *>::`scalar deleting destructor'

// FUNCTION: LEGO1 0x1001d500 SYNTHETIC
// MxList<LegoPathController *>::`scalar deleting destructor'

// FUNCTION: LEGO1 0x1001d5b0 SYNTHETIC
// MxPtrList<LegoPathController>::`scalar deleting destructor'
