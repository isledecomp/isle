#include "legoworldlist.h"

#include "legoworld.h"

// FUNCTION: LEGO1 0x100598d0
MxS8 LegoWorldList::Compare(LegoWorld* p_a, LegoWorld* p_b)
{
	return p_a == p_b ? 0 : p_a < p_b ? -1 : 1;
}

// TEMPLATE: LEGO1 0x100598f0
// MxCollection<LegoWorld *>::Compare

// TEMPLATE: LEGO1 0x10059900
// MxCollection<LegoWorld *>::~MxCollection<LegoWorld *>

// TEMPLATE: LEGO1 0x10059950
// MxCollection<LegoWorld *>::Destroy

// TEMPLATE: LEGO1 0x10059960
// MxList<LegoWorld *>::~MxList<LegoWorld *>

// FUNCTION: LEGO1 0x100599f0
void LegoWorldList::Destroy(LegoWorld* p_world)
{
	delete p_world;
}

// SYNTHETIC: LEGO1 0x10059ac0
// MxCollection<LegoWorld *>::`scalar deleting destructor'

// SYNTHETIC: LEGO1 0x10059b30
// MxList<LegoWorld *>::`scalar deleting destructor'

// SYNTHETIC: LEGO1 0x10059be0
// MxPtrList<LegoWorld>::`scalar deleting destructor'
