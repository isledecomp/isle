#include "legoworldlist.h"

#include "legoworld.h"

// FUNCTION: LEGO1 0x100598d0
MxS8 LegoWorldList::Compare(LegoWorld* p_a, LegoWorld* p_b)
{
	return p_a == p_b ? 0 : p_a < p_b ? -1 : 1;
}

// FUNCTION: LEGO1 0x100599f0
void LegoWorldList::Destroy(LegoWorld* p_world)
{
	delete p_world;
}
