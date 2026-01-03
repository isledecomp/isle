#include "legocolor.h"

#include "decomp.h"
#include "misc/legostorage.h"

DECOMP_SIZE_ASSERT(LegoColor, 0x03)

// FUNCTION: LEGO1 0x100d3a20
// FUNCTION: BETA10 0x10190730
LegoResult LegoColor::Read(LegoStorage* p_storage)
{
	LegoResult result;
	if ((result = p_storage->Read(&m_red, sizeof(LegoU8))) != SUCCESS) {
		return result;
	}
	if ((result = p_storage->Read(&m_green, sizeof(LegoU8))) != SUCCESS) {
		return result;
	}
	if ((result = p_storage->Read(&m_blue, sizeof(LegoU8))) != SUCCESS) {
		return result;
	}
	return SUCCESS;
}
