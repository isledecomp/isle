#include "legocolor.h"

#include "decomp.h"
#include "legostorage.h"

DECOMP_SIZE_ASSERT(LegoColor, 0x03)

// FUNCTION: LEGO1 0x100d3a20
LegoResult LegoColor::Read(LegoStorage* p_storage)
{
	LegoResult result;
	if ((result = p_storage->Read(&m_red, sizeof(m_red))) != SUCCESS) {
		return result;
	}
	if ((result = p_storage->Read(&m_green, sizeof(m_green))) != SUCCESS) {
		return result;
	}
	if ((result = p_storage->Read(&m_blue, sizeof(m_blue))) != SUCCESS) {
		return result;
	}
	return SUCCESS;
}
