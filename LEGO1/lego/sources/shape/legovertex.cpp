#include "legovertex.h"

#include "decomp.h"
#include "misc/legostorage.h"

DECOMP_SIZE_ASSERT(LegoVertex, 0x0c)

// FUNCTION: LEGO1 0x100d37b0
LegoVertex::LegoVertex()
{
	m_coordinates[0] = 0.0F;
	m_coordinates[1] = 0.0F;
	m_coordinates[2] = 0.0F;
}

// FUNCTION: LEGO1 0x100d37c0
LegoResult LegoVertex::Read(LegoStorage* p_storage)
{
	LegoResult result;
	if ((result = p_storage->Read(&m_coordinates[0], sizeof(m_coordinates[0]))) != SUCCESS) {
		return result;
	}
	if ((result = p_storage->Read(&m_coordinates[1], sizeof(m_coordinates[1]))) != SUCCESS) {
		return result;
	}
	if ((result = p_storage->Read(&m_coordinates[2], sizeof(m_coordinates[2]))) != SUCCESS) {
		return result;
	}
	return SUCCESS;
}
