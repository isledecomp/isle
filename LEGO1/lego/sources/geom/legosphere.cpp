#include "legosphere.h"

#include "decomp.h"
#include "misc/legostorage.h"

DECOMP_SIZE_ASSERT(LegoSphere, 0x10)

// FUNCTION: LEGO1 0x100d3770
LegoResult LegoSphere::Read(LegoStorage* p_storage)
{
	LegoResult result;
	if ((result = m_center.Read(p_storage)) != SUCCESS) {
		return result;
	}
	if ((result = p_storage->Read(&m_radius, sizeof(m_radius))) != SUCCESS) {
		return result;
	}
	return SUCCESS;
}
