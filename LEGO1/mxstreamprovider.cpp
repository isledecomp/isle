#include "mxstreamprovider.h"

#include "decomp.h"

DECOMP_SIZE_ASSERT(MxStreamProvider, 0x10);

// FUNCTION: LEGO1 0x100d07c0
MxResult MxStreamProvider::SetResourceToGet(MxStreamController* p_resource)
{
	m_pLookup = p_resource;
	return SUCCESS;
}

// FUNCTION: LEGO1 0x100d07d0
void MxStreamProvider::VTable0x20(MxDSAction* p_action)
{
}
