#include "decomp.h"
#include "mxstreamprovider.h"

DECOMP_SIZE_ASSERT(MxStreamProvider, 0x10);

// OFFSET: LEGO1 0x100d07c0
MxResult MxStreamProvider::SetResourceToGet(MxStreamController* p_resource)
{
  m_pLookup = p_resource;
  return SUCCESS;
}

// OFFSET: LEGO1 0x100d07d0
void MxStreamProvider::vtable0x20(undefined4 p_unknown1)
{

}
