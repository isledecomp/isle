#include "mxobjectfactory.h"

#include "mxpresenter.h"
#include "mxcompositepresenter.h"
#include "mxvideopresenter.h"
#include "mxflcpresenter.h"
#include "mxsmkpresenter.h"
#include "mxstillpresenter.h"
#include "mxwavepresenter.h"
#include "mxmidipresenter.h"
#include "mxeventpresenter.h"
#include "mxloopingflcpresenter.h"
#include "mxloopingsmkpresenter.h"
#include "mxloopingmidipresenter.h"

#include "decomp.h"

DECOMP_SIZE_ASSERT(MxObjectFactory, 0x38); // 100af1db

// OFFSET: LEGO1 0x100b0d80
MxObjectFactory::MxObjectFactory()
{
#define X(V) this->m_id##V = MxAtomId(#V, LookupMode_Exact);
  FOR_MXOBJECTFACTORY_OBJECTS(X)
#undef X
}

// OFFSET: LEGO1 0x100b12c0
void *MxObjectFactory::Create(const char *p_name)
{
  MxAtomId atom(p_name, LookupMode_Exact);

  if (0) {
#define X(V) } else if (this->m_id##V == atom) { return new V;
  FOR_MXOBJECTFACTORY_OBJECTS(X)
#undef X
  } else {
    return NULL;
  }
}

// OFFSET: LEGO1 0x100b1a30 STUB
void MxObjectFactory::Destroy(void *p_object) {
  // FIXME
}
