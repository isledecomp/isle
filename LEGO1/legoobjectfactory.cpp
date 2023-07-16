#include "legoobjectfactory.h"

#include "infocenterstate.h"

#include "decomp.h"

// TODO: Uncomment once we have all the relevant types ready
// DECOMP_SIZE_ASSERT(LegoObjectFactory, 0x1c4);

// OFFSET: LEGO1 0x100b0d80
LegoObjectFactory::LegoObjectFactory()
{
#define X(V) this->m_id##V = MxAtomId(#V, LookupMode_Exact);
  FOR_LEGOOBJECTFACTORY_OBJECTS(X)
#undef X
}

// OFFSET: LEGO1 0x100b12c0
void *LegoObjectFactory::Create(const char *p_name)
{
  MxAtomId atom(p_name, LookupMode_Exact);

  if (0) {
#define X(V) } else if (this->m_id##V == atom) { return new V;
  FOR_LEGOOBJECTFACTORY_OBJECTS(X)
#undef X
  } else {
    return MxObjectFactory::Create(p_name);
  }
}

// OFFSET: LEGO1 0x100b1a30 STUB
void LegoObjectFactory::Destroy(void *p_object) {
  // FIXME
}
