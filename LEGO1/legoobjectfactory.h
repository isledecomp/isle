#ifndef LEGOOBJECTFACTORY_H
#define LEGOOBJECTFACTORY_H

#include "mxobjectfactory.h"

#define FOR_LEGOOBJECTFACTORY_OBJECTS(X) \
  X(InfocenterState)

// VTABLE 0x100d4768
class LegoObjectFactory : public MxObjectFactory
{
public:
  LegoObjectFactory();
  virtual MxCore *Create(const char *p_name) override; // vtable 0x14
  virtual void Destroy(void *p_object) override; // vtable 0x18
private:
#define X(V) MxAtomId m_id##V;
  FOR_LEGOOBJECTFACTORY_OBJECTS(X)
#undef X
};

#endif // LEGOOBJECTFACTORY_H
