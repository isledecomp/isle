#ifndef LEGOOBJECTFACTORY_H
#define LEGOOBJECTFACTORY_H

#include "mxobjectfactory.h"

#define FOR_LEGOOBJECTFACTORY_OBJECTS(X) \
  X(InfocenterState)

// VTABLE 0x100dc220
class LegoObjectFactory : public MxObjectFactory
{
public:
  LegoObjectFactory();
  virtual void *Create(const char *p_name); // vtable 0x14
  virtual void Destroy(void *p_object); // vtable 0x18
private:
#define X(V) MxAtomId m_id##V;
  FOR_LEGOOBJECTFACTORY_OBJECTS(X)
#undef X
};

#endif // LEGOOBJECTFACTORY_H
