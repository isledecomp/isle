#ifndef MXOBJECTFACTORY_H
#define MXOBJECTFACTORY_H

#include "mxcore.h"
#include "mxatomid.h"

#define FOR_MXOBJECTFACTORY_OBJECTS(X)  \
  X(MxPresenter)                        \
  X(MxCompositePresenter)               \
  X(MxVideoPresenter)                   \
  X(MxFlcPresenter)                     \
  X(MxSmkPresenter)                     \
  X(MxStillPresenter)                   \
  X(MxWavePresenter)                    \
  X(MxMIDIPresenter)                    \
  X(MxEventPresenter)                   \
  X(MxLoopingFlcPresenter)              \
  X(MxLoopingSmkPresenter)              \
  X(MxLoopingMIDIPresenter)

// VTABLE 0x100dc220
class MxObjectFactory : public MxCore
{
public:
  MxObjectFactory();
  virtual MxCore *Create(const char *name); // vtable 0x14
  virtual void vtable18(void *); // vtable 0x18
private:
#define X(V) MxAtomId m_id##V;
  FOR_MXOBJECTFACTORY_OBJECTS(X)
#undef X
};

#endif // MXOBJECTFACTORY_H
