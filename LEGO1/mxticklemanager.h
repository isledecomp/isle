#ifndef MXTICKLEMANAGER_H
#define MXTICKLEMANAGER_H

#include "mxcore.h"

// VTABLE 0x100d86d8
class MxTickleManager : public MxCore
{
public:
  virtual ~MxTickleManager();

  virtual MxLong Tickle();
  virtual const char *ClassName() const;
  virtual MxBool IsA(const char *name) const;
  virtual void Register(MxCore *p_listener, int p_milliseconds);
  virtual void Unregister(MxCore *p_listener);
  virtual void vtable1c(void *v, int p);
  virtual void vtable20();
};

#endif // MXTICKLEMANAGER_H
