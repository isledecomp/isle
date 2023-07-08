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
  // May be Register(obj, milliseconds);
  virtual void vtable14(MxCore *p_unk1, int p_unk2);
  // May be Unregister(obj);
  virtual void vtable18(MxCore *p_unk1);
  virtual void vtable1c(void *v, int p);
  virtual void vtable20();
};

#endif // MXTICKLEMANAGER_H
