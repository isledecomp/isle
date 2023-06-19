#ifndef MXTICKLEMANAGER_H
#define MXTICKLEMANAGER_H

#include "mxcore.h"

class MxTickleManager : public MxCore
{
public:
  virtual ~MxTickleManager();

  virtual long Tickle();
  virtual const char *GetClassName() const;
  virtual MxBool IsClass(const char *name) const;
  virtual void vtable14();
  virtual void vtable18();
  virtual void vtable1c(void *v, int p);
  virtual void vtable20();
};

#endif // MXTICKLEMANAGER_H
