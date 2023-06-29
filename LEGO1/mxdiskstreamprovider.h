#ifndef MXDISKSTREAMPROVIDER_H
#define MXDISKSTREAMPROVIDER_H

#include "mxstreamprovider.h"

// VTABLE 0x100dd138
class MxDiskStreamProvider : public MxStreamProvider
{
public:
  MxDiskStreamProvider();

  virtual ~MxDiskStreamProvider() override;

  // OFFSET: LEGO1 0x100d1160
  inline virtual const char *ClassName() const override // vtable+0x0c
  {
    // 0x1010287c
    return "MxDiskStreamProvider";
  }

  // OFFSET: LEGO1 0x100d1170
  inline virtual MxBool IsA(const char *name) const override // vtable+0x10
  {
    return !strcmp(name, MxDiskStreamProvider::ClassName()) || MxStreamProvider::IsA(name);
  }
};

#endif // MXDISKSTREAMPROVIDER_H
