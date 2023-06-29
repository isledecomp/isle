#ifndef MXDISKSTREAMCONTROLLER_H
#define MXDISKSTREAMCONTROLLER_H

#include <string.h>

#include "mxstreamcontroller.h"
#include "mxtypes.h"

// VTABLE 0x100dccb8
// SIZE 0xc8
class MxDiskStreamController : public MxStreamController
{
public:
  MxDiskStreamController();
  virtual ~MxDiskStreamController() override;

  virtual long Tickle() override; // vtable+0x8

  // OFFSET: LEGO1 0x100c7360
  inline virtual const char *ClassName() const override // vtable+0x0c
  {
    // 0x10102144
    return "MxDiskStreamController";
  }

  // OFFSET: LEGO1 0x100c7370
  inline virtual MxBool IsA(const char *name) const override // vtable+0x10
  {
    return !strcmp(name, MxDiskStreamController::ClassName()) || MxStreamController::IsA(name);
  }

};

#endif // MXDISKSTREAMCONTROLLER_H
