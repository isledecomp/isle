#ifndef MXDISKSTREAMCONTROLLER_H
#define MXDISKSTREAMCONTROLLER_H

#include "mxstreamcontroller.h"

class MxDiskStreamController : public MxStreamController
{
public:
  virtual ~MxDiskStreamController();

  virtual long Tickle(); // vtable+0x8
};

#endif // MXDISKSTREAMCONTROLLER_H
