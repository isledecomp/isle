#ifndef MXSTREAMER_H
#define MXSTREAMER_H

#include "mxcore.h"
#include "mxstreamcontroller.h"
#include "mxtypes.h"

// VTABLE 0x100dc710
class MxStreamer : public MxCore
{
public:
  virtual ~MxStreamer() override;

  __declspec(dllexport) MxStreamController *Open(const char *name, MxU16 p);
  __declspec(dllexport) MxLong Close(const char *p);

  virtual MxLong Notify(MxParam &p) override; // vtable+0x4
  virtual MxResult VTable0x14(); // vtable+0x14
};

#endif // MXSTREAMER_H
