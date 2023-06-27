#ifndef MXSTREAMER_H
#define MXSTREAMER_H

#include "mxcore.h"
#include "mxstreamcontroller.h"
#include "mxresult.h"

class MxStreamer : public MxCore
{
public:
  virtual ~MxStreamer();

  __declspec(dllexport) MxStreamController *Open(const char *name, unsigned short p);
  __declspec(dllexport) long Close(const char *p);

  virtual long Notify(MxParam &p); // vtable+0x4
  virtual MxResult VTable0x14(); // vtable+0x14
};

#endif // MXSTREAMER_H
