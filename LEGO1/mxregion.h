#ifndef MXREGION_H
#define MXREGION_H

#include "mxcore.h"
#include "decomp.h"

// VTABLE 0x100dcae8
// SIZE 0x1c
class MxRegion : public MxCore
{
public:
  MxRegion();
  virtual ~MxRegion() override;

  virtual void Reset();
  virtual void vtable18();
  virtual void vtable1c();
  virtual void vtable20();

private:
  // A container (probably MxList) holding MxRect32
  // MxList<MxRect32> *m_rects;
  // 4 coordinates (could be MxRect32)
  // MxS32 left, top, right, bottom;
  undefined pad[0x14];
};

#endif // MXREGION_H
