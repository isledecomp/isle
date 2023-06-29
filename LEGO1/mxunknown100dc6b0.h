#ifndef MXUNKNOWN100DC6B0_H
#define MXUNKNOWN100DC6B0_H

#include "mxcore.h"
#include "mxcriticalsection.h"
#include "mxtypes.h"

// VTABLE 0x100dc6b0
class MxUnknown100dc6b0 : public MxCore
{
public:
  MxUnknown100dc6b0();

  MxResult Init();

private:
  int m_unk08;
  int m_unk0c;

protected:
  MxCriticalSection m_criticalSection;
};

#endif // MXUNKNOWN100DC6B0_H
