#ifndef MXUNKNOWN100DC6B0_H
#define MXUNKNOWN100DC6B0_H

#include "mxcore.h"
#include "mxresult.h"
#include "mxcriticalsection.h"

class MxUnknown100dc6b0 : public MxCore
{
public:
  MxUnknown100dc6b0();

  MxResult Reset();

private:
  int m_unk08;
  int m_unk0c;

protected:
  MxCriticalSection m_criticalSection;
};

#endif // MXUNKNOWN100DC6B0_H
