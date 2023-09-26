#ifndef MXDSBUFFER_H
#define MXDSBUFFER_H

#include "decomp.h"
#include "mxcore.h"

// VTABLE 0x100dcca0
// SIZE 0x34
class MxDSBuffer : public MxCore
{
public:
  MxDSBuffer();
  virtual ~MxDSBuffer() override;

private:
  undefined m_unk08[0x2C];

};

#endif // MXDSBUFFER_H
