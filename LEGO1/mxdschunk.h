#ifndef MXDSCHUNK_H
#define MXDSCHUNK_H

#include "mxcore.h"
#include "mxtypes.h"

// VTABLE 0x100dc7f8
class MxDSChunk : public MxCore
{
public:
  MxDSChunk();
  virtual ~MxDSChunk() override;

  // OFFSET: LEGO1 0x100be0c0
  inline virtual const char *ClassName() const override // vtable+0x0c
  {
    // 0x10101e6c
    return "MxDSChunk";
  }

  // OFFSET: LEGO1 0x100be0d0
  inline virtual MxBool IsA(const char *name) const override // vtable+0x10
  {
    return !strcmp(name, MxDSChunk::ClassName()) || MxCore::IsA(name);
  }
private:
  MxS16 m_length; // 0x8
  MxLong m_buffer; // 0xc
  MxLong m_long1FromHeader; // 0x10
  MxLong m_long2FromHeader; // 0x14
  void* m_pStuff; // 0x18
  void* m_pSomething; // 0x1c
};

#endif // MXDSCHUNK_H
