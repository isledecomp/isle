#ifndef MXRAMSTREAMCONTROLLER_H
#define MXRAMSTREAMCONTROLLER_H

#include "mxdsbuffer.h"
#include "mxstreamcontroller.h"

// VTABLE 0x100dc728
// SIZE 0x98
class MxRAMStreamController : public MxStreamController
{
public:
  inline MxRAMStreamController() {}

  // OFFSET: LEGO1 0x100b9430
  inline virtual const char *ClassName() const override // vtable+0xc
  {
    // 0x10102130
    return "MxRAMStreamController";
  }

  // OFFSET: LEGO1 0x100b9440
  inline virtual MxBool IsA(const char *name) const override // vtable+0x10
  {
    return !strcmp(name, MxRAMStreamController::ClassName()) || !strcmp(name, MxStreamController::ClassName()) || MxCore::IsA(name);
  }

  virtual MxResult Open(const char *p_filename) override;
  virtual MxResult vtable0x20(MxDSAction* p_action) override;
  virtual MxResult vtable0x24(undefined4 p_unknown) override;

private:
  MxDSBuffer m_buffer;

};

#endif // MXRAMSTREAMCONTROLLER_H
