#ifndef MXVIDEOPRESENTER_H
#define MXVIDEOPRESENTER_H

#include "mxmediapresenter.h"

#include "decomp.h"

class MxVideoPresenter : public MxMediaPresenter
{
public:
  MxVideoPresenter()
  {
    Init();
  }

  virtual ~MxVideoPresenter() override; // vtable+0x0

  // OFFSET: LEGO1 0x1000c820
  inline virtual const char *ClassName() const override // vtable+0x0c
  {
    // 0x100f0760
    return "MxVideoPresenter";
  }

  // OFFSET: LEGO1 0x1000c830
  inline virtual MxBool IsA(const char *name) const override // vtable+0x10
  {
    return !strcmp(name, MxVideoPresenter::ClassName()) || MxMediaPresenter::IsA(name);
  }

  void Init();

  virtual void InitVirtual() override; // vtable+0x38

  virtual void VTable0x5c(); // vtable+0x5c
  virtual void VTable0x60(); // vtable+0x60
  virtual void VTable0x64(); // vtable+0x64
  virtual void VTable0x68(); // vtable+0x68
  virtual void VTable0x6c(); // vtable+0x6c
  virtual void VTable0x70(); // vtable+0x70
  virtual void VTable0x74(); // vtable+0x74
  virtual void VTable0x78(); // vtable+0x78
  virtual void VTable0x7c(); // vtable+0x7c
  virtual MxS32 GetWidth();  // vtable+0x80
  virtual MxS32 GetHeight(); // vtable+0x84

  undefined4 m_unk50;
  undefined4 m_unk54;
  undefined4 m_unk58;
  undefined2 m_unk5c;
  unsigned char m_flags; // 0x5e
  undefined4 m_unk60;
};

#endif // MXVIDEOPRESENTER_H
