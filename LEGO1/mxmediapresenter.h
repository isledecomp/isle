#ifndef MXMEDIAPRESENTER_H
#define MXMEDIAPRESENTER_H

#include "mxpresenter.h"

#include "decomp.h"

// VTABLE 0x100d4cd8
class MxMediaPresenter : public MxPresenter
{
public:
  inline MxMediaPresenter()
  {
    Init();
  }
  ~MxMediaPresenter();

  virtual MxResult Tickle() override; // vtable+0x8, override MxCore

  // OFFSET: LEGO1 0x1000c5c0
  inline virtual const char *ClassName() const override // vtable+0xc
  {
    // 0x100f074c
    return "MxMediaPresenter";
  }

  // OFFSET: LEGO1 0x1000c5d0
  inline virtual MxBool IsA(const char *name) const override // vtable+0x10
  {
    return !strcmp(name, MxMediaPresenter::ClassName()) || MxPresenter::IsA(name);
  }

  virtual void StreamingTickle() override; // vtable+0x20, override MxPresenter
  virtual void RepeatingTickle() override; // vtable+0x24, override MxPresenter
  virtual void DoneTickle() override; // vtable+0x2c, override MxPresenter
  virtual void InitVirtual() override; // vtable+0x38, override MxPresenter
  virtual MxLong StartAction(MxStreamController *, MxDSAction *) override; // vtable+0x3c, override MxPresenter
  virtual void EndAction() override; // vtable+0x40, override MxPresenter
  virtual void Enable(MxBool p_enable) override; //vtable+0x54, override MxPresenter
  virtual void VTable0x58(); // vtable+0x58

  undefined4 m_unk40;
  undefined4 m_unk44;
  undefined4 m_unk48;
  undefined4 m_unk4c;
private:
  void Init();
  void Destroy(MxBool);

};

#endif // MXMEDIAPRESENTER_H
