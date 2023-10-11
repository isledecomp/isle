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
  virtual ~MxMediaPresenter() override;

  virtual MxResult Tickle() override;

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

  virtual void StreamingTickle() override;
  virtual void RepeatingTickle() override;
  virtual void DoneTickle() override;
  virtual void InitVirtual() override;
  virtual MxLong StartAction(MxStreamController *, MxDSAction *) override;
  virtual void EndAction() override;
  virtual void Enable(MxBool p_enable) override;
  virtual void VTable0x58();

  undefined4 m_unk40;
  undefined4 m_unk44;
  undefined4 m_unk48;
  undefined4 m_unk4c;
protected:
  void Destroy(MxBool);
private:
  void Init();

};

#endif // MXMEDIAPRESENTER_H
