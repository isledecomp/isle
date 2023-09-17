#ifndef MXPRESENTER_H
#define MXPRESENTER_H

#include "mxcore.h"
#include "mxdsaction.h"
#include "mxcriticalsection.h"
#include "mxomni.h"

#include "decomp.h"

class MxStreamController;

// VTABLE 0x100d4d38
class MxPresenter : public MxCore
{
public:
  enum TickleState 
  {
    TickleState_Idle = 0,
    TickleState_Ready,
    TickleState_Starting,
    TickleState_Streaming,
    TickleState_Repeating,
    TickleState_unk5,
    TickleState_Done,
  };

  MxPresenter() { Init(); }

  __declspec(dllexport) virtual ~MxPresenter(); // vtable+0x0
  __declspec(dllexport) virtual MxLong Tickle() override; // vtable+0x8

  // OFFSET: LEGO1 0x1000bfe0
  inline virtual const char *ClassName() const override// vtable+0xc
  {
    // 0x100f0740
    return "MxPresenter";
  }

  // OFFSET: LEGO1 0x1000bff0
  inline virtual MxBool IsA(const char *name) const override// vtable+0x10
  {
    return !strcmp(name, MxPresenter::ClassName()) || MxCore::IsA(name);
  }

  virtual void VTable0x14(); // vtable+0x14
  virtual void ReadyTickle(); // vtable+0x18
  virtual void StartingTickle(); // vtable+0x1c
  virtual void StreamingTickle(); // vtable+0x20
  virtual void RepeatingTickle(); // vtable+0x24
  virtual void Unk5Tickle(); // vtable+0x28

protected:
  __declspec(dllexport) virtual void DoneTickle(); // vtable+0x2c
  __declspec(dllexport) virtual void ParseExtra(); // vtable+0x30

public:
  virtual undefined4 VTable0x34(); // vtable+0x34
  virtual void InitVirtual(); // vtable+0x38
  __declspec(dllexport) virtual MxLong StartAction(MxStreamController *, MxDSAction *); // vtable+0x3c
  __declspec(dllexport) virtual void EndAction(); // vtable+0x40
  virtual void SetTickleState(TickleState p_tickleState); // vtable+0x44
  virtual MxBool HasTickleStatePassed(TickleState p_tickleState); // vtable+0x48
  virtual undefined4 VTable0x4c(); // vtable+0x4c
  virtual undefined VTable0x50(undefined4, undefined4); // vtable+0x50
  __declspec(dllexport) virtual void Enable(MxBool p_enable); // vtable+0x54

  MxBool IsEnabled();

protected:
  __declspec(dllexport) void Init();
  void SendTo_unkPresenter(MxOmni *);

private:
  MxS32 m_currentTickleState; // 0x8
  MxU32 m_previousTickleStates;
  undefined4 m_unk0x10;
  undefined4 m_unk0x14;
  undefined4 m_unk0x18;
  MxDSAction *m_action; // 0
  MxCriticalSection m_criticalSection;
  MxPresenter *m_unkPresenter; // 0x3c
};

#endif // MXPRESENTER_H
