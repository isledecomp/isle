#ifndef MXPRESENTER_H
#define MXPRESENTER_H

#include "mxcore.h"

#include "mxcriticalsection.h"

class MxStreamController;
class MxDSAction;

#ifndef undefined4
#define undefined4 int
#endif

#ifndef undefined
#define undefined int
#endif

class MxPresenter : public MxCore
{
public:
  __declspec(dllexport) virtual ~MxPresenter(); // vtable+0x0

  // OFFSET: LEGO1 0x1000bfe0
  inline virtual const char *MxPresenter::GetClassName() const // vtable+0xc
  {
    // 0x100f0740
    return "MxPresenter";
  }

  // OFFSET: LEGO1 0x1000bff0
  inline virtual MxBool MxPresenter::IsClass(const char *name) const // vtable+0x10
  {
    return !strcmp(name, MxPresenter::GetClassName()) || MxCore::IsClass(name);
  }

  __declspec(dllexport) virtual long Tickle(); // vtable+0x8
  virtual void VTable0x14(); // vtable+0x14
  virtual void VTable0x18(); // vtable+0x18
  virtual void VTable0x1c(); // vtable+0x1c
  virtual void VTable0x20(); // vtable+0x20
  virtual void VTable0x24(); // vtable+0x24
  virtual void VTable0x28(); // vtable+0x28
  virtual undefined4 VTable0x34(); // vtable+0x34
  virtual void InitVirtual(); // vtable+0x38
  virtual void VTable0x44(undefined4 param); // vtable+0x44
  virtual undefined4 VTable0x48(undefined4 param); // vtable+0x48
  virtual undefined4 VTable0x4c(); // vtable+0x4c
  virtual undefined VTable0x50(); // vtable+0x50
protected:
  __declspec(dllexport) virtual void DoneTickle(); // vtable+0x2c
  __declspec(dllexport) void Init();
  __declspec(dllexport) virtual void ParseExtra(); // vtable+0x30
public:
  __declspec(dllexport) virtual long StartAction(MxStreamController *, MxDSAction *); // vtable+0x3c
  __declspec(dllexport) virtual void EndAction(); // vtable+0x40
  __declspec(dllexport) virtual void Enable(unsigned char); // vtable+0x54

  int m_unk0x8;
  int m_unk0xc;
  int m_unk0x10;
  int m_unk0x14;
  int m_unk0x18;
  MxDSAction* m_action; // 0
  MxCriticalSection m_criticalSection;
  int m_unk0x3c;

  // VTABLE 0x100d4d38
};

#endif // MXPRESENTER_H
