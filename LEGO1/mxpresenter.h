#ifndef MXPRESENTER_H
#define MXPRESENTER_H

#include "mxcore.h"

class MxStreamController;
class MxDSAction;

class MxPresenter : public MxCore
{
protected:
  __declspec(dllexport) virtual void DoneTickle(); // vtable+0x2c
  __declspec(dllexport) void Init();
  __declspec(dllexport) virtual void ParseExtra(); // vtable+0x30
public:
  __declspec(dllexport) virtual ~MxPresenter(); // vtable+0x0

  __declspec(dllexport) virtual long Tickle(); // vtable+0x8
  virtual const char *GetClassName() const; // vtable+0xc
  virtual MxBool IsClass(const char *name) const; // vtable+0x10
  __declspec(dllexport) virtual long StartAction(MxStreamController *, MxDSAction *); // vtable+0x3c
  __declspec(dllexport) virtual void EndAction(); // vtable+0x40
  __declspec(dllexport) virtual void Enable(unsigned char); // vtable+0x54

  virtual void FUN_1000be30(); // vtable+0x14
  virtual void __fastcall FUN_1000be40(int param); // vtable+0x18
  virtual void __fastcall FUN_1000be60(int param); // vtable+0x1c
  virtual void __fastcall FUN_1000be80(int param); // vtable+0x20
  virtual void __fastcall FUN_1000bea0(int param); // vtable+0x24
  virtual void __fastcall FUN_1000bec0(int param); // vtable+0x28

  // VTABLE 0x100d4d38
};

#endif // MXPRESENTER_H
