#ifndef LEGOANIMATIONMANAGER_H
#define LEGOANIMATIONMANAGER_H

#include "mxcore.h"

// VTABLE 0x100d8c18
// SIZE 0x500
class LegoAnimationManager : public MxCore
{
public:
  LegoAnimationManager();
  virtual ~LegoAnimationManager() override; // vtable+0x0

  virtual long Notify(MxParam &p) override; // vtable+0x4
  virtual long Tickle() override; // vtable+0x8

  // OFFSET: LEGO1 0x1005ec80
  inline virtual const char *ClassName() const override // vtable+0x0c
  {
    // 0x100f7508
    return "LegoAnimationManager";
  }

  // OFFSET: LEGO1 0x1005ec90
  inline virtual MxBool IsA(const char *name) const override // vtable+0x10
  {
    return !strcmp(name, LegoAnimationManager::ClassName()) || MxCore::IsA(name);
  }

  __declspec(dllexport) static void configureLegoAnimationManager(int param_1);
  
private:
  void Init();

};

#endif // LEGOANIMATIONMANAGER_H
