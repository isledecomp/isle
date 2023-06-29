#ifndef LEGOBUILDINGMANAGER_H
#define LEGOBUILDINGMANAGER_H

#include "mxcore.h"

// VTABLE 0x100d6f50
// SIZE 0x30
class LegoBuildingManager : public MxCore
{
public:
  LegoBuildingManager();
  virtual ~LegoBuildingManager() override;

  // OFFSET: LEGO1 0x1002f930
  inline virtual const char *ClassName() const override // vtable+0x0c
  {
    // 0x100f37d0
    return "LegoBuildingManager";
  }

  __declspec(dllexport) static void configureLegoBuildingManager(int param_1);

private:
  void Init();

};

#endif // LEGOBUILDINGMANAGER_H
