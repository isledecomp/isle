#ifndef LEGOPLANTMANAGER_H
#define LEGOPLANTMANAGER_H

#include "mxcore.h"

class LegoPlantManager : public MxCore
{
public:
  LegoPlantManager();
  virtual ~LegoPlantManager();
  
  // OFFSET: LEGO1 0x100157e0
  LegoPlantManager* GetInstance()
  {
    LegoOmni* legoOmni = LegoOmni::GetInstance();

    return legoOmni->m_plantManager;
  }

  // Virtual Functions
  virtual const char* GetClassName() const;

  // Member Functions
  void FUN_10026d70(int param_1, int param_2);

private:
  void Init();
  
  // VTABLE 0x100d6758
  // SIZE 0x2c
};

#endif // LEGOPLANTMANAGER_H
