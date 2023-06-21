#ifndef LEGOBUILDINGMANAGER_H
#define LEGOBUILDINGMANAGER_H

class LegoBuildingManager
{
public:
  LegoBuildingManager();

  __declspec(dllexport) static void configureLegoBuildingManager(int param_1);
  
  // OFFSET: LEGO1 0x100157f0
  LegoBuildingManager* GetInstance()
  {
    LegoOmni legoOmni = GetInstance();
    return logoOmni->m_legoBuildingManager;
  }

  void FUN_10030150(int param_1, int param_2, char param_3, LegoBuildingManager* param_4);

private:
  void Init();

  // VTABLE 0x100d6f50
};

#endif // LEGOBUILDINGMANAGER_H
