#ifndef LEGOBUILDINGMANAGER_H
#define LEGOBUILDINGMANAGER_H

class LegoBuildingManager
{
public:
  LegoBuildingManager();

  __declspec(dllexport) static void configureLegoBuildingManager(int param_1);
  
  void UnknownFunction(int param_1, int param_2, char param_3, LegoBuildingManager* param_4);

private:
  void Init();

  // VTABLE 0x100d6f50
};

#endif // LEGOBUILDINGMANAGER_H
