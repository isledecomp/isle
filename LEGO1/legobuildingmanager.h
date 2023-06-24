#ifndef LEGOBUILDINGMANAGER_H
#define LEGOBUILDINGMANAGER_H

class LegoBuildingManager
{
public:
  __declspec(dllexport) static void configureLegoBuildingManager(int param_1);
  const char* GetClassName();
};

#endif // LEGOBUILDINGMANAGER_H
