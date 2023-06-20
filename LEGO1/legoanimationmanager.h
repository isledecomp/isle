#ifndef LEGOANIMATIONMANAGER_H
#define LEGOANIMATIONMANAGER_H

class LegoAnimationManager
{
public:
  LegoAnimationManager();

  __declspec(dllexport) static void configureLegoAnimationManager(int param_1);
  
private:
  void Init();
  
  // VTABLE 0x100d8c18
  // SIZE 0x500
};

#endif // LEGOANIMATIONMANAGER_H
