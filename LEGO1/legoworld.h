#ifndef LEGOWORLD_H
#define LEGOWORLD_H

class LegoWorld
{
public:
  __declspec(dllexport) LegoWorld();
  __declspec(dllexport) virtual ~LegoWorld();
  const char* GetClassName();
};

#endif // LEGOWORLD_H
