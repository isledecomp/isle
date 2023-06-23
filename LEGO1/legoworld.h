#ifndef LEGOWORLD_H
#define LEGOWORLD_H

#include "legoentity.h"

class LegoWorld : public LegoEntity
{
public:
  __declspec(dllexport) LegoWorld();
  __declspec(dllexport) virtual ~LegoWorld(); // vtable+0x0
};

#endif // LEGOWORLD_H
