#ifndef LEGOWORLD_H
#define LEGOWORLD_H

#include "legoentity.h"

class LegoWorld : public LegoEntity
{
public:
  __declspec(dllexport) LegoWorld();
  __declspec(dllexport) virtual ~LegoWorld();
};

#endif // LEGOWORLD_H
