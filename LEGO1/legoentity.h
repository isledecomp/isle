#ifndef LEGOENTITY_H
#define LEGOENTITY_H

class LegoEntity
{
public:
  __declspec(dllexport) virtual ~LegoEntity();
  const char* GetClassName();
};

#endif // LEGOENTITY_H
