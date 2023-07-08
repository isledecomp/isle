#ifndef PIZZA_H
#define PIZZA_H

#include "decomp.h"
#include "isleactor.h"
#include "mxtypes.h"

// VTABLE 0x100d7380
// SIZE 0x9c
class Pizza : public IsleActor
{
public:
  Pizza();
  virtual ~Pizza() override;

  Pizza* Unk1002c7b0(undefined4 p_param);
private:
  undefined4 m_unk80;
  undefined4 m_unk84;
  undefined4 m_unk88;
  undefined4 m_unk8c;
  undefined4 m_unk90;
  undefined4 m_unk98;
};

#endif // PIZZA_H
