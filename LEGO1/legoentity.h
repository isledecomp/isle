#ifndef LEGOENTITY_H
#define LEGOENTITY_H

#include "mxentity.h"
#include "extra.h"

// VTABLE 0x100d4858
// SIZE 0x68 (probably)
class LegoEntity : public MxEntity
{
public:
  // Inlined at 0x100853f7
  inline LegoEntity()
  {
    // TODO
  }

  __declspec(dllexport) virtual ~LegoEntity() override; // vtable+0x0

  virtual MxLong Notify(MxParam &p) override; // vtable+0x4

  // OFFSET: LEGO1 0x1000c2f0
  inline const char *ClassName() const override // vtable+0xc
  {
    // 0x100f0064
    return "LegoEntity";
  }

  // OFFSET: LEGO1 0x1000c300
  inline MxBool IsA(const char *name) const override // vtable+0x10
  {
    return !strcmp(name, LegoEntity::ClassName()) || MxEntity::IsA(name);
  }

  virtual void vtable18(); // vtable+0x18
  virtual void Destroy() override; // vtable+0x1c
  virtual void ParseAction(char *); // vtable+0x20

protected:
  // For tokens from the extra string that look like this:
  // "Action:openram;\lego\scripts\Race\CarRaceR;0"
  ExtraActionType m_actionType; // 0x5c
  char *m_actionArgString; // 0x60
  MxS32 m_actionArgNumber; // 0x64

};

#endif // LEGOENTITY_H
