#ifndef LEGOENTITY_H
#define LEGOENTITY_H

#include "mxentity.h"

// VTABLE 0x100d4858
class LegoEntity : public MxEntity
{
public:
  // Inlined at 0x100853f7
  inline LegoEntity()
  {
    // TODO
  }

  __declspec(dllexport) virtual ~LegoEntity() override; // vtable+0x0

  virtual long Notify(MxParam &p) override; // vtable+0x4

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

  virtual void Destroy() override; // vtable+0x1c

};

#endif // LEGOENTITY_H
