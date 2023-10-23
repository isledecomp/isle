#ifndef ISLEPATHACTOR_H
#define ISLEPATHACTOR_H

#include "legopathactor.h"
#include "legoworld.h"
#include "mxtypes.h"

// VTABLE 0x100d4398
// SIZE 0x160
class IslePathActor : public LegoPathActor
{
public: 
  IslePathActor();

  // OFFSET: LEGO1 0x10002ea0
  inline virtual const char *ClassName() const override // vtable+0x0c
  {
    // 0x100f0104
    return "IslePathActor";
  }

  // OFFSET: LEGO1 0x10002eb0
  inline virtual MxBool IsA(const char *name) const override // vtable+0x10
  {
    return !strcmp(name, IslePathActor::ClassName()) || LegoPathActor::IsA(name);
  }

  // OFFSET: LEGO1 0x10002ff0 TEMPLATE
  // IslePathActor::`scalar deleting destructor'
  inline virtual ~IslePathActor()
  {
    IslePathActor::Destroy(TRUE);
  }

  virtual MxResult InitFromMxDSObject(MxDSObject &p_dsObject) override; // vtable+0x18
  
  inline void SetWorld(LegoWorld *p_world) { m_pLegoWorld = p_world; }
  inline LegoWorld *GetWorld() { return m_pLegoWorld; }
  
private:
  LegoWorld *m_pLegoWorld; // 0x154
  MxFloat m_unk158;
  MxFloat m_unk15c;
};

#endif // ISLEPATHACTOR_H
