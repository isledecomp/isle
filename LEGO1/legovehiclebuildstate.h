#ifndef LEGOVEHICLEBUILDSTATE_H
#define LEGOVEHICLEBUILDSTATE_H

#include "legostate.h"
#include "mxstring.h"
#include "decomp.h"

#include "decomp.h"

// VTABLE 0x100d66e0
// SIZE 0x50 (from 1000acd7)
class LegoVehicleBuildState : public LegoState
{
public:
  LegoVehicleBuildState(char* p_classType);

  // OFFSET: LEGO1 0x10025ff0
  inline virtual const char *ClassName() const override // vtable+0x0c
  {
    return this->m_className.GetData();
  }

  // OFFSET: LEGO1 0x10026000
  inline virtual MxBool IsA(const char *p_name) const override // vtable+0x10
  {
    return !strcmp(p_name, this->m_className.GetData()) || LegoState::IsA(p_name);
  }

public:
  struct UnkStruct
  {
    undefined4 m_unk0;
    undefined2 m_unk1;
    undefined2 m_unk2;
    undefined2 m_unk3;
    undefined2 _padding;

    UnkStruct();
  };
private:
  UnkStruct m_unk0[4]; // 0x08

  // This can be one of the following:
  // * LegoRaceCarBuildState
  // * LegoCopterBuildState
  // * LegoDuneCarBuildState
  // * LegoJetskiBuildState
  MxString m_className; // 0x38

  // Known States:
  // * 1 == enter(ing) build screen
  // * 3 == cutscene/dialogue
  // * 6 == exit(ing) build screen
  MxU32 m_animationState; // 0x48
  undefined m_unk2; // 0x4c
  undefined m_unk3; // 0x4d
  undefined m_unk4; // 0x4e
  MxU8 m_placedPartCount; // 0x4f
};

#endif // LEGOVEHICLEBUILDSTATE_H
