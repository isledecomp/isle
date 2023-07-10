#ifndef INFOCENTERSTATE_H
#define INFOCENTERSTATE_H

#include "legostate.h"

// VTABLE 0x100d93a8
// SIZE 0x94
class InfocenterState : public LegoState
{
public:
  InfocenterState();
  virtual ~InfocenterState();

  // OFFSET: LEGO1 0x10071840
  inline virtual const char *ClassName() const override // vtable+0x0c
  { 
    // 0x100f04dc
    return "InfocenterState";
  }

  // OFFSET: LEGO1 0x10071850
  inline virtual MxBool IsA(const char *name) const override // vtable+0x10
  {
    return !strcmp(name, InfocenterState::ClassName()) || LegoState::IsA(name);
  }

  inline MxU32 GetSomething(int p_index) { return m_buffer[p_index]; }
  inline void SetSomething(int p_index, MxU32 p_value) { m_buffer[p_index] = p_value; }

private:
  // Size: 0xC
  struct SomeStruct
  {
    MxU32 unk1;
    MxU16 unk2;
    MxU16 unk3;
    MxU16 unk4;
    MxU16 padding;
  };

  MxU16 unk1;
  MxU16 unk2;
  MxU32 unk3;
  MxU32 padding1;
  void *unk4;
  MxU16 unk5;
  MxU16 unk6;
  MxU16 unk7;
  MxU16 padding2;
  void *unk8;
  MxU16 unk9;
  MxU16 unk10;
  MxU16 unk11;
  MxU16 padding3;
  SomeStruct unk12[6];
  MxU32 unk13;
  MxU32 m_buffer[7];
};

#endif // INFOCENTERSTATE_H
