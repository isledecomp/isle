#ifndef SCORESTATE_H
#define SCORESTATE_H

#include "legostate.h"

// VTABLE 0x100d53f8
// SIZE 0xc
class ScoreState : public LegoState
{
public:
  // OFFSET: LEGO1 0x1000de40
  inline virtual const char *ClassName() const override // vtable+0x0c
  { 
    // 0x100f0084
    return "ScoreState";
  }; 

  // OFFSET: LEGO1 0x1000de50
  inline virtual MxBool IsA(const char *name) const override // vtable+0x10
  {
    return !strcmp(name, ScoreState::ClassName()) || LegoState::IsA(name);
  };

  virtual MxBool VTable0x14() override; // vtable+0x14
  virtual MxBool SetFlag() override; // vtable+0x18

  inline MxBool GetTutorialFlag() { return m_playCubeTutorial; }
  inline void SetTutorialFlag(MxBool p_playCubeTutorial) { m_playCubeTutorial = p_playCubeTutorial; }

private:
  MxBool m_playCubeTutorial;
};

#endif // SCORESTATE_H
