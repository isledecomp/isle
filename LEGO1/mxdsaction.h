#ifndef MXDSACTION_H
#define MXDSACTION_H

#include "mxdsobject.h"
#include "mxvector.h"
#include "mxomni.h"

// VTABLE 0x100dc098
// SIZE 0x94
class MxDSAction : public MxDSObject
{
public:
  __declspec(dllexport) MxDSAction();
  __declspec(dllexport) virtual ~MxDSAction();

  // OFFSET: LEGO1 0x100ad980
  inline virtual const char *ClassName() const override // vtable+0x0c
  {
    // 0x101013f4
    return "MxDSAction";
  }

  // OFFSET: LEGO1 0x100ad990
  inline virtual MxBool IsA(const char *name) const override // vtable+0x10
  {
    return !strcmp(name, MxDSAction::ClassName()) || MxDSObject::IsA(name);
  }
private:
  undefined4 m_unk2c;
  DWORD m_flags;
  DWORD m_startTime;
  LONG m_duration;
  MxS32 m_loopCount;
  MxVector3Data m_location;
  MxVector3Data m_direction;
  MxVector3Data m_up;
  undefined4 *m_unk7c;
  undefined2 m_unk80;
  undefined4 m_unk84;
  undefined4 m_unk88;
  MxOmni* m_omni; // 0x8c
  MxS32 m_someTimingField; // 0x90
};

#endif // MXDSACTION_H
