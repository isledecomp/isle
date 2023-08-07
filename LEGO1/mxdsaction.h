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

  void CopyFrom(MxDSAction &p_dsAction);
  MxDSAction &operator=(MxDSAction &p_dsAction);

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

  virtual MxU32 GetSizeOnDisk(); // vtable+18;
  virtual void Deserialize(char **p_source, MxS16 p_unk24); // vtable+1c;
  virtual MxLong GetDuration(); // vtable+24;
  virtual void SetDuration(LONG p_duration); // vtable+28;
  virtual MxDSAction *Clone(); // vtable+2c;
  virtual void MergeFrom(MxDSAction &p_dsAction); // vtable+30;
  virtual MxBool HasId(MxU32 p_objectId); // vtable+34;
  virtual void SetSomeTimingField(MxLong p_someTimingField); // vtable+38;
  virtual MxLong GetSomeTimingField(); // vtable+3c;
  virtual MxLong GetCurrentTime(); // vtable+40;

  void FUN_100ADE60(MxU16 p_length, void *p_data);

private:
  undefined4 m_sizeOnDisk;
  DWORD m_flags;
  DWORD m_startTime;
  MxLong m_duration;
  MxS32 m_loopCount;
  MxVector3Data m_location;
  MxVector3Data m_direction;
  MxVector3Data m_up;
  undefined4 *m_unk7c;
  MxU16 m_unk80;
  undefined4 m_unk84;
  undefined4 m_unk88;
  MxOmni* m_omni; // 0x8c
  MxLong m_someTimingField; // 0x90
};

#endif // MXDSACTION_H
