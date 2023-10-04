#ifndef MXDSACTION_H
#define MXDSACTION_H

#include "mxdsobject.h"
#include "mxtypes.h"
#include "mxvector.h"

class MxOmni;

// VTABLE 0x100dc098
// SIZE 0x94
class MxDSAction : public MxDSObject
{
public:
  enum
  {
    Flag_Looping = 0x01,
    Flag_Bit3 = 0x04,
    Flag_Enabled = 0x20,
    Flag_Parsed = 0x80,
  };

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
  virtual void SetDuration(MxLong p_duration); // vtable+28;
  virtual MxDSAction *Clone(); // vtable+2c;
  virtual void MergeFrom(MxDSAction &p_dsAction); // vtable+30;
  virtual MxBool HasId(MxU32 p_objectId); // vtable+34;
  virtual void SetSomeTimingField(MxLong p_someTimingField); // vtable+38;
  virtual MxLong GetSomeTimingField(); // vtable+3c;
  virtual MxLong GetCurrentTime(); // vtable+40;

  void AppendData(MxU16 p_extraLength, const char *p_extraData);

  inline MxU32 GetFlags() { return this->m_flags; } 
  inline void SetFlags(MxU32 m_flags) { this->m_flags = m_flags; }
  inline char *GetExtraData() { return m_extraData; }
  inline MxU16 GetExtraLength() const { return m_extraLength; }
  inline MxLong GetStartTime() const { return m_startTime; }
  inline MxS32 GetLoopCount() { return m_loopCount; }
  inline void SetLoopCount(MxS32 m_loopCount) { this->m_loopCount = m_loopCount; }
  inline const MxVector3Data &GetLocation() const { return m_location; }
  inline void SetOmni(MxOmni *p_omni) { m_omni = p_omni; }

  inline MxBool IsLooping() const { return this->m_flags & Flag_Looping; }
  inline MxBool IsBit3() const { return this->m_flags & Flag_Bit3; }

private:
  MxU32 m_sizeOnDisk;
  MxU32 m_flags;
  MxLong m_startTime;

protected:
  MxLong m_duration;
  MxS32 m_loopCount;

private:
  MxVector3Data m_location;
  MxVector3Data m_direction;
  MxVector3Data m_up;
  char *m_extraData;
  MxU16 m_extraLength;
  undefined4 m_unk84;
  undefined4 m_unk88;
  MxOmni *m_omni; // 0x8c

protected:
  MxLong m_someTimingField; // 0x90
};

#endif // MXDSACTION_H
