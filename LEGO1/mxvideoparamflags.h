#ifndef MXVIDEOPARAMFLAGS_H
#define MXVIDEOPARAMFLAGS_H

#include "legoinc.h"

// Must be union with struct for match.
typedef union {
  struct {
    BYTE bit0: 1;
    BYTE bit1: 1;
    BYTE bit2: 1;
    BYTE bit3: 1;
    BYTE bit4: 1;
    BYTE bit5: 1;
    BYTE bit6: 1;
    BYTE bit7: 1;
  };
  // BYTE all; // ?
} flag_bitfield;

class MxVideoParamFlags
{
public:
  __declspec(dllexport) MxVideoParamFlags();

  inline void SetFullScreen(BOOL e)    { m_flags1.bit0 = e; }
  inline void SetFlipSurfaces(BOOL e)  { m_flags1.bit1 = e; }
  inline void SetBackBuffers(BOOL e)   { m_flags1.bit2 = e; }
  inline void Set_f1bit3(BOOL e)       { m_flags1.bit3 = e; }
  inline void Set_f1bit4(BOOL e)       { m_flags1.bit4 = e; }
  inline void Set16Bit(BOOL e)         { m_flags1.bit5 = e; }
  inline void SetWideViewAngle(BOOL e) { m_flags1.bit6 = e; }
  inline void Set_f1bit7(BOOL e)       { m_flags1.bit7 = e; }
  inline void Set_f2bit0(BOOL e)       { m_flags2.bit0 = e; }
  inline void Set_f2bit1(BOOL e)       { m_flags2.bit1 = e; }
  inline void Set_f2bit2(BOOL e)       { m_flags2.bit2 = e; }
  inline void Set_f2bit3(BOOL e)       { m_flags2.bit3 = e; }
  inline void Set_f2bit4(BOOL e)       { m_flags2.bit4 = e; }
  inline void Set_f2bit5(BOOL e)       { m_flags2.bit5 = e; }
  inline void Set_f2bit6(BOOL e)       { m_flags2.bit6 = e; }
  inline void Set_f2bit7(BOOL e)       { m_flags2.bit7 = e; }

private:
  flag_bitfield m_flags1;
  flag_bitfield m_flags2;

};

#endif // MXVIDEOPARAMFLAGS_H
