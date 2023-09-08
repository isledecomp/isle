#ifndef MXVIDEOPARAMFLAGS_H
#define MXVIDEOPARAMFLAGS_H

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include <windows.h>

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
  inline void Set16Bit(BYTE e)         { m_flags1.bit5 = e; }
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

  inline BYTE GetFullScreen()    { return m_flags1.bit0; }
  inline BYTE GetFlipSurfaces()  { return m_flags1.bit1; }
  inline BYTE GetBackBuffers()   { return m_flags1.bit2; }
  inline BYTE Get_f1bit3()       { return m_flags1.bit3; }
  inline BYTE Get_f1bit4()       { return m_flags1.bit4; }
  inline BYTE Get16Bit()         { return m_flags1.bit5; }
  inline BYTE GetWideViewAngle() { return m_flags1.bit6; }
  inline BYTE Get_f1bit7()       { return m_flags1.bit7; }
  inline BYTE Get_f2bit0()       { return m_flags2.bit0; }
  inline BYTE Get_f2bit1()       { return m_flags2.bit1; }
  inline BYTE Get_f2bit2()       { return m_flags2.bit2; }
  inline BYTE Get_f2bit3()       { return m_flags2.bit3; }
  inline BYTE Get_f2bit4()       { return m_flags2.bit4; }
  inline BYTE Get_f2bit5()       { return m_flags2.bit5; }
  inline BYTE Get_f2bit6()       { return m_flags2.bit6; }
  inline BYTE Get_f2bit7()       { return m_flags2.bit7; }

private:
  flag_bitfield m_flags1;
  flag_bitfield m_flags2;

};

#endif // MXVIDEOPARAMFLAGS_H
