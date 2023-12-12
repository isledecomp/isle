#ifndef MXVIDEOPARAMFLAGS_H
#define MXVIDEOPARAMFLAGS_H

#include "mxtypes.h"

#include <windows.h>

class MxVideoParamFlags {
public:
	__declspec(dllexport) MxVideoParamFlags();

	inline void SetFullScreen(BOOL p_e) { m_flags1.m_bit0 = p_e; }
	inline void SetFlipSurfaces(BOOL p_e) { m_flags1.m_bit1 = p_e; }
	inline void SetBackBuffers(BOOL p_e) { m_flags1.m_bit2 = p_e; }
	inline void SetF1bit3(BOOL p_e) { m_flags1.m_bit3 = p_e; }
	inline void SetF1bit4(BOOL p_e) { m_flags1.m_bit4 = p_e; }
	inline void Set16Bit(BYTE p_e) { m_flags1.m_bit5 = p_e; }
	inline void SetWideViewAngle(BOOL p_e) { m_flags1.m_bit6 = p_e; }
	inline void SetF1bit7(BOOL p_e) { m_flags1.m_bit7 = p_e; }
	inline void SetF2bit0(BOOL p_e) { m_flags2.m_bit0 = p_e; }
	inline void SetF2bit1(BOOL p_e) { m_flags2.m_bit1 = p_e; }
	inline void SetF2bit2(BOOL p_e) { m_flags2.m_bit2 = p_e; }
	inline void SetF2bit3(BOOL p_e) { m_flags2.m_bit3 = p_e; }
	inline void SetF2bit4(BOOL p_e) { m_flags2.m_bit4 = p_e; }
	inline void SetF2bit5(BOOL p_e) { m_flags2.m_bit5 = p_e; }
	inline void SetF2bit6(BOOL p_e) { m_flags2.m_bit6 = p_e; }
	inline void SetF2bit7(BOOL p_e) { m_flags2.m_bit7 = p_e; }

	inline BYTE GetFullScreen() { return m_flags1.m_bit0; }
	inline BYTE GetFlipSurfaces() { return m_flags1.m_bit1; }
	inline BYTE GetBackBuffers() { return m_flags1.m_bit2; }
	inline BYTE GetF1bit3() { return m_flags1.m_bit3; }
	inline BYTE GetF1bit4() { return m_flags1.m_bit4; }
	inline BYTE Get16Bit() { return m_flags1.m_bit5; }
	inline BYTE GetWideViewAngle() { return m_flags1.m_bit6; }
	inline BYTE GetF1bit7() { return m_flags1.m_bit7; }
	inline BYTE GetF2bit0() { return m_flags2.m_bit0; }
	inline BYTE GetF2bit1() { return m_flags2.m_bit1; }
	inline BYTE GetF2bit2() { return m_flags2.m_bit2; }
	inline BYTE GetF2bit3() { return m_flags2.m_bit3; }
	inline BYTE GetF2bit4() { return m_flags2.m_bit4; }
	inline BYTE GetF2bit5() { return m_flags2.m_bit5; }
	inline BYTE GetF2bit6() { return m_flags2.m_bit6; }
	inline BYTE GetF2bit7() { return m_flags2.m_bit7; }

private:
	FlagBitfield m_flags1;
	FlagBitfield m_flags2;
};

#endif // MXVIDEOPARAMFLAGS_H
