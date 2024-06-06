#ifndef MXVIDEOPARAMFLAGS_H
#define MXVIDEOPARAMFLAGS_H

#include "mxtypes.h"

#include <windows.h>

class MxVideoParamFlags {
public:
	MxVideoParamFlags();

	// inlined in ISLE
	inline void SetFullScreen(MxBool p_e) { m_flags1.m_bit0 = p_e; }

	// FUNCTION: BETA10 0x10141f80
	inline void SetFlipSurfaces(MxBool p_e) { m_flags1.m_bit1 = p_e; }

	// FUNCTION: BETA10 0x10141fb0
	inline void SetBackBuffers(MxBool p_e) { m_flags1.m_bit2 = p_e; }

	// FUNCTION: BETA10 0x100d9250
	inline void SetF1bit3(MxBool p_e) { m_flags1.m_bit3 = p_e; }

	// inlined in ISLE
	inline void Set16Bit(MxBool p_e) { m_flags1.m_bit5 = p_e; }

	// inlined in ISLE
	inline void SetWideViewAngle(MxBool p_e) { m_flags1.m_bit6 = p_e; }

	// inlined in ISLE
	inline void SetF1bit7(MxBool p_e) { m_flags1.m_bit7 = p_e; }

	// FUNCTION: BETA10 0x100d81b0
	inline void SetF2bit0(MxBool p_e) { m_flags2.m_bit0 = p_e; }

	// inlined in ISLE
	inline void SetF2bit1(MxBool p_e) { m_flags2.m_bit1 = p_e; }

	// FUNCTION: BETA10 0x1009e770
	inline MxBool GetFullScreen() { return m_flags1.m_bit0; }

	// FUNCTION: BETA10 0x100d80f0
	inline MxBool GetFlipSurfaces() { return m_flags1.m_bit1; }

	// FUNCTION: BETA10 0x100d8120
	inline MxBool GetBackBuffers() { return m_flags1.m_bit2; }

	// FUNCTION: BETA10 0x10142010
	inline MxBool GetF1bit3() { return m_flags1.m_bit3; }

	// FUNCTION: BETA10 0x100d8150
	inline MxBool Get16Bit() { return m_flags1.m_bit5; }

	// FUNCTION: BETA10 0x100d8180
	inline MxBool GetWideViewAngle() { return m_flags1.m_bit6; }

	// FUNCTION: BETA10 0x100886b0
	inline MxBool GetF2bit0() { return m_flags2.m_bit0; }

	// FUNCTION: BETA10 0x10142050
	inline MxBool GetF2bit1() { return m_flags2.m_bit1; }

private:
	FlagBitfield m_flags1;
	FlagBitfield m_flags2;
};

#endif // MXVIDEOPARAMFLAGS_H
