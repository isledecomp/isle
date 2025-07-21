#ifndef MXVIDEOPARAMFLAGS_H
#define MXVIDEOPARAMFLAGS_H

#include "mxtypes.h"

#include <windows.h>

class MxVideoParamFlags {
public:
	MxVideoParamFlags();

	// inlined in ISLE
	void SetFullScreen(MxBool p_e) { m_flags1.m_bit0 = p_e; }

	// FUNCTION: BETA10 0x10141f80
	void SetFlipSurfaces(MxBool p_e) { m_flags1.m_bit1 = p_e; }

	// FUNCTION: BETA10 0x10141fb0
	void SetBackBuffers(MxBool p_e) { m_flags1.m_bit2 = p_e; }

	// FUNCTION: BETA10 0x100d9250
	void SetDoubleScaling(MxBool p_e) { m_flags1.m_bit3 = p_e; }

	// inlined in ISLE
	void Set16Bit(MxBool p_e) { m_flags1.m_bit5 = p_e; }

	// inlined in ISLE
	void SetWideViewAngle(MxBool p_e) { m_flags1.m_bit6 = p_e; }

	// inlined in ISLE
	void SetF1bit7(MxBool p_e) { m_flags1.m_bit7 = p_e; }

	// FUNCTION: BETA10 0x100d81b0
	void SetLacksLightSupport(MxBool p_e) { m_flags2.m_bit0 = p_e; }

	// inlined in ISLE
	void SetEnabled(MxBool p_e) { m_flags2.m_bit1 = p_e; }

	// FUNCTION: BETA10 0x1009e770
	MxBool GetFullScreen() { return m_flags1.m_bit0; }

	// FUNCTION: BETA10 0x100d80f0
	MxBool GetFlipSurfaces() { return m_flags1.m_bit1; }

	// FUNCTION: BETA10 0x100d8120
	MxBool GetBackBuffers() { return m_flags1.m_bit2; }

	// FUNCTION: BETA10 0x10142010
	MxBool GetDoubleScaling() { return m_flags1.m_bit3; }

	// FUNCTION: BETA10 0x100d8150
	MxBool Get16Bit() { return m_flags1.m_bit5; }

	// FUNCTION: BETA10 0x100d8180
	MxBool GetWideViewAngle() { return m_flags1.m_bit6; }

	// FUNCTION: BETA10 0x100886b0
	MxBool GetLacksLightSupport() { return m_flags2.m_bit0; }

	// FUNCTION: BETA10 0x10142050
	MxBool GetEnabled() { return m_flags2.m_bit1; }

private:
	FlagBitfield m_flags1;
	FlagBitfield m_flags2;
};

#endif // MXVIDEOPARAMFLAGS_H
