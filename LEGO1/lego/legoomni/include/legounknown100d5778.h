#ifndef LEGOUNKNOWN100D5778_H
#define LEGOUNKNOWN100D5778_H

#include "decomp.h"
#include "mxtypes.h"
#include "roi/legoroi.h"

#include <dsound.h>

// VTABLE: LEGO1 0x100d5778
// SIZE 0x30
class LegoUnknown100d5778 {
public:
	LegoUnknown100d5778();
	virtual ~LegoUnknown100d5778();

	void Init();
	MxResult FUN_100116a0(LPDIRECTSOUND p_dsound, undefined4, undefined4 p_unk0x2c);
	void Destroy();
	undefined4 FUN_100118e0(LPDIRECTSOUNDBUFFER p_dsBuffer);
	void FUN_10011ca0();

	// SYNTHETIC: LEGO1 0x10011650
	// LegoUnknown100d5778::`scalar deleting destructor'

private:
	undefined m_unk0x4[4];          // 0x04
	LPDIRECTSOUNDBUFFER m_dsBuffer; // 0x08
	LegoROI* m_unk0xc;              // 0x0c
	undefined4 m_unk0x10;           // 0x10
	MxBool m_unk0x14;               // 0x14
	MxBool m_unk0x15;               // 0x15
	undefined4 m_unk0x18;           // 0x18
	undefined m_unk0x1c[0x10];      // 0x1c
	undefined4 m_unk0x2c;           // 0x2c
};

#endif // LEGOUNKNOWN100D5778_H
