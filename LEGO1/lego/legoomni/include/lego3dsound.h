#ifndef LEGO3DSOUND_H
#define LEGO3DSOUND_H

#include "decomp.h"
#include "mxtypes.h"

#include <dsound.h>

class LegoROI;

// VTABLE: LEGO1 0x100d5778
// SIZE 0x30
class Lego3DSound {
public:
	Lego3DSound();
	virtual ~Lego3DSound();

	void Init();
	MxResult Create(LPDIRECTSOUNDBUFFER p_directSoundBuffer, const char*, MxS32 p_volume);
	void Destroy();
	undefined4 FUN_100118e0(LPDIRECTSOUNDBUFFER p_directSoundBuffer);
	void FUN_10011ca0();
	MxS32 FUN_10011cf0(undefined4, undefined4);

	// SYNTHETIC: LEGO1 0x10011650
	// Lego3DSound::`scalar deleting destructor'

private:
	undefined m_unk0x04[4];         // 0x04
	LPDIRECTSOUNDBUFFER m_dsBuffer; // 0x08
	LegoROI* m_unk0x0c;             // 0x0c
	undefined4 m_unk0x10;           // 0x10
	MxBool m_unk0x14;               // 0x14
	MxBool m_unk0x15;               // 0x15
	undefined4 m_unk0x18;           // 0x18
	undefined m_unk0x1c[0x10];      // 0x1c
	MxS32 m_volume;                 // 0x2c
};

#endif // LEGO3DSOUND_H
