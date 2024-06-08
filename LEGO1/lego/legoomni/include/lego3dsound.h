#ifndef LEGO3DSOUND_H
#define LEGO3DSOUND_H

#include "decomp.h"
#include "mxtypes.h"

#include <dsound.h>

class LegoActor;
class LegoROI;

// VTABLE: LEGO1 0x100d5778
// SIZE 0x30
class Lego3DSound {
public:
	Lego3DSound();
	virtual ~Lego3DSound();

	void Init();
	MxResult Create(LPDIRECTSOUNDBUFFER p_directSoundBuffer, const char* p_name, MxS32 p_volume);
	void Destroy();
	MxU32 UpdatePosition(LPDIRECTSOUNDBUFFER p_directSoundBuffer);
	void FUN_10011a60(LPDIRECTSOUNDBUFFER p_directSoundBuffer, const char* p_name);
	void Reset();
	MxS32 SetDistance(MxS32 p_min, MxS32 p_max);

	// SYNTHETIC: LEGO1 0x10011650
	// Lego3DSound::`scalar deleting destructor'

private:
	LPDIRECTSOUND3DBUFFER m_ds3dBuffer; // 0x08
	LegoROI* m_roi;                     // 0x0c
	LegoROI* m_positionROI;             // 0x10
	MxBool m_enabled;                   // 0x14
	MxBool m_isActor;                   // 0x15
	LegoActor* m_actor;                 // 0x18
	double m_frequencyFactor;           // 0x20
	DWORD m_dwFrequency;                // 0x28
	MxS32 m_volume;                     // 0x2c
};

// GLOBAL: LEGO1 0x100db6c0
// IID_IDirectSound3DBuffer

#endif // LEGO3DSOUND_H
