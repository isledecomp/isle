#ifndef LEGOSOUNDMANAGER_H
#define LEGOSOUNDMANAGER_H

#include "legounknown100d6b4c.h"
#include "mxsoundmanager.h"

// VTABLE: LEGO1 0x100d6b10
// SIZE 0x44
class LegoSoundManager : public MxSoundManager {
public:
	LegoSoundManager();
	~LegoSoundManager() override;

	MxResult Tickle() override;                                           // vtable+08
	void Destroy() override;                                              // vtable+18
	MxResult Create(MxU32 p_frequencyMS, MxBool p_createThread) override; // vtable+0x30

	// SYNTHETIC: LEGO1 0x10029920
	// LegoSoundManager::`scalar deleting destructor'

	inline LegoUnknown100d6b4c* GetUnknown0x40() { return m_unk0x40; }

private:
	void Init();
	void Destroy(MxBool p_fromDestructor);

	LPDIRECTSOUND3DLISTENER m_listener; // 0x3c
	LegoUnknown100d6b4c* m_unk0x40;     // 0x40
};

// GLOBAL: LEGO1 0x100db6d0
// IID_IDirectSound3DListener

#endif // LEGOSOUNDMANAGER_H
