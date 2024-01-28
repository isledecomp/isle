#ifndef LEGOSOUNDMANAGER_H
#define LEGOSOUNDMANAGER_H

#include "legounknown100d6b4c.h"
#include "mxsoundmanager.h"

// VTABLE: LEGO1 0x100d6b10
// SIZE 0x44
class LegoSoundManager : public MxSoundManager {
public:
	LegoSoundManager();
	virtual ~LegoSoundManager() override;

	virtual MxResult Tickle() override;                                           // vtable+08
	virtual void Destroy() override;                                              // vtable+18
	virtual MxResult Create(MxU32 p_frequencyMS, MxBool p_createThread) override; // vtable+0x30

	// SYNTHETIC: LEGO1 0x10029920
	// LegoSoundManager::`scalar deleting destructor'

	inline LegoUnknown100d6b4c* GetUnknown0x40() { return m_unk0x40; }

private:
	void Init();
	void Destroy(MxBool p_fromDestructor);

	undefined4 m_unk0x3c;           // 0x3c
	LegoUnknown100d6b4c* m_unk0x40; // 0x40
};

#endif // LEGOSOUNDMANAGER_H
