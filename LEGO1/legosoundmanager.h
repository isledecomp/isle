#ifndef LEGOSOUNDMANAGER_H
#define LEGOSOUNDMANAGER_H

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

private:
	void Init();
	void Destroy(MxBool p_fromDestructor);

	IDirectSound3DListener* m_listener;
	LegoSoundManagerSubclass* m_unk0x40;
};

// VTABLE: LEGO1 0x100d6b4c
// SIZE 0x20
class LegoSoundManagerSubclass
{

};

#endif // LEGOSOUNDMANAGER_H
