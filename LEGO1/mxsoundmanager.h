#ifndef MXSOUNDMANAGER_H
#define MXSOUNDMANAGER_H

#include "decomp.h"
#include "mxatomid.h"
#include "mxaudiomanager.h"

#include <dsound.h>

// VTABLE 0x100dc128
// SIZE 0x3c
class MxSoundManager : public MxAudioManager {
public:
	MxSoundManager();

	// OFFSET: LEGO1 0x100ae7b0 TEMPLATE
	// MxSoundManager::`scalar deleting destructor'
	virtual ~MxSoundManager() override; // vtable+0x0

	virtual void Destroy() override;                                     // vtable+18
	virtual void SetVolume(MxS32 p_volume) override;                     // vtable+2c
	virtual MxResult Create(MxU32 p_frequencyMS, MxBool p_createThread); // vtable+0x30
	virtual void vtable0x34();                                           // vtable+0x34
	virtual void vtable0x38();                                           // vtable+0x38

	inline LPDIRECTSOUND GetDirectSound() { return m_directSound; }

private:
	void Init();
	void Destroy(MxBool p_fromDestructor);
	MxPresenter* FUN_100aebd0(const MxAtomId& p_atomId, MxU32 p_objectId);
	MxS32 FUN_100aecf0(MxU32 p_unk);

	LPDIRECTSOUND m_directSound;    // 0x30
	LPDIRECTSOUNDBUFFER m_dsBuffer; // 0x34
	undefined m_unk38[4];
};

#endif // MXSOUNDMANAGER_H
