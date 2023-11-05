#ifndef MXBACKGROUNDAUDIOMANAGER_H
#define MXBACKGROUNDAUDIOMANAGER_H

#include "mxaudiopresenter.h"
#include "mxcore.h"
#include "mxdsaction.h"
#include "mxnotificationmanager.h"
#include "mxpresenter.h"
#include "mxtypes.h"

// VTABLE 0x100d9fe8
// SIZE 0x150
class MxBackgroundAudioManager : public MxCore {
public:
	MxBackgroundAudioManager();
	virtual ~MxBackgroundAudioManager() override;

	// OFFSET: LEGO1 0x1007eb70
	inline virtual const char* ClassName() const override // vtable+0x0c
	{
		// 0x100f7ac4
		return "MxBackgroundAudioManager";
	}

	// OFFSET: LEGO1 0x1007eb80
	inline virtual MxBool IsA(const char* name) const override // vtable+0x10
	{
		return !strcmp(name, MxBackgroundAudioManager::ClassName()) || MxCore::IsA(name);
	}

	virtual MxResult Notify(MxParam& p) override;

	void StartAction(MxParam& p);
	void StopAction(MxParam& p);
	MxResult PlayMusic(MxDSAction& p_action, undefined4 p_unknown, undefined4 p_unknown2);

	virtual MxResult Tickle() override;
	void FUN_1007ee70();
	void FUN_1007ef40();
	void FadeInOrFadeOut();

	__declspec(dllexport) void Enable(unsigned char p);
	virtual MxResult Create(MxAtomId& p_script, MxU32 p_frequencyMS);

	void Stop();
	void FUN_1007f570();
	void FUN_1007f5b0();

private:
	void Init();
	MxResult OpenMusic(MxAtomId& p_script);
	void DestroyMusic();

	MxBool m_musicEnabled; // 0x8
	MxDSAction m_action1;  // 0xc
	MxAudioPresenter* m_unka0;
	MxDSAction m_action2; // 0xa4
	MxAudioPresenter* m_unk138;
	MxS32 m_unk13c;
	MxS32 m_unk140;
	MxS32 m_targetVolume;
	MxS16 m_unk148;
	MxAtomId m_script;
};

#endif // MXBACKGROUNDAUDIOMANAGER_H
