#ifndef MXBACKGROUNDAUDIOMANAGER_H
#define MXBACKGROUNDAUDIOMANAGER_H

#include "mxaudiopresenter.h"
#include "mxcore.h"
#include "mxdsaction.h"
#include "mxnotificationmanager.h"
#include "mxpresenter.h"
#include "mxtypes.h"

// VTABLE: LEGO1 0x100d9fe8
// SIZE 0x150
class MxBackgroundAudioManager : public MxCore {
public:
	MxBackgroundAudioManager();
	virtual ~MxBackgroundAudioManager() override;

	virtual MxLong Notify(MxParam& p_param) override; // vtable+0x04
	virtual MxResult Tickle() override;               // vtable+0x08

	// FUNCTION: LEGO1 0x1007eb70
	inline virtual const char* ClassName() const override // vtable+0x0c
	{
		// STRING: LEGO1 0x100f7ac4
		return "MxBackgroundAudioManager";
	}

	// FUNCTION: LEGO1 0x1007eb80
	inline virtual MxBool IsA(const char* p_name) const override // vtable+0x10
	{
		return !strcmp(p_name, MxBackgroundAudioManager::ClassName()) || MxCore::IsA(p_name);
	}

	void StartAction(MxParam& p_param);
	void StopAction(MxParam& p_param);
	MxResult PlayMusic(MxDSAction& p_action, undefined4 p_unk0x140, undefined4 p_unk0x13c);

	void FUN_1007ee70();
	void FUN_1007ef40();
	void FadeInOrFadeOut();

	__declspec(dllexport) void Enable(MxBool p_enable);
	virtual MxResult Create(MxAtomId& p_script, MxU32 p_frequencyMS);

	void Stop();
	void LowerVolume();
	void RaiseVolume();

private:
	void Init();
	MxResult OpenMusic(MxAtomId& p_script);
	void DestroyMusic();

	MxBool m_musicEnabled; // 0x8
	MxDSAction m_action1;  // 0xc
	MxAudioPresenter* m_unk0xa0;
	MxDSAction m_action2; // 0xa4
	MxAudioPresenter* m_unk0x138;
	MxS32 m_unk0x13c;
	MxS32 m_unk0x140;
	MxS32 m_targetVolume;
	MxS16 m_unk0x148;
	MxAtomId m_script;
};

#endif // MXBACKGROUNDAUDIOMANAGER_H
