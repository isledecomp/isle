#ifndef MXBACKGROUNDAUDIOMANAGER_H
#define MXBACKGROUNDAUDIOMANAGER_H

#include "mxcore.h"
#include "mxdsaction.h"
#include "mxpresenter.h"
#include "mxtypes.h"

class MxAudioPresenter;

// VTABLE: LEGO1 0x100d9fe8
// VTABLE: BETA10 0x101bf508
// SIZE 0x150
class MxBackgroundAudioManager : public MxCore {
public:
	MxBackgroundAudioManager();
	~MxBackgroundAudioManager() override;

	MxLong Notify(MxParam& p_param) override; // vtable+0x04
	MxResult Tickle() override;               // vtable+0x08

	// FUNCTION: LEGO1 0x1007eb70
	// FUNCTION: BETA10 0x100e9af0
	const char* ClassName() const override // vtable+0x0c
	{
		// STRING: LEGO1 0x100f7ac4
		return "MxBackgroundAudioManager";
	}

	// FUNCTION: LEGO1 0x1007eb80
	MxBool IsA(const char* p_name) const override // vtable+0x10
	{
		return !strcmp(p_name, MxBackgroundAudioManager::ClassName()) || MxCore::IsA(p_name);
	}

	MxBool GetEnabled() { return m_enabled; }

	void StartAction(MxParam& p_param);
	void StopAction(MxParam& p_param);
	MxResult PlayMusic(MxDSAction& p_action, undefined4 p_speed, MxPresenter::TickleState p_tickleState);

	void FUN_1007ee70();
	void FUN_1007ef40();
	void FadeInOrFadeOut();

	void Enable(MxBool p_enable);
	virtual MxResult Create(MxAtomId& p_script, MxU32 p_frequencyMS);

	void Init();
	void Stop();
	void LowerVolume();
	void RaiseVolume();
	undefined4 FUN_1007f610(MxPresenter* p_unk0x138, MxS32 p_speed, MxPresenter::TickleState p_tickleState);

	// SYNTHETIC: LEGO1 0x1007ec00
	// MxBackgroundAudioManager::`scalar deleting destructor'

private:
	MxResult OpenMusic(MxAtomId& p_script);
	void DestroyMusic();

	MxBool m_enabled;             // 0x08
	MxDSAction m_action1;         // 0x0c
	MxAudioPresenter* m_unk0xa0;  // 0xa0
	MxDSAction m_action2;         // 0xa4
	MxAudioPresenter* m_unk0x138; // 0x138

	// name is inferred from context
	MxPresenter::TickleState m_tickleState; // 0x13c

	// name inferred from parameter p_speed
	MxS32 m_speed; // 0x140

	MxS32 m_targetVolume; // 0x144
	MxS16 m_unk0x148;     // 0x148
	MxAtomId m_script;    // 0x14c
};

#endif // MXBACKGROUNDAUDIOMANAGER_H
