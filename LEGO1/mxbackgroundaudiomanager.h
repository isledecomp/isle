#ifndef MXBACKGROUNDAUDIOMANAGER_H
#define MXBACKGROUNDAUDIOMANAGER_H

#include "mxcore.h"
#include "mxdsaction.h"
#include "mxnotificationmanager.h"
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

	__declspec(dllexport) void Enable(unsigned char p);
	virtual MxResult Create(MxAtomId& p_script, MxU32 p_frequencyMS);

	void Stop();

private:
	void Init();
	MxResult OpenMusic(MxAtomId& p_script);
	void DestroyMusic();

	MxBool m_musicEnabled; // 0x8
	MxDSAction m_action1;  // 0xc
	MxS32 m_unka0;
	MxDSAction m_action2; // 0xa4
	MxS32 m_unk138;
	MxS32 m_unk13c;
	MxS32 m_unk140;
	MxS32 m_unk144;
	MxS16 m_unk148;
	MxAtomId m_script;
};

#endif // MXBACKGROUNDAUDIOMANAGER_H
