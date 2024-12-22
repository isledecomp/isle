#ifndef LEGOCACHSOUND_H
#define LEGOCACHSOUND_H

#include "decomp.h"
#include "lego3dsound.h"
#include "mxcore.h"
#include "mxstring.h"

// VTABLE: LEGO1 0x100d4718
// SIZE 0x88
class LegoCacheSound : public MxCore {
public:
	LegoCacheSound();
	~LegoCacheSound() override; // vtable+0x00

	// FUNCTION: LEGO1 0x10006580
	const char* ClassName() const override // vtable+0x0c
	{
		// not in BETA10
		// STRING: LEGO1 0x100f01c4
		return "LegoCacheSound";
	}

	// FUNCTION: LEGO1 0x10006590
	MxBool IsA(const char* p_name) const override // vtable+0x10
	{
		return !strcmp(p_name, LegoCacheSound::ClassName()) || MxCore::IsA(p_name);
	}

	virtual MxResult Create(
		LPPCMWAVEFORMAT p_pwfx,
		MxString p_mediaSrcPath,
		MxS32 p_volume,
		MxU8* p_data,
		MxU32 p_dataSize
	);                                                 // vtable+0x14
	virtual void Destroy();                            // vtable+0x18
	virtual void FUN_10006cd0(undefined4, undefined4); // vtable+0x1c

	const MxString& GetUnknown0x48() const { return m_unk0x48; }
	const MxBool GetUnknown0x58() const { return m_unk0x58; }

	LegoCacheSound* Clone();
	MxResult Play(const char* p_name, MxBool p_looping);
	void Stop();
	void FUN_10006be0();
	void SetDistance(MxS32 p_min, MxS32 p_max);
	void MuteSilence(MxBool p_muted);
	void MuteStop(MxBool p_mute);

	// SYNTHETIC: LEGO1 0x10006610
	// LegoCacheSound::`scalar deleting destructor'

private:
	void Init();
	void CopyData(MxU8* p_data, MxU32 p_dataSize);
	MxString FUN_10006d80(const MxString& p_str);

	LPDIRECTSOUNDBUFFER m_dsBuffer; // 0x08
	undefined m_unk0x0c[4];         // 0x0c
	Lego3DSound m_sound;            // 0x10
	MxU8* m_data;                   // 0x40
	MxU32 m_dataSize;               // 0x44
	MxString m_unk0x48;             // 0x48
	MxBool m_unk0x58;               // 0x58
	PCMWAVEFORMAT m_wfx;            // 0x59
	MxBool m_looping;               // 0x69
	MxBool m_unk0x6a;               // 0x6a
	MxS32 m_volume;                 // 0x6c
	MxBool m_unk0x70;               // 0x70
	MxString m_unk0x74;             // 0x74
	MxBool m_muted;                 // 0x84
};

#endif // LEGOCACHSOUND_H
