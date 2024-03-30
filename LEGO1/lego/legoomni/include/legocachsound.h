#ifndef LEGOCACHSOUND_H
#define LEGOCACHSOUND_H

#include "decomp.h"
#include "legounknown100d5778.h"
#include "mxcore.h"
#include "mxstring.h"

// VTABLE: LEGO1 0x100d4718
// SIZE 0x88
class LegoCacheSound : public MxCore {
public:
	LegoCacheSound();
	~LegoCacheSound() override; // vtable+0x00

	// FUNCTION: LEGO1 0x10006580
	inline const char* ClassName() const override // vtable+0x0c
	{
		// STRING: LEGO1 0x100f01c4
		return "LegoCacheSound";
	}

	// FUNCTION: LEGO1 0x10006590
	inline MxBool IsA(const char* p_name) const override // vtable+0x10
	{
		return !strcmp(p_name, LegoCacheSound::ClassName()) || MxCore::IsA(p_name);
	}

	virtual MxResult FUN_10006710();                   // vtable+0x14
	virtual void Destroy();                            // vtable+0x18
	virtual void FUN_10006cd0(undefined4, undefined4); // vtable+0x1c

	inline const MxString& GetString0x48() const { return m_string0x48; }
	inline const undefined GetUnk0x58() const { return m_unk0x58; }

	LegoCacheSound* FUN_10006960();
	MxResult FUN_10006a30(const char* p_str, MxBool);
	void FUN_10006b80();
	void FUN_10006be0();

	// SYNTHETIC: LEGO1 0x10006610
	// LegoCacheSound::`scalar deleting destructor'

private:
	void Init();

	LPDIRECTSOUNDBUFFER m_dsBuffer; // 0x08
	undefined m_unk0xc[4];          // 0x0c
	LegoUnknown100d5778 m_unk0x10;  // 0x10
	undefined* m_unk0x40;           // 0x40
	undefined4 m_unk0x44;           // 0x44
	MxString m_string0x48;          // 0x48
	undefined m_unk0x58;            // 0x58
	PCMWAVEFORMAT m_unk0x59;        // 0x59
	MxBool m_isLooping;             // 0x69
	MxBool m_unk0x6a;               // 0x6a
	undefined4 m_unk0x6c;           // 0x6c
	undefined m_unk0x70;            // 0x70
	MxString m_string0x74;          // 0x74
	undefined m_unk0x84;            // 0x84
};

#endif // LEGOCACHSOUND_H
