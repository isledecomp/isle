#ifndef MXMUSICMANAGER_H
#define MXMUSICMANAGER_H

#include "decomp.h"
#include "mxaudiomanager.h"

// VTABLEADDR 0x100dc930
// SIZE 0x58
class MxMusicManager : public MxAudioManager {
public:
	MxMusicManager();
	virtual ~MxMusicManager() override;

	virtual void Destroy() override;                                     // vtable+18
	virtual void SetVolume(MxS32 p_volume) override;                     // vtable+2c
	virtual MxResult Create(MxU32 p_frequencyMS, MxBool p_createThread); // vtable+30

	inline MxBool GetMIDIInitialized() { return m_MIDIInitialized; }

private:
	void Destroy(MxBool p_fromDestructor);
	void DeinitializeMIDI();

	MxS32 CalculateVolume(MxS32 p_volume);
	void SetMIDIVolume();

	HMIDISTRM m_MIDIStreamH;  // 0x30
	MxBool m_MIDIInitialized; // 0x34
	undefined4 m_unk38;       // 0x38
	undefined4 m_unk3c;       // 0x3c
	undefined4 m_unk40;       // 0x40
	undefined4 m_unk44;       // 0x44
	undefined4 m_unk48;       // 0x48
	MIDIHDR* m_MIDIHdrP;      // 0x4c
	MxS32 m_multiplier;       // 0x50
	DWORD m_MIDIVolume;       // 0x54

protected:
	void Init();
	void InitData();
};

#endif // MXMUSICMANAGER_H
