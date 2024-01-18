#ifndef MXMUSICMANAGER_H
#define MXMUSICMANAGER_H

#include "decomp.h"
#include "mxaudiomanager.h"

#include <windows.h>

// VTABLE: LEGO1 0x100dc930
// SIZE 0x58
class MxMusicManager : public MxAudioManager {
public:
	MxMusicManager();
	virtual ~MxMusicManager() override;

	virtual void Destroy() override;                                     // vtable+18
	virtual void SetVolume(MxS32 p_volume) override;                     // vtable+2c
	virtual MxResult Create(MxU32 p_frequencyMS, MxBool p_createThread); // vtable+30

	inline MxBool GetMIDIInitialized() { return m_midiInitialized; }
	inline void GetMIDIVolume(DWORD& p_volume)
	{
		if (midiOutGetVolume((HMIDIOUT) m_midiStreamH, &p_volume)) {
			p_volume = CalculateVolume(100);
		}
	}

	MxResult ResetStream();
	void ResetBuffer();
	MxResult InitializeMIDI(MxU8* p_data, MxS32 p_loopCount);
	void DeinitializeMIDI();
	void SetMultiplier(MxS32 p_multiplier);

private:
	void Destroy(MxBool p_fromDestructor);

	MxS32 CalculateVolume(MxS32 p_volume);
	void SetMIDIVolume();

	static void CALLBACK MidiCallbackProc(HDRVR p_hdrvr, UINT p_uMsg, DWORD p_dwUser, DWORD p_dw1, DWORD p_dw2);

	HMIDISTRM m_midiStreamH;     // 0x30
	MxBool m_midiInitialized;    // 0x34
	MxU32 m_bufferSize;          // 0x38
	MxU32 m_bufferCurrentSize;   // 0x3c
	MxU8* m_bufferOffset;        // 0x40
	MxU8* m_bufferCurrentOffset; // 0x44
	MxU32 m_loopCount;           // 0x48
	MIDIHDR* m_midiHdrP;         // 0x4c
	MxS32 m_multiplier;          // 0x50
	DWORD m_midiVolume;          // 0x54

	// SYNTHETIC: LEGO1 0x100c0610
	// MxMusicManager::`scalar deleting destructor'

protected:
	void Init();
	void InitData();
};

#endif // MXMUSICMANAGER_H
