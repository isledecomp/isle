#ifndef MXWAVEPRESENTER_H
#define MXWAVEPRESENTER_H

#include "decomp.h"
#include "mxsoundpresenter.h"

#include <dsound.h>

// VTABLE: LEGO1 0x100d49a8
// SIZE 0x6c
class MxWavePresenter : public MxSoundPresenter {
public:
	MxWavePresenter() { Init(); }

	// FUNCTION: LEGO1 0x1000d640
	~MxWavePresenter() override { Destroy(TRUE); } // vtable+0x00

	// FUNCTION: LEGO1 0x1000d6c0
	inline const char* ClassName() const override // vtable+0x0c
	{
		// STRING: LEGO1 0x100f07b4
		return "MxWavePresenter";
	}

	// FUNCTION: LEGO1 0x1000d6d0
	inline MxBool IsA(const char* p_name) const override // vtable+0x10
	{
		return !strcmp(p_name, MxWavePresenter::ClassName()) || MxSoundPresenter::IsA(p_name);
	}

	void ReadyTickle() override;      // vtable+0x18
	void StartingTickle() override;   // vtable+0x1c
	void StreamingTickle() override;  // vtable+0x20
	void DoneTickle() override;       // vtable+0x2c
	void ParseExtra() override;       // vtable+0x30
	MxResult AddToManager() override; // vtable+0x34

	// FUNCTION: LEGO1 0x1000d6a0
	void Destroy() override { Destroy(FALSE); } // vtable+0x38

	void EndAction() override;                       // vtable+0x40
	MxResult PutData() override;                     // vtable+0x4c
	void Enable(MxBool p_enable) override;           // vtable+0x54
	void LoopChunk(MxStreamChunk* p_chunk) override; // vtable+0x58
	void SetVolume(MxS32 p_volume) override;         // vtable+0x60
	virtual void Pause();                            // vtable+0x64
	virtual void Resume();                           // vtable+0x68

	// FUNCTION: LEGO1 0x1000d6b0
	virtual MxBool IsPaused() { return m_paused; } // vtable+0x6c

	// SIZE 0x18
	struct WaveFormat {
		PCMWAVEFORMAT m_pcmWaveFormat; // 0x00
		MxU32 m_dataSize;              // 0x10
		MxU32 m_flags;                 // 0x14
	};

	// SYNTHETIC: LEGO1 0x1000d810
	// MxWavePresenter::`scalar deleting destructor'

protected:
	void Init();
	void Destroy(MxBool p_fromDestructor);

	MxS8 GetPlayedChunks();
	MxBool FUN_100b1ba0();
	void WriteToSoundBuffer(void* p_audioPtr, MxU32 p_length);

	WaveFormat* m_waveFormat;       // 0x54
	LPDIRECTSOUNDBUFFER m_dsBuffer; // 0x58
	MxU32 m_chunkLength;            // 0x5c
	MxU32 m_lockSize;               // 0x60
	MxU8 m_writtenChunks;           // 0x64
	MxBool m_started;               // 0x65
	MxBool m_is3d;                  // 0x66
	MxS8 m_silenceData;             // 0x67
	MxBool m_paused;                // 0x68
};

#endif // MXWAVEPRESENTER_H
