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
	virtual ~MxWavePresenter() override; // vtable+0x00

	// FUNCTION: LEGO1 0x1000d6c0
	inline virtual const char* ClassName() const override // vtable+0x0c
	{
		// STRING: LEGO1 0x100f07b4
		return "MxWavePresenter";
	}

	// FUNCTION: LEGO1 0x1000d6d0
	inline virtual MxBool IsA(const char* p_name) const override // vtable+0x10
	{
		return !strcmp(p_name, MxWavePresenter::ClassName()) || MxSoundPresenter::IsA(p_name);
	}

	virtual void ReadyTickle() override;                       // vtable+0x18
	virtual void StartingTickle() override;                    // vtable+0x1c
	virtual void StreamingTickle() override;                   // vtable+0x20
	virtual void DoneTickle() override;                        // vtable+0x2c
	virtual void ParseExtra() override;                        // vtable+0x30
	virtual MxResult AddToManager() override;                  // vtable+0x34
	virtual void Destroy() override;                           // vtable+0x38
	virtual void EndAction() override;                         // vtable+0x40
	virtual MxResult PutData() override;                       // vtable+0x4c
	virtual void Enable(MxBool p_enable) override;             // vtable+0x54
	virtual void AppendChunk(MxStreamChunk* p_chunk) override; // vtable+0x58
	virtual void SetVolume(MxS32 p_volume) override;           // vtable+0x60
	virtual void Pause();                                      // vtable+0x64
	virtual void Resume();                                     // vtable+0x68
	virtual MxBool IsPaused();                                 // vtable+0x6c

	// Reference: https://github.com/itsmattkc/SIEdit/blob/master/lib/othertypes.h
	// SIZE 0x1c
	struct WaveFormat {
		WAVEFORMATEX m_waveFormatEx;
		MxU32 m_dataSize;
		MxU32 m_flags;
	};

protected:
	void Destroy(MxBool p_fromDestructor);

private:
	void Init();
	MxS8 GetPlayedChunks();
	MxBool FUN_100b1ba0();
	void WriteToSoundBuffer(void* p_audioPtr, MxU32 p_length);

	WaveFormat* m_waveFormat;       // 0x54
	LPDIRECTSOUNDBUFFER m_dsBuffer; // 0x58
	MxU32 m_chunkLength;            // 0x5c
	MxU32 m_lockSize;               // 0x60
	MxU8 m_writtenChunks;           // 0x64
	MxBool m_started;               // 0x65
	MxBool m_unk0x66;               // 0x66
	MxS8 m_silenceData;             // 0x67
	MxBool m_paused;                // 0x68
};

#endif // MXWAVEPRESENTER_H
