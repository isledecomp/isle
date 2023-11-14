#ifndef MXWAVEPRESENTER_H
#define MXWAVEPRESENTER_H

#include "decomp.h"
#include "mxsoundpresenter.h"

#include <dsound.h>

// VTABLE 0x100d49a8
// SIZE 0x6c
class MxWavePresenter : public MxSoundPresenter {
public:
	MxWavePresenter() { Init(); }
	virtual ~MxWavePresenter() override; // vtable+0x00

	// OFFSET: LEGO1 0x1000d6c0
	inline virtual const char* ClassName() const override // vtable+0x0c
	{
		// 0x100f07b4
		return "MxWavePresenter";
	}

	// OFFSET: LEGO1 0x1000d6d0
	inline virtual MxBool IsA(const char* name) const override // vtable+0x10
	{
		return !strcmp(name, MxWavePresenter::ClassName()) || MxSoundPresenter::IsA(name);
	}

	virtual void ReadyTickle() override;                       // vtable+0x18
	virtual void StartingTickle() override;                    // vtable+0x1c
	virtual void StreamingTickle() override;                   // vtable+0x20
	virtual void DoneTickle() override;                        // vtable+0x2c
	virtual void ParseExtra() override;                        // vtable+0x30
	virtual MxResult AddToManager() override;                  // vtable+0x34
	virtual void Destroy() override;                           // vtable+0x38
	virtual void EndAction() override;                         // vtable+0x40
	virtual undefined4 PutData() override;                     // vtable+0x4c
	virtual void Enable(MxBool p_enable) override;             // vtable+0x54
	virtual void AppendChunk(MxStreamChunk* p_chunk) override; // vtable+0x58
	virtual void SetVolume(MxU32 p_volume) override;           // vtable+0x60
	virtual void VTable0x64();                                 // vtable+0x64
	virtual void VTable0x68();                                 // vtable+0x68
	virtual undefined VTable0x6c();                            // vtable+0x6c

	// Reference: https://github.com/itsmattkc/SIEdit/blob/master/lib/othertypes.h
	// SIZE 0x1c
	struct WaveFormat {
		WAVEFORMATEX m_waveFormatEx;
		MxU32 m_dataSize;
		MxU32 m_flags;
	};

private:
	void Init();
	void Destroy(MxBool p_fromDestructor);
	MxS8 FUN_100b1b60();
	MxBool FUN_100b1ba0();
	void FUN_100b1bd0(void* p_audioPtr, MxU32 p_length);

	WaveFormat* m_waveFormat;
	LPDIRECTSOUNDBUFFER m_dsBuffer;
	MxU32 m_length;
	undefined4 m_unk60;
	MxU8 m_unk64;
	MxBool m_unk65;
	MxBool m_unk66;
	MxS8 m_unk67;
	undefined m_unk68;
};

#endif // MXWAVEPRESENTER_H
