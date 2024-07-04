#ifndef LEGOLOADCACHESOUNDPRESENTER_H
#define LEGOLOADCACHESOUNDPRESENTER_H

#include "decomp.h"
#include "mxwavepresenter.h"

class LegoCacheSound;

// VTABLE: LEGO1 0x100d5fa8
// SIZE 0x90
class LegoLoadCacheSoundPresenter : public MxWavePresenter {
public:
	LegoLoadCacheSoundPresenter();
	~LegoLoadCacheSoundPresenter() override;

	// FUNCTION: BETA10 0x1008cf90
	static const char* HandlerClassName()
	{
		// STRING: LEGO1 0x100f05a0
		return "LegoLoadCacheSoundPresenter";
	}

	// FUNCTION: LEGO1 0x10018450
	// FUNCTION: BETA10 0x1008cf60
	const char* ClassName() const override // vtable+0x0c
	{
		return HandlerClassName();
	}

	void ReadyTickle() override;     // vtable+0x18
	void StreamingTickle() override; // vtable+0x20
	void DoneTickle() override;      // vtable+0x2c
	MxResult PutData() override;     // vtable+0x4c

private:
	void Init();
	void Destroy(MxBool p_fromDestructor);

	LegoCacheSound* m_cacheSound;  // 0x6c
	MxU8* m_data;                  // 0x70
	MxU8* m_pData;                 // 0x74
	MxU32 m_dataSize;              // 0x78
	MxBool m_unk0x7c;              // 0x7c
	PCMWAVEFORMAT m_pcmWaveFormat; // 0x7d
};

// SYNTHETIC: LEGO1 0x10018460
// LegoLoadCacheSoundPresenter::`scalar deleting destructor'

#endif // LEGOLOADCACHESOUNDPRESENTER_H
