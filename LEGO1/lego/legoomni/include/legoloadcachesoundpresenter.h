#ifndef LEGOLOADCACHESOUNDPRESENTER_H
#define LEGOLOADCACHESOUNDPRESENTER_H

#include "decomp.h"
#include "mxwavepresenter.h"

// VTABLE: LEGO1 0x100d5fa8
// SIZE 0x90
class LegoLoadCacheSoundPresenter : public MxWavePresenter {
public:
	LegoLoadCacheSoundPresenter();
	virtual ~LegoLoadCacheSoundPresenter() override;

	// FUNCTION: LEGO1 0x10018450
	inline const char* ClassName() const override // vtable+0xc
	{
		// STRING: LEGO1 0x100f05a0
		return "LegoLoadCacheSoundPresenter";
	}

	virtual void ReadyTickle() override;     // vtable+0x18
	virtual void StreamingTickle() override; // vtable+0x20
	virtual void DoneTickle() override;      // vtable+0x2c
	virtual MxResult PutData() override;     // vtable+0x4c

private:
	void Init();
	void Destroy(MxBool p_fromDestructor);

	undefined4* m_unk0x6c;   // 0x6c
	undefined4* m_unk0x70;   // 0x70
	undefined4 m_unk0x74;    // 0x74
	undefined4 m_unk0x78;    // 0x78
	undefined m_unk0x7c;     // 0x7c
	undefined4 m_unk0x80[4]; // 0x80
};

// SYNTHETIC: LEGO1 0x10018460
// LegoLoadCacheSoundPresenter::`scalar deleting destructor'

#endif // LEGOLOADCACHESOUNDPRESENTER_H
