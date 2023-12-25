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
		// GLOBAL: LEGO1 0x100f05a0
		return "LegoLoadCacheSoundPresenter";
	}

private:
	void Init();
	void Destroy(MxBool p_fromDestructor);

	// TODO: Types
	undefined4* m_unk0x6c;
	undefined4* m_unk0x70; // might be a void* as per Destroy function
	undefined4 m_unk0x74;
	undefined4 m_unk0x78;
	undefined m_unk0x7c;
	undefined4 m_unk0x7d[4];
};

#endif // LEGOLOADCACHESOUNDPRESENTER_H
