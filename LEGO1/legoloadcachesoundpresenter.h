#ifndef LEGOLOADCACHESOUNDPRESENTER_H
#define LEGOLOADCACHESOUNDPRESENTER_H

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
};

#endif // LEGOLOADCACHESOUNDPRESENTER_H
