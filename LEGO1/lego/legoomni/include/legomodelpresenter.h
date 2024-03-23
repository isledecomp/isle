#ifndef LEGOMODELPRESENTER_H
#define LEGOMODELPRESENTER_H

#include "mxvideopresenter.h"

class LegoROI;
class LegoWorld;
class LegoEntity;
class MxDSChunk;

// VTABLE: LEGO1 0x100d4e50
// SIZE 0x6c
class LegoModelPresenter : public MxVideoPresenter {
public:
	LegoModelPresenter() { Reset(); }

	// FUNCTION: LEGO1 0x10067a10
	~LegoModelPresenter() override { Destroy(TRUE); }

	static void configureLegoModelPresenter(MxS32 p_modelPresenterConfig);

	// FUNCTION: LEGO1 0x1000ccb0
	inline const char* ClassName() const override // vtable+0x0c
	{
		// STRING: LEGO1 0x100f067c
		return "LegoModelPresenter";
	}

	// FUNCTION: LEGO1 0x1000ccc0
	inline MxBool IsA(const char* p_name) const override // vtable+0x10
	{
		return !strcmp(p_name, ClassName()) || MxVideoPresenter::IsA(p_name);
	}

	void ReadyTickle() override; // vtable+0x18
	void ParseExtra() override;  // vtable+0x30
	void Destroy() override;     // vtable+0x38

	MxResult FUN_1007ff70(MxDSChunk& p_chunk, LegoEntity* p_entity, MxBool p_roiVisible, LegoWorld* p_world);

	inline void Reset()
	{
		m_roi = NULL;
		m_addedToView = FALSE;
	}

	// SYNTHETIC: LEGO1 0x1000cdd0
	// LegoModelPresenter::`scalar deleting destructor'

protected:
	void Destroy(MxBool p_fromDestructor);

private:
	LegoROI* m_roi;       // 0x64
	MxBool m_addedToView; // 0x68

	MxResult CreateROI(MxDSChunk* p_chunk);
};

#endif // LEGOMODELPRESENTER_H
