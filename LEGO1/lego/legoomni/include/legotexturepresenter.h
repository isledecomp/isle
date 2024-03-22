#ifndef LEGOTEXTUREPRESENTER_H
#define LEGOTEXTUREPRESENTER_H

#include "legonamedtexturelist.h"
#include "mxmediapresenter.h"

// VTABLE: LEGO1 0x100d4d90
// SIZE 0x54
class LegoTexturePresenter : public MxMediaPresenter {
public:
	LegoTexturePresenter() : m_textures(NULL) {}
	~LegoTexturePresenter() override;

	// FUNCTION: LEGO1 0x1000ce50
	inline const char* ClassName() const override // vtable+0x0c
	{
		// STRING: LEGO1 0x100f0664
		return "LegoTexturePresenter";
	}

	// FUNCTION: LEGO1 0x1000ce60
	inline MxBool IsA(const char* p_name) const override // vtable+0x10
	{
		return !strcmp(p_name, LegoTexturePresenter::ClassName()) || MxMediaPresenter::IsA(p_name);
	}

	void DoneTickle() override;       // vtable+0x2c
	MxResult AddToManager() override; // vtable+0x34
	MxResult PutData() override;      // vtable+0x4c

	// SYNTHETIC: LEGO1 0x1000cf40
	// LegoTexturePresenter::`scalar deleting destructor'

	MxResult Read(MxDSChunk& p_chunk);
	MxResult Store();

private:
	LegoNamedTextureList* m_textures; // 0x50
};

#endif // LEGOTEXTUREPRESENTER_H
