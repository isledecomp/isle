#ifndef MXDSSOUND_H
#define MXDSSOUND_H

#include "mxdsmediaaction.h"

// VTABLE: LEGO1 0x100dcdd0
// SIZE 0xc0
class MxDSSound : public MxDSMediaAction {
public:
	MxDSSound();
	virtual ~MxDSSound() override;

	void CopyFrom(MxDSSound& p_dsSound);
	MxDSSound& operator=(MxDSSound& p_dsSound);

	// FUNCTION: LEGO1 0x100c9330
	inline virtual const char* ClassName() const override // vtable+0x0c
	{
		// STRING: LEGO1 0x101025e4
		return "MxDSSound";
	}

	// FUNCTION: LEGO1 0x100c9340
	inline virtual MxBool IsA(const char* p_name) const override // vtable+0x10
	{
		return !strcmp(p_name, MxDSSound::ClassName()) || MxDSMediaAction::IsA(p_name);
	}

	virtual MxU32 GetSizeOnDisk() override;                              // vtable+18;
	virtual void Deserialize(MxU8** p_source, MxS16 p_unk0x24) override; // vtable+1c;
	virtual MxDSAction* Clone() override;                                // vtable+2c;

	inline MxS32 GetVolume() const { return m_volume; }

private:
	MxU32 m_sizeOnDisk;
	MxS32 m_volume; // 0xbc
};

#endif // MXDSSOUND_H
