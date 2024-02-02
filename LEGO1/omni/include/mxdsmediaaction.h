#ifndef MXDSMEDIAACTION_H
#define MXDSMEDIAACTION_H

#include "decomp.h"
#include "mxdsaction.h"
#include "mxpoint32.h"

// VTABLE: LEGO1 0x100dcd40
// SIZE 0xb8
class MxDSMediaAction : public MxDSAction {
public:
	MxDSMediaAction();
	~MxDSMediaAction() override;

	void CopyFrom(MxDSMediaAction& p_dsMediaAction);
	MxDSMediaAction& operator=(MxDSMediaAction& p_dsMediaAction);

	// FUNCTION: LEGO1 0x100c8be0
	inline const char* ClassName() const override // vtable+0x0c
	{
		// STRING: LEGO1 0x100f7624
		return "MxDSMediaAction";
	}

	// FUNCTION: LEGO1 0x100c8bf0
	inline MxBool IsA(const char* p_name) const override // vtable+0x10
	{
		return !strcmp(p_name, MxDSMediaAction::ClassName()) || MxDSAction::IsA(p_name);
	}

	// SYNTHETIC: LEGO1 0x100c8cd0
	// MxDSMediaAction::`scalar deleting destructor'

	undefined4 VTable0x14() override;                            // vtable+14;
	MxU32 GetSizeOnDisk() override;                              // vtable+18;
	void Deserialize(MxU8** p_source, MxS16 p_unk0x24) override; // vtable+1c;
	MxDSAction* Clone() override;                                // vtable+2c;

	void CopyMediaSrcPath(const char* p_mediaSrcPath);

	inline MxS32 GetFramesPerSecond() const { return this->m_framesPerSecond; }
	inline MxS32 GetMediaFormat() const { return this->m_mediaFormat; }
	inline MxS32 GetPaletteManagement() const { return this->m_paletteManagement; }
	inline MxLong GetSustainTime() const { return this->m_sustainTime; }

private:
	MxU32 m_sizeOnDisk;   // 0x94
	char* m_mediaSrcPath; // 0x98
	struct {
		undefined4 m_unk0x00;
		undefined4 m_unk0x04;
	} m_unk0x9c;               // 0x9c
	MxS32 m_framesPerSecond;   // 0xa4
	MxS32 m_mediaFormat;       // 0xa8
	MxS32 m_paletteManagement; // 0xac
	MxLong m_sustainTime;      // 0xb0
	undefined4 m_unk0xb4;      // 0xb4
};

#endif // MXDSMEDIAACTION_H
