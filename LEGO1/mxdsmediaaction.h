#ifndef MXDSMEDIAACTION_H
#define MXDSMEDIAACTION_H

#include "decomp.h"
#include "mxdsaction.h"
#include "mxpoint32.h"

// VTABLE 0x100dcd40
// SIZE 0xb8
class MxDSMediaAction : public MxDSAction {
public:
	MxDSMediaAction();
	virtual ~MxDSMediaAction() override;

	void CopyFrom(MxDSMediaAction& p_dsMediaAction);
	MxDSMediaAction& operator=(MxDSMediaAction& p_dsMediaAction);

	// OFFSET: LEGO1 0x100c8be0
	inline virtual const char* ClassName() const override // vtable+0x0c
	{
		// 0x100f7624
		return "MxDSMediaAction";
	}

	// OFFSET: LEGO1 0x100c8bf0
	inline virtual MxBool IsA(const char* name) const override // vtable+0x10
	{
		return !strcmp(name, MxDSMediaAction::ClassName()) || MxDSAction::IsA(name);
	}

	virtual MxU32 GetSizeOnDisk() override;                            // vtable+18;
	virtual void Deserialize(char** p_source, MxS16 p_unk24) override; // vtable+1c;

	void CopyMediaSrcPath(const char* p_mediaSrcPath);

	inline MxS32 GetMediaFormat() const { return this->m_mediaFormat; }
	inline MxLong GetSustainTime() const { return this->m_sustainTime; }

private:
	MxU32 m_sizeOnDisk;   // 0x94
	char* m_mediaSrcPath; // 0x98
	struct {
		undefined4 m_unk00;
		undefined4 m_unk04;
	} m_unk9c;                 // 0x9c
	MxS32 m_framesPerSecond;   // 0xa4
	MxS32 m_mediaFormat;       // 0xa8
	MxS32 m_paletteManagement; // 0xac
	MxLong m_sustainTime;      // 0xb0
	undefined4 m_unkb4;        // 0xb4
};

#endif // MXDSMEDIAACTION_H
