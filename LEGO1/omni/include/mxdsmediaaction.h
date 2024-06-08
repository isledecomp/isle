#ifndef MXDSMEDIAACTION_H
#define MXDSMEDIAACTION_H

#include "decomp.h"
#include "mxdsaction.h"

// VTABLE: LEGO1 0x100dcd40
// VTABLE: BETA10 0x101c2ad8
// SIZE 0xb8
class MxDSMediaAction : public MxDSAction {
public:
	MxDSMediaAction();
	~MxDSMediaAction() override;

	void CopyFrom(MxDSMediaAction& p_dsMediaAction);
	MxDSMediaAction(MxDSMediaAction& p_dsMediaAction);
	MxDSMediaAction& operator=(MxDSMediaAction& p_dsMediaAction);

	// FUNCTION: LEGO1 0x100c8be0
	// FUNCTION: BETA10 0x1015c700
	inline const char* ClassName() const override // vtable+0x0c
	{
		// STRING: LEGO1 0x100f7624
		return "MxDSMediaAction";
	}

	// FUNCTION: LEGO1 0x100c8bf0
	// FUNCTION: BETA10 0x1015c6a0
	inline MxBool IsA(const char* p_name) const override // vtable+0x10
	{
		return !strcmp(p_name, MxDSMediaAction::ClassName()) || MxDSAction::IsA(p_name);
	}

	// SYNTHETIC: LEGO1 0x100c8cd0
	// SYNTHETIC: BETA10 0x1015d810
	// MxDSMediaAction::`scalar deleting destructor'

	undefined4 VTable0x14() override;                            // vtable+14;
	MxU32 GetSizeOnDisk() override;                              // vtable+18;
	void Deserialize(MxU8*& p_source, MxS16 p_unk0x24) override; // vtable+1c;
	MxDSAction* Clone() override;                                // vtable+2c;

	void CopyMediaSrcPath(const char* p_mediaSrcPath);

	// FUNCTION: LEGO1 0x100186e0
	inline const char* GetMediaSrcPath() { return m_mediaSrcPath; }

	// FUNCTION: BETA10 0x1013c2e0
	inline MxS32 GetFramesPerSecond() const { return m_framesPerSecond; }

	// FUNCTION: BETA10 0x1012efd0
	inline MxS32 GetMediaFormat() const { return m_mediaFormat; }

	// FUNCTION: BETA10 0x1013b860
	inline MxS32 GetPaletteManagement() const { return m_paletteManagement; }

	// FUNCTION: BETA10 0x1005ab60
	inline MxLong GetSustainTime() const { return m_sustainTime; }

private:
	struct Unk0x9cStruct {
		// FUNCTION: BETA10 0x1015d7c0
		void SetUnk0x00(undefined4 p_value) { m_unk0x00 = p_value; }

		// FUNCTION: BETA10 0x1015d7e0
		void SetUnk0x04(undefined4 p_value) { m_unk0x04 = p_value; }

		// intentionally public
		undefined4 m_unk0x00;
		undefined4 m_unk0x04;
	};

	MxU32 m_sizeOnDisk;        // 0x94
	char* m_mediaSrcPath;      // 0x98
	Unk0x9cStruct m_unk0x9c;   // 0x9c
	MxS32 m_framesPerSecond;   // 0xa4
	MxS32 m_mediaFormat;       // 0xa8
	MxS32 m_paletteManagement; // 0xac
	MxLong m_sustainTime;      // 0xb0
	undefined4 m_unk0xb4;      // 0xb4
};

#endif // MXDSMEDIAACTION_H
