#ifndef MXDSACTION_H
#define MXDSACTION_H

#include "mxdsobject.h"
#include "mxtypes.h"
#include "realtime/vector.h"

class MxOmni;

// VTABLE 0x100dc098
// SIZE 0x94
class MxDSAction : public MxDSObject {
public:
	enum {
		Flag_Looping = 0x01,
		Flag_Bit3 = 0x04,
		Flag_Bit4 = 0x08,
		Flag_Bit5 = 0x10,
		Flag_Enabled = 0x20,
		Flag_Bit7 = 0x40,
		Flag_World = 0x80,
		Flag_Bit9 = 0x200,
		Flag_Bit10 = 0x400,
	};

	__declspec(dllexport) MxDSAction();
	__declspec(dllexport) virtual ~MxDSAction();

	void CopyFrom(MxDSAction& p_dsAction);
	MxDSAction& operator=(MxDSAction& p_dsAction);

	// OFFSET: LEGO1 0x100ad980
	inline virtual const char* ClassName() const override // vtable+0x0c
	{
		// 0x101013f4
		return "MxDSAction";
	}

	// OFFSET: LEGO1 0x100ad990
	inline virtual MxBool IsA(const char* name) const override // vtable+0x10
	{
		return !strcmp(name, MxDSAction::ClassName()) || MxDSObject::IsA(name);
	}

	virtual MxU32 GetSizeOnDisk() override;                            // vtable+18;
	virtual void Deserialize(char** p_source, MxS16 p_unk24) override; // vtable+1c;
	virtual MxLong GetDuration();                                      // vtable+24;
	virtual void SetDuration(MxLong p_duration);                       // vtable+28;
	virtual MxDSAction* Clone();                                       // vtable+2c;
	virtual void MergeFrom(MxDSAction& p_dsAction);                    // vtable+30;
	virtual MxBool HasId(MxU32 p_objectId);                            // vtable+34;
	virtual void SetUnkTimingField(MxLong p_unkTimingField);           // vtable+38;
	virtual MxLong GetUnkTimingField();                                // vtable+3c;
	virtual MxLong GetElapsedTime();                                   // vtable+40;

	void AppendData(MxU16 p_extraLength, const char* p_extraData);

	inline MxU32 GetFlags() { return m_flags; }
	inline void SetFlags(MxU32 p_flags) { m_flags = p_flags; }
	inline char* GetExtraData() { return m_extraData; }
	inline MxU16 GetExtraLength() const { return m_extraLength; }
	inline MxLong GetStartTime() const { return m_startTime; }
	inline MxS32 GetLoopCount() { return m_loopCount; }
	inline void SetLoopCount(MxS32 p_loopCount) { m_loopCount = p_loopCount; }
	inline const Vector3Data& GetLocation() const { return m_location; }
	inline void SetUnknown84(MxCore* p_unk84) { m_unk84 = p_unk84; }
	inline MxCore* GetUnknown8c() { return m_unk8c; }
	inline void SetUnknown8c(MxCore* p_unk8c) { m_unk8c = p_unk8c; }

	inline MxBool IsLooping() const { return m_flags & Flag_Looping; }
	inline MxBool IsBit3() const { return m_flags & Flag_Bit3; }

protected:
	MxU32 m_sizeOnDisk;      // 0x2c
	MxU32 m_flags;           // 0x30
	MxLong m_startTime;      // 0x34
	MxLong m_duration;       // 0x38
	MxS32 m_loopCount;       // 0x3c
	Vector3Data m_location;  // 0x40
	Vector3Data m_direction; // 0x54
	Vector3Data m_up;        // 0x68
	char* m_extraData;       // 0x7c
	MxU16 m_extraLength;     // 0x80
	MxCore* m_unk84;         // 0x84
	undefined4 m_unk88;      // 0x88
	MxCore* m_unk8c;         // 0x8c
	MxLong m_unkTimingField; // 0x90
};

#endif // MXDSACTION_H
