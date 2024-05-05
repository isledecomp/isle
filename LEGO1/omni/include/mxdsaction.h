#ifndef MXDSACTION_H
#define MXDSACTION_H

#include "mxdsobject.h"
#include "mxgeometry/mxgeometry3d.h"
#include "mxtypes.h"

class MxOmni;

// VTABLE: LEGO1 0x100dc098
// VTABLE: BETA10 0x101c1b68
// SIZE 0x94
class MxDSAction : public MxDSObject {
public:
	enum {
		c_looping = 0x01,
		c_bit3 = 0x04,
		c_bit4 = 0x08,
		c_bit5 = 0x10,
		c_enabled = 0x20,
		c_bit7 = 0x40,
		c_world = 0x80,
		c_bit9 = 0x100,
		c_bit10 = 0x200,
		c_bit11 = 0x400,
	};

	MxDSAction();
	~MxDSAction() override;

	MxDSAction(MxDSAction& p_dsAction);
	void CopyFrom(MxDSAction& p_dsAction);
	MxDSAction& operator=(MxDSAction& p_dsAction);

	// FUNCTION: LEGO1 0x100ad980
	// FUNCTION: BETA10 0x1012bcf0
	inline const char* ClassName() const override // vtable+0x0c
	{
		// STRING: LEGO1 0x101013f4
		return "MxDSAction";
	}

	// FUNCTION: LEGO1 0x100ad990
	// FUNCTION: BETA10 0x1012bd10
	inline MxBool IsA(const char* p_name) const override // vtable+0x10
	{
		return !strcmp(p_name, MxDSAction::ClassName()) || MxDSObject::IsA(p_name);
	}

	undefined4 VTable0x14() override;                            // vtable+14;
	MxU32 GetSizeOnDisk() override;                              // vtable+18;
	void Deserialize(MxU8*& p_source, MxS16 p_unk0x24) override; // vtable+1c;
	virtual MxLong GetDuration();                                // vtable+24;
	virtual void SetDuration(MxLong p_duration);                 // vtable+28;
	virtual MxDSAction* Clone();                                 // vtable+2c;
	virtual void MergeFrom(MxDSAction& p_dsAction);              // vtable+30;
	virtual MxBool HasId(MxU32 p_objectId);                      // vtable+34;
	virtual void SetUnknown90(MxLong p_unk0x90);                 // vtable+38;
	virtual MxLong GetUnknown90();                               // vtable+3c;
	virtual MxLong GetElapsedTime();                             // vtable+40;

	void AppendExtra(MxU16 p_extraLength, const char* p_extraData);

	// FUNCTION: BETA10 0x1003a560
	inline void GetExtra(MxU16& p_extraLength, char*& p_extraData)
	{
		p_extraLength = m_extraLength;
		p_extraData = m_extraData;
	}

	// FUNCTION: BETA10 0x1003cf70
	inline MxU32 GetFlags() { return m_flags; }

	// FUNCTION: BETA10 0x1004daa0
	inline void SetFlags(MxU32 p_flags) { m_flags = p_flags; }

	inline char* GetExtraData() { return m_extraData; }
	inline MxU16 GetExtraLength() const { return m_extraLength; }

	// FUNCTION: BETA10 0x1005a560
	inline MxLong GetStartTime() const { return m_startTime; }

	// FUNCTION: BETA10 0x1012be80
	inline MxS32 GetLoopCount() { return m_loopCount; }

	inline void SetLoopCount(MxS32 p_loopCount) { m_loopCount = p_loopCount; }

	// FUNCTION: BETA10 0x1003db50
	inline Mx3DPointFloat& GetLocation() { return m_location; }

	// FUNCTION: BETA10 0x1003db80
	inline Mx3DPointFloat& GetDirection() { return m_direction; }

	// FUNCTION: BETA10 0x1003dbb0
	inline Mx3DPointFloat& GetUp() { return m_up; }

	inline void SetLocation(const Vector3& p_location) { m_location = p_location; }
	inline void SetDirection(const Vector3& p_direction) { m_direction = p_direction; }
	inline void SetUp(const Vector3& p_up) { m_up = p_up; }
	inline MxCore* GetUnknown84() { return m_unk0x84; }
	inline void SetUnknown84(MxCore* p_unk0x84) { m_unk0x84 = p_unk0x84; }
	inline MxCore* GetOrigin() { return m_origin; }
	inline void SetOrigin(MxCore* p_origin) { m_origin = p_origin; }

	inline MxBool IsLooping() const { return m_flags & c_looping; }
	inline MxBool IsBit3() const { return m_flags & c_bit3; }

	// SYNTHETIC: LEGO1 0x100ada60
	// SYNTHETIC: BETA10 0x1012be40
	// MxDSAction::`scalar deleting destructor'

protected:
	MxU32 m_sizeOnDisk;         // 0x2c
	MxU32 m_flags;              // 0x30
	MxLong m_startTime;         // 0x34
	MxLong m_duration;          // 0x38
	MxS32 m_loopCount;          // 0x3c
	Mx3DPointFloat m_location;  // 0x40
	Mx3DPointFloat m_direction; // 0x54
	Mx3DPointFloat m_up;        // 0x68
	char* m_extraData;          // 0x7c
	MxU16 m_extraLength;        // 0x80
	MxCore* m_unk0x84;          // 0x84
	undefined4 m_unk0x88;       // 0x88
	MxCore* m_origin;           // 0x8c
	MxLong m_unk0x90;           // 0x90
};

#endif // MXDSACTION_H
