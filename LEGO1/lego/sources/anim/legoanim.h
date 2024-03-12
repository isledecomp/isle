#ifndef __LEGOANIM_H
#define __LEGOANIM_H

#include "decomp.h"
#include "misc/legostorage.h"
#include "misc/legotree.h"
#include "realtime/matrix.h"

// SIZE 0x08
class LegoAnimKey {
public:
	enum Flags {
		c_bit1 = 0x01,
		c_bit2 = 0x02,
		c_bit3 = 0x04
	};

	LegoAnimKey();
	LegoResult Read(LegoStorage* p_storage);
	LegoFloat GetTime() { return m_time; }
	void SetTime(LegoFloat p_time) { m_time = p_time; }
	LegoU32 TestBit1() { return m_flags & c_bit1; }
	LegoU32 TestBit2() { return m_flags & c_bit2; }
	LegoU32 TestBit3() { return m_flags & c_bit3; }

protected:
	LegoU8 m_flags;   // 0x00
	LegoFloat m_time; // 0x04
};

// SIZE 0x14
class LegoTranslationKey : public LegoAnimKey {
public:
	LegoTranslationKey();
	LegoResult Read(LegoStorage* p_storage);
	LegoFloat GetX() { return m_x; }
	void SetX(LegoFloat p_x) { m_x = p_x; }
	LegoFloat GetY() { return m_y; }
	void SetY(LegoFloat p_y) { m_y = p_y; }
	LegoFloat GetZ() { return m_z; }
	void SetZ(LegoFloat p_z) { m_z = p_z; }

protected:
	LegoFloat m_x; // 0x08
	LegoFloat m_y; // 0x0c
	LegoFloat m_z; // 0x10
};

// SIZE 0x18
class LegoRotationKey : public LegoAnimKey {
public:
	LegoRotationKey();
	LegoResult Read(LegoStorage* p_storage);
	LegoFloat GetAngle() { return m_angle; }
	void SetAngle(LegoFloat p_angle) { m_angle = p_angle; }
	LegoFloat GetX() { return m_x; }
	void SetX(LegoFloat p_x) { m_x = p_x; }
	LegoFloat GetY() { return m_y; }
	void SetY(LegoFloat p_y) { m_y = p_y; }
	LegoFloat GetZ() { return m_z; }
	void SetZ(LegoFloat p_z) { m_z = p_z; }

protected:
	LegoFloat m_angle; // 0x08
	LegoFloat m_x;     // 0x0c
	LegoFloat m_y;     // 0x10
	LegoFloat m_z;     // 0x14
};

// SIZE 0x14
class LegoScaleKey : public LegoAnimKey {
public:
	LegoScaleKey();
	LegoResult Read(LegoStorage* p_storage);
	LegoFloat GetX() { return m_x; }
	void SetX(LegoFloat p_x) { m_x = p_x; }
	LegoFloat GetY() { return m_y; }
	void SetY(LegoFloat p_y) { m_y = p_y; }
	LegoFloat GetZ() { return m_z; }
	void SetZ(LegoFloat p_z) { m_z = p_z; }

protected:
	LegoFloat m_x; // 0x08
	LegoFloat m_y; // 0x0c
	LegoFloat m_z; // 0x10
};

// SIZE 0x0c
class LegoMorphKey : public LegoAnimKey {
public:
	LegoMorphKey();
	LegoResult Read(LegoStorage* p_storage);
	LegoBool GetUnknown0x08() { return m_unk0x08; }

protected:
	LegoBool m_unk0x08; // 0x08
};

// SIZE 0x0c
class LegoUnknownKey : public LegoAnimKey {
public:
	LegoUnknownKey();
	LegoResult Read(LegoStorage* p_storage);

protected:
	undefined4 m_unk0x08; // 0x08
};

// VTABLE: LEGO1 0x100db8c8
// SIZE 0x34
class LegoAnimNodeData : public LegoTreeNodeData {
public:
	LegoAnimNodeData();
	~LegoAnimNodeData() override;
	LegoResult Read(LegoStorage* p_storage) override;  // vtable+0x04
	LegoResult Write(LegoStorage* p_storage) override; // vtable+0x08

	LegoResult CreateLocalTransform(LegoFloat p_time, Matrix4& p_matrix);
	LegoBool FUN_100a0990(LegoFloat p_time);

	const LegoChar* GetName() { return m_name; }
	LegoU32 GetTranslationIndex() { return m_translationIndex; }
	LegoU32 GetRotationIndex() { return m_rotationIndex; }
	LegoU32 GetScaleIndex() { return m_scaleIndex; }
	LegoU32 GetMorphIndex() { return m_morphIndex; }

	void SetTranslationIndex(LegoU32 p_translationIndex) { m_translationIndex = p_translationIndex; }
	void SetRotationIndex(LegoU32 p_rotationIndex) { m_rotationIndex = p_rotationIndex; }
	void SetScaleIndex(LegoU32 p_scaleIndex) { m_scaleIndex = p_scaleIndex; }
	void SetMorphIndex(LegoU32 p_morphIndex) { m_morphIndex = p_morphIndex; }

	LegoResult CreateLocalTransform(LegoTime p_time, Matrix4& p_matrix)
	{
		return CreateLocalTransform((LegoFloat) p_time, p_matrix);
	}
	LegoBool FUN_100a0990(LegoTime p_time) { return FUN_100a0990((LegoFloat) p_time); }

	inline static void GetTranslation(
		LegoU16 p_numTranslationKeys,
		LegoTranslationKey* p_translationKeys,
		LegoFloat p_time,
		Matrix4& p_matrix,
		LegoU32& p_old_index
	);
	/*inline*/ static void GetRotation(
		LegoU16 p_numRotationKeys,
		LegoRotationKey* p_rotationKeys,
		LegoFloat p_time,
		Matrix4& p_matrix,
		LegoU32& p_old_index
	);
	inline static void GetScale(
		LegoU16 p_numScaleKeys,
		LegoScaleKey* p_scaleKeys,
		LegoFloat p_time,
		Matrix4& p_matrix,
		LegoU32& p_old_index
	);
	inline static LegoFloat Interpolate(
		LegoFloat p_time,
		LegoAnimKey& p_key1,
		LegoFloat p_value1,
		LegoAnimKey& p_key2,
		LegoFloat p_value2
	);

	static LegoU32 FindKeys(
		LegoFloat p_time,
		LegoU32 p_numKeys,
		LegoAnimKey* p_keys,
		LegoU32 p_size,
		LegoU32& p_new_index,
		LegoU32& p_old_index
	);

	// SYNTHETIC: LEGO1 0x1009fd80
	// LegoAnimNodeData::`scalar deleting destructor'

protected:
	LegoChar* m_name;                      // 0x04
	LegoU16 m_numTranslationKeys;          // 0x08
	LegoU16 m_numRotationKeys;             // 0x0a
	LegoU16 m_numScaleKeys;                // 0x0c
	LegoU16 m_numMorphKeys;                // 0x0e
	LegoTranslationKey* m_translationKeys; // 0x10
	LegoRotationKey* m_rotationKeys;       // 0x14
	LegoScaleKey* m_scaleKeys;             // 0x18
	LegoMorphKey* m_morphKeys;             // 0x1c
	undefined2 m_unk0x20;                  // 0x20
	undefined2 m_unk0x22;                  // 0x22
	LegoU32 m_translationIndex;            // 0x24
	LegoU32 m_rotationIndex;               // 0x28
	LegoU32 m_scaleIndex;                  // 0x2c
	LegoU32 m_morphIndex;                  // 0x30
};

// SIZE 0x08
struct LegoAnimActorEntry {
	LegoChar* m_name;     // 0x00
	undefined4 m_unk0x04; // 0x04
};

// SIZE 0x24
class LegoAnimScene {
public:
	LegoAnimScene();
	~LegoAnimScene();
	LegoResult Read(LegoStorage* p_storage);

private:
	LegoU16 m_unk0x00;             // 0x00
	LegoTranslationKey* m_unk0x04; // 0x04
	LegoU16 m_unk0x08;             // 0x08
	LegoTranslationKey* m_unk0x0c; // 0x0c
	LegoU16 m_unk0x10;             // 0x10
	LegoUnknownKey* m_unk0x14;     // 0x14
	undefined4 m_unk0x18;          // 0x18
	undefined4 m_unk0x1c;          // 0x1c
	undefined4 m_unk0x20;          // 0x20
};

// VTABLE: LEGO1 0x100db8d8
// SIZE 0x18
class LegoAnim : public LegoTree {
public:
	LegoAnim();
	~LegoAnim() override;
	LegoTime GetDuration() { return m_duration; }
	LegoU32 GetNumActors() { return m_numActors; }
	LegoResult Write(LegoStorage* p_storage) override;                     // vtable+0x08
	virtual LegoResult Read(LegoStorage* p_storage, LegoS32 p_parseScene); // vtable+0x10

	const LegoChar* GetActorName(LegoU32 p_index);
	undefined4 GetActorUnknown0x04(LegoU32 p_index);

	// SYNTHETIC: LEGO1 0x100a0ba0
	// LegoAnim::`scalar deleting destructor'

protected:
	LegoTime m_duration;          // 0x08
	LegoAnimActorEntry* m_actors; // 0x0c
	LegoU32 m_numActors;          // 0x10
	LegoAnimScene* m_scene;       // 0x14

	// FUNCTION: LEGO1 0x100a1040
	LegoTreeNodeData* CreateData() override { return new LegoAnimNodeData(); } // vtable+0x0c
};

#endif // __LEGOANIM_H
