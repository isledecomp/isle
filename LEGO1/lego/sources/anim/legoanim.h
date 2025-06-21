#ifndef __LEGOANIM_H
#define __LEGOANIM_H

#include "decomp.h"
#include "misc/legostorage.h"
#include "misc/legotree.h"

class Matrix4;

// SIZE 0x08
class LegoAnimKey {
public:
	enum Flags {
		c_active = 0x01,
		c_negateRotation = 0x02,
		c_skipInterpolation = 0x04
	};

	LegoAnimKey();
	LegoResult Read(LegoStorage* p_storage);
	LegoResult Write(LegoStorage* p_storage);
	LegoFloat GetTime() { return m_time; }

	// The different types (LegoFloat vs. MxS32) are correct according to BETA10
	// FUNCTION: BETA10 0x100738a0
	void SetTime(MxS32 p_time) { m_time = p_time; }

	LegoU32 IsActive() { return m_flags & c_active; }
	LegoU32 ShouldNegateRotation() { return m_flags & c_negateRotation; }
	LegoU32 ShouldSkipInterpolation() { return m_flags & c_skipInterpolation; }

	// FUNCTION: BETA10 0x100739a0
	void SetActive(MxS32 p_active)
	{
		if (p_active) {
			m_flags |= c_active;
		}
		else {
			m_flags &= ~c_active;
		}
	}

protected:
	LegoU8 m_flags;   // 0x00
	LegoFloat m_time; // 0x04
};

// SIZE 0x14
class LegoTranslationKey : public LegoAnimKey {
public:
	LegoTranslationKey();
	LegoResult Read(LegoStorage* p_storage);
	LegoResult Write(LegoStorage* p_storage);
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
	LegoResult Write(LegoStorage* p_storage);

	// FUNCTION: BETA10 0x10073a00
	LegoFloat GetAngle() { return m_angle; }

	// FUNCTION: BETA10 0x10073a30
	void SetAngle(LegoFloat p_angle) { m_angle = p_angle; }

	// FUNCTION: BETA10 0x10073a60
	LegoFloat GetX() { return m_x; }

	// FUNCTION: BETA10 0x10073a90
	void SetX(LegoFloat p_x) { m_x = p_x; }

	// FUNCTION: BETA10 0x10073ac0
	LegoFloat GetY() { return m_y; }

	// FUNCTION: BETA10 0x10073af0
	void SetY(LegoFloat p_y) { m_y = p_y; }

	// FUNCTION: BETA10 0x10073b20
	LegoFloat GetZ() { return m_z; }

	// FUNCTION: BETA10 0x10073b50
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
	LegoResult Write(LegoStorage* p_storage);
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
	LegoResult Write(LegoStorage* p_storage);
	LegoBool IsVisible() { return m_visible; }

	// FUNCTION: BETA10 0x100738d0
	void SetVisible(LegoBool p_visible) { m_visible = p_visible; }

protected:
	LegoBool m_visible; // 0x08
};

// SIZE 0x0c
class LegoRotationZKey : public LegoAnimKey {
public:
	LegoRotationZKey();
	LegoResult Read(LegoStorage* p_storage);
	LegoResult Write(LegoStorage* p_storage);

	LegoFloat GetZ() { return m_z; }

protected:
	LegoFloat m_z; // 0x08
};

// VTABLE: LEGO1 0x100db8c8
// SIZE 0x34
class LegoAnimNodeData : public LegoTreeNodeData {
public:
	LegoAnimNodeData();
	~LegoAnimNodeData() override;
	LegoResult Read(LegoStorage* p_storage) override;  // vtable+0x04
	LegoResult Write(LegoStorage* p_storage) override; // vtable+0x08

	void SetName(LegoChar* p_name);
	LegoResult CreateLocalTransform(LegoFloat p_time, Matrix4& p_matrix);
	LegoBool GetVisibility(LegoFloat p_time);

	// FUNCTION: BETA10 0x100595d0
	LegoChar* GetName() { return m_name; }

	// FUNCTION: BETA10 0x10073780
	LegoU16 GetNumTranslationKeys() { return m_numTranslationKeys; }

	// FUNCTION: BETA10 0x100737b0
	LegoU16 GetNumRotationKeys() { return m_numRotationKeys; }

	// FUNCTION: BETA10 0x100737e0
	void SetNumRotationKeys(LegoU16 p_numRotationKeys) { m_numRotationKeys = p_numRotationKeys; }

	// FUNCTION: BETA10 0x10073810
	void SetRotationKeys(LegoRotationKey* p_keys)
	{
		m_rotationKeys = p_keys;
		m_rotationIndex = 0;
	}

	LegoU32 GetTranslationIndex() { return m_translationIndex; }
	LegoU32 GetRotationIndex() { return m_rotationIndex; }
	LegoU32 GetScaleIndex() { return m_scaleIndex; }
	LegoU32 GetMorphIndex() { return m_morphIndex; }

	// FUNCTION: BETA10 0x1005abc0
	LegoU16 GetROIIndex() { return m_roiIndex; }

	// FUNCTION: BETA10 0x1005d5c0
	LegoU16 GetBoundaryIndex() { return m_boundaryIndex; }

	// FUNCTION: BETA10 0x10073b80
	LegoRotationKey* GetRotationKey(MxS32 index) { return &m_rotationKeys[index]; }

	void SetTranslationIndex(LegoU32 p_translationIndex) { m_translationIndex = p_translationIndex; }
	void SetRotationIndex(LegoU32 p_rotationIndex) { m_rotationIndex = p_rotationIndex; }
	void SetScaleIndex(LegoU32 p_scaleIndex) { m_scaleIndex = p_scaleIndex; }
	void SetMorphIndex(LegoU32 p_morphIndex) { m_morphIndex = p_morphIndex; }

	// FUNCTION: BETA10 0x10073930
	LegoMorphKey* GetMorphKeys() { return m_morphKeys; }

	// FUNCTION: BETA10 0x10073960
	void SetMorphKeys(LegoMorphKey* p_morphKeys)
	{
		m_morphKeys = p_morphKeys;
		m_morphIndex = 0;
	}

	// FUNCTION: BETA10 0x10073900
	void SetNumMorphKeys(LegoU16 p_numMorphKeys) { m_numMorphKeys = p_numMorphKeys; }

	// FUNCTION: BETA10 0x10059600
	void SetROIIndex(LegoU16 p_roiIndex) { m_roiIndex = p_roiIndex; }

	// FUNCTION: BETA10 0x1005f2e0
	void SetBoundaryIndex(LegoU16 p_boundaryIndex) { m_boundaryIndex = p_boundaryIndex; }

	LegoResult CreateLocalTransform(LegoTime p_time, Matrix4& p_matrix)
	{
		return CreateLocalTransform((LegoFloat) p_time, p_matrix);
	}

	// FUNCTION: BETA10 0x1005d580
	LegoBool GetVisibility(LegoTime p_time) { return GetVisibility((LegoFloat) p_time); }

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
	inline static LegoAnimKey& GetKey(LegoU32 p_i, LegoAnimKey* p_keys, LegoU32 p_size);

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
	LegoU16 m_roiIndex;                    // 0x20
	LegoU16 m_boundaryIndex;               // 0x22
	LegoU32 m_translationIndex;            // 0x24
	LegoU32 m_rotationIndex;               // 0x28
	LegoU32 m_scaleIndex;                  // 0x2c
	LegoU32 m_morphIndex;                  // 0x30
};

// SIZE 0x08
struct LegoAnimActorEntry {
	enum {
		e_managedLegoActor = 2,
		e_managedInvisibleRoiTrimmed = 3,
		e_managedInvisibleRoi = 4,
		e_sceneRoi1 = 5,
		e_sceneRoi2 = 6,
	};

	LegoChar* m_name; // 0x00
	LegoU32 m_type;   // 0x04
};

// TODO: Possibly called `LegoCameraAnim(ation)`?
// SIZE 0x24
class LegoAnimScene {
public:
	LegoAnimScene();
	~LegoAnimScene();
	LegoResult Read(LegoStorage* p_storage);
	LegoResult Write(LegoStorage* p_storage);
	LegoResult CalculateCameraTransform(LegoFloat p_time, Matrix4& p_matrix);

	LegoU32 GetTargetIndex() { return m_targetIndex; }
	LegoU32 GetTranslationIndex() { return m_translationIndex; }
	LegoU32 GetRotationIndex() { return m_rotationIndex; }

	void SetTargetIndex(LegoU32 p_targetIndex) { m_targetIndex = p_targetIndex; }
	void SetTranslationIndex(LegoU32 p_translationIndex) { m_translationIndex = p_translationIndex; }
	void SetRotationIndex(LegoU32 p_rotationIndex) { m_rotationIndex = p_rotationIndex; }

private:
	LegoU16 m_translationKeysCount;        // 0x00
	LegoTranslationKey* m_translationKeys; // 0x04
	LegoU16 m_targetKeysCount;             // 0x08
	LegoTranslationKey* m_targetKeys;      // 0x0c
	LegoU16 m_rotationKeysCount;           // 0x10
	LegoRotationZKey* m_rotationKeys;      // 0x14
	LegoU32 m_targetIndex;                 // 0x18
	LegoU32 m_translationIndex;            // 0x1c
	LegoU32 m_rotationIndex;               // 0x20
};

// VTABLE: LEGO1 0x100db8d8
// SIZE 0x18
class LegoAnim : public LegoTree {
public:
	LegoAnim();
	~LegoAnim() override;

	// FUNCTION: BETA10 0x100284c0
	LegoTime GetDuration() { return m_duration; }

	LegoU32 GetNumActors() { return m_numActors; }
	LegoResult Write(LegoStorage* p_storage) override;                     // vtable+0x08
	virtual LegoResult Read(LegoStorage* p_storage, LegoS32 p_parseScene); // vtable+0x10

	const LegoChar* GetActorName(LegoU32 p_index);
	LegoU32 GetActorType(LegoU32 p_index);

	// FUNCTION: BETA10 0x1005abf0
	LegoAnimScene* GetCamAnim() { return m_camAnim; }

	// SYNTHETIC: LEGO1 0x100a0ba0
	// LegoAnim::`scalar deleting destructor'

protected:
	LegoTime m_duration;             // 0x08
	LegoAnimActorEntry* m_modelList; // 0x0c
	LegoU32 m_numActors;             // 0x10
	LegoAnimScene* m_camAnim;        // 0x14

	// FUNCTION: LEGO1 0x100a1040
	LegoTreeNodeData* CreateData() override { return new LegoAnimNodeData(); } // vtable+0x0c
};

#endif // __LEGOANIM_H
