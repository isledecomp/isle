#ifndef __LEGOANIM_H
#define __LEGOANIM_H

#include "decomp.h"
#include "lego/sources/misc/legostorage.h"
#include "lego/sources/misc/legotree.h"

// SIZE 0x08
class LegoAnimKey {
public:
	enum Flags {
		c_bit1 = 0x01
	};

	LegoAnimKey();
	LegoResult Read(LegoStorage* p_storage);

protected:
	undefined m_unk0x00; // 0x00
	float m_unk0x04;     // 0x04
};

// SIZE 0x14
class LegoTranslationKey : public LegoAnimKey {
public:
	LegoTranslationKey();
	LegoResult Read(LegoStorage* p_storage);

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

protected:
	undefined m_unk0x08; // 0x08
};

// VTABLE: LEGO1 0x100db8c8
// SIZE 0x34
class LegoAnimNodeData : public LegoTreeNodeData {
public:
	LegoAnimNodeData();
	~LegoAnimNodeData() override;
	LegoResult Read(LegoStorage* p_storage) override;  // vtable+0x04
	LegoResult Write(LegoStorage* p_storage) override; // vtable+0x08

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
	undefined m_unk0x20[0x14];             // 0x20
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
	undefined m_unk0x00[0x24]; // 0x00
};

// VTABLE: LEGO1 0x100db8d8
// SIZE 0x18
class LegoAnim : public LegoTree {
public:
	LegoAnim();
	~LegoAnim() override;
	LegoTime GetDuration() { return m_duration; }
	LegoResult Write(LegoStorage* p_storage) override;                     // vtable+0x08
	virtual LegoResult Read(LegoStorage* p_storage, LegoS32 p_parseScene); // vtable+0x10

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
