#ifndef LEGOANIMPRESENTER_H
#define LEGOANIMPRESENTER_H

#include "lego/sources/misc/legostorage.h"
#include "lego/sources/misc/legotree.h"
#include "mxgeometry/mxgeometry3d.h"
#include "mxvideopresenter.h"

class LegoWorld;
class LegoAnimClass;

// VTABLE: LEGO1 0x100d90c8
// SIZE 0xc0
class LegoAnimPresenter : public MxVideoPresenter {
public:
	LegoAnimPresenter();
	~LegoAnimPresenter() override;

	// FUNCTION: LEGO1 0x10068530
	inline const char* ClassName() const override // vtable+0x0c
	{
		// STRING: LEGO1 0x100f071c
		return "LegoAnimPresenter";
	}

	// FUNCTION: LEGO1 0x10068540
	inline MxBool IsA(const char* p_name) const override // vtable+0x10
	{
		return !strcmp(p_name, LegoAnimPresenter::ClassName()) || MxVideoPresenter::IsA(p_name);
	}

	void ReadyTickle() override;                                                           // vtable+0x18
	void StartingTickle() override;                                                        // vtable+0x1c
	void StreamingTickle() override;                                                       // vtable+0x20
	void DoneTickle() override;                                                            // vtable+0x2c
	void ParseExtra() override;                                                            // vtable+0x30
	MxResult AddToManager() override;                                                      // vtable+0x34
	void Destroy() override;                                                               // vtable+0x38
	MxResult StartAction(MxStreamController* p_controller, MxDSAction* p_action) override; // vtable+0x3c
	void EndAction() override;                                                             // vtable+0x40
	void PutFrame() override;                                                              // vtable+0x6c
	virtual MxResult VTable0x88(MxStreamChunk* p_chunk);                                   // vtable+0x88

	inline LegoAnimClass* GetUnknown0x64() { return m_unk0x64; }

	const char* GetActionObjectName();

protected:
	void Init();
	void Destroy(MxBool p_fromDestructor);

	LegoAnimClass* m_unk0x64;  // 0x64
	undefined4 m_unk0x68;      // 0x68
	undefined4 m_unk0x6c;      // 0x6c
	undefined4 m_unk0x70;      // 0x70
	undefined4 m_unk0x74;      // 0x74
	undefined4 m_unk0x78;      // 0x78
	undefined4 m_unk0x7c;      // 0x7c
	LegoWorld* m_currentWorld; // 0x80
	MxAtomId m_animAtom;       // 0x84
	undefined4 m_unk0x88;      // 0x88
	undefined4 m_unk0x8c;      // 0x8c
	undefined4 m_unk0x90;      // 0x90
	undefined m_unk0x94;       // 0x94
	undefined m_unk0x95;       // 0x95
	undefined m_unk0x96;       // 0x96
	undefined m_unk0x97;       // 0x97
	undefined4 m_unk0x98;      // 0x98
	MxS16 m_unk0x9c;           // 0x9c
	undefined4 m_unk0xa0;      // 0xa0
	undefined4 m_unk0xa4;      // 0xa4
	Mx3DPointFloat m_unk0xa8;  // 0xa8
	undefined4 m_unk0xbc;      // 0xbc
};

// SYNTHETIC: LEGO1 0x10068650
// LegoAnimPresenter::`scalar deleting destructor'

// VTABLE: LEGO1 0x100db8d8
// SIZE 0x18
class LegoAnimClass : public LegoTree {
public:
	LegoAnimClass();
	~LegoAnimClass() override;

	LegoResult Write(LegoStorage* p_storage) override;        // vtable+0x08
	LegoTreeNodeData* CreateData() override;                  // vtable+0x0c
	virtual MxResult VTable0x10(LegoMemory* p_stream, MxS32); // vtable+0x10

	inline MxLong GetUnknown0x8() { return m_unk0x08; }

private:
	MxLong m_unk0x08;     // 0x08
	undefined4 m_unk0x0c; // 0x0c
	undefined4 m_unk0x10; // 0x10
	undefined4 m_unk0x14; // 0x14
};

// SYNTHETIC: LEGO1 0x100a0ba0
// LegoAnimClass::`scalar deleting destructor'

#endif // LEGOANIMPRESENTER_H
