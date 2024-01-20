#ifndef LEGOROI_H
#define LEGOROI_H

#include "mxtypes.h"
#include "viewmanager/viewroi.h"

typedef MxBool (*ROIHandler)(char*, char*, MxU32);

class LegoEntity;

// Note: There is an extra class between LegoROI and ViewROI,
// maybe called "AutoROI". VTABLE 0x100dbe38

// VTABLE: LEGO1 0x100dbea8
// SIZE 0x10c
class LegoROI : public ViewROI {
public:
	LegoROI(Tgl::Renderer* p_renderer, ViewLODList* p_lodList, MxTime p_time);

	virtual float IntrinsicImportance() const override; // vtable+0x4
	// Note: Actually part of parent class (doesn't exist yet)
	virtual void UpdateWorldBoundingVolumes() override; // vtable+0x18

	__declspec(dllexport) void SetDisplayBB(MxS32 p_displayBB);
	__declspec(dllexport) static void configureLegoROI(MxS32 p_roi);

	static void SetSomeHandlerFunction(ROIHandler p_func);
	static MxBool CallTheHandlerFunction(
		char* p_param,
		MxFloat& p_red,
		MxFloat& p_green,
		MxFloat& p_blue,
		MxFloat& p_other
	);
	static MxBool ColorAliasLookup(char* p_param, MxFloat& p_red, MxFloat& p_green, MxFloat& p_blue, MxFloat& p_other);

	void WrappedSetLocalTransform(Matrix4& p_transform);
	void FUN_100a46b0(Matrix4& p_transform);
	void FUN_100a58f0(Matrix4& p_transform);

	inline LegoEntity* GetUnknown0x104() { return m_unk0x104; }
	inline void SetUnknown0x104(LegoEntity* p_unk0x104) { m_unk0x104 = p_unk0x104; }

	// SYNTHETIC: LEGO1 0x100a9ad0
	// LegoROI::`scalar deleting destructor'

private:
	undefined m_pad[0x24];  // 0xe0
	LegoEntity* m_unk0x104; // 0x104
	MxTime m_time;          // 0x108
};

#endif // LEGOROI_H
