#ifndef LEGOROI_H
#define LEGOROI_H

#include "viewmanager/viewroi.h"

typedef unsigned char (*ROIHandler)(char*, char*, unsigned int);

class LegoEntity;

// Note: There is an extra class between LegoROI and ViewROI,
// maybe called "AutoROI". VTABLE 0x100dbe38

// TODO: Set as superclass of LegoROI
class AutoROI : public ViewROI {};

// VTABLE: LEGO1 0x100dbea8
// SIZE 0x10c
class LegoROI : public ViewROI {
public:
	LegoROI(Tgl::Renderer* p_renderer, ViewLODList* p_lodList, int p_time);

	float IntrinsicImportance() const override; // vtable+0x04
	// Note: Actually part of parent class (doesn't exist yet)
	void UpdateWorldBoundingVolumes() override; // vtable+0x18

	void SetDisplayBB(int p_displayBB);
	static void configureLegoROI(int p_roi);

	static void SetSomeHandlerFunction(ROIHandler p_func);
	static unsigned char CallTheHandlerFunction(
		char* p_param,
		float& p_red,
		float& p_green,
		float& p_blue,
		float& p_other
	);
	static unsigned char ColorAliasLookup(char* p_param, float& p_red, float& p_green, float& p_blue, float& p_other);

	void WrappedSetLocalTransform(Matrix4& p_transform);
	void FUN_100a46b0(Matrix4& p_transform);
	void FUN_100a58f0(Matrix4& p_transform);

	inline const char* GetUnknown0xe4() { return m_unk0xe4; }
	inline LegoEntity* GetUnknown0x104() { return m_unk0x104; }

	inline void SetUnknown0x104(LegoEntity* p_unk0x104) { m_unk0x104 = p_unk0x104; }

	// SYNTHETIC: LEGO1 0x100a9ad0
	// LegoROI::`scalar deleting destructor'

private:
	undefined4 m_unk0xe0;      // 0xe0
	const char* m_unk0xe4;     // 0xe4
	undefined m_unk0xe8[0x1c]; // 0xe8
	LegoEntity* m_unk0x104;    // 0x104
	int m_time;                // 0x108
};

#endif // LEGOROI_H
