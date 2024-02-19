#ifndef LEGOROI_H
#define LEGOROI_H

#include "lego/sources/misc/legotypes.h"
#include "viewmanager/viewroi.h"

typedef unsigned char (*ROIHandler)(char*, char*, unsigned int);

class LegoEntity;

// VTABLE: LEGO1 0x100dbe38
// SIZE 0x108
class LegoROI : public ViewROI {
public:
	LegoROI(Tgl::Renderer* p_renderer);
	LegoROI(Tgl::Renderer* p_renderer, ViewLODList* p_lodList);
	~LegoROI() override;

	float IntrinsicImportance() const override; // vtable+0x04
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

	inline const char* GetName() const { return m_name; }
	inline LegoEntity* GetUnknown0x104() { return m_unk0x104; }

	inline void SetUnknown0x104(LegoEntity* p_unk0x104) { m_unk0x104 = p_unk0x104; }

	// SYNTHETIC: LEGO1 0x100a82b0
	// LegoROI::`scalar deleting destructor'

private:
	int m_unk0xe0;           // 0xe0
	LegoChar* m_name;        // 0xe4
	BoundingSphere m_sphere; // 0xe8
	undefined4 m_unk0x100;   // 0x100
	LegoEntity* m_unk0x104;  // 0x104
};

// VTABLE: LEGO1 0x100dbea8
// SIZE 0x10c
class TimeROI : public LegoROI {
public:
	TimeROI(Tgl::Renderer* p_renderer, ViewLODList* p_lodList, int p_time);

	// SYNTHETIC: LEGO1 0x100a9ad0
	// TimeROI::`scalar deleting destructor'

private:
	int m_time; // 0x108
};

#endif // LEGOROI_H
