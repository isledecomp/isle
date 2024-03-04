#ifndef LEGOROI_H
#define LEGOROI_H

#include "misc/legotypes.h"
#include "viewmanager/viewlod.h"
#include "viewmanager/viewroi.h"

typedef unsigned char (*ROIHandler)(char*, char*, unsigned int);

class LegoEntity;
class LegoTextureContainer;
class LegoStorage;
class LegoAnim;

// VTABLE: LEGO1 0x100dbf10
// SIZE 0x20
class LegoLOD : public ViewLOD {
public:
	LegoLOD(Tgl::Renderer*);
	~LegoLOD() override;

	// FUNCTION: LEGO1 0x100aae70
	int NumPolys() const override { return m_numPolys; } // vtable+0x0c

	// FUNCTION: LEGO1 0x100aae80
	double VTable0x10() override { return 0.0; } // vtable+0x10

	// SYNTHETIC: LEGO1 0x100aa430
	// LegoLOD::`scalar deleting destructor'

protected:
	// TODO: Review 1996 version
	undefined4 m_unk0x0c; // 0x0c
	undefined4 m_unk0x10; // 0x10
	undefined4 m_unk0x14; // 0x14
	LegoU32 m_numPolys;   // 0x18
	undefined4 m_unk0x1c; // 0x1c
};

// VTABLE: LEGO1 0x100dbe38
// SIZE 0x108
class LegoROI : public ViewROI {
public:
	LegoROI(Tgl::Renderer* p_renderer);
	LegoROI(Tgl::Renderer* p_renderer, ViewLODList* p_lodList);
	~LegoROI() override;

	LegoResult Read(
		OrientableROI* p_unk0xd4,
		Tgl::Renderer* p_renderer,
		ViewLODListManager* p_viewLODListManager,
		LegoTextureContainer* p_textureContainer,
		LegoStorage* p_storage
	);
	LegoResult SetFrame(LegoAnim* p_anim, LegoTime p_time);

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

	inline const LegoChar* GetName() const { return m_name; }
	inline LegoEntity* GetUnknown0x104() { return m_unk0x104; }

	inline void SetUnknown0x104(LegoEntity* p_unk0x104) { m_unk0x104 = p_unk0x104; }

	// SYNTHETIC: LEGO1 0x100a82b0
	// LegoROI::`scalar deleting destructor'

private:
	LegoChar* m_name;        // 0xe4
	BoundingSphere m_sphere; // 0xe8
	undefined4 m_unk0x100;   // 0x100
	LegoEntity* m_unk0x104;  // 0x104
};

// VTABLE: LEGO1 0x100dbea8
// SIZE 0x10c
class TimeROI : public LegoROI {
public:
	TimeROI(Tgl::Renderer* p_renderer, ViewLODList* p_lodList, LegoTime p_time);

	// SYNTHETIC: LEGO1 0x100a9ad0
	// TimeROI::`scalar deleting destructor'

private:
	LegoTime m_time; // 0x108
};

#endif // LEGOROI_H
