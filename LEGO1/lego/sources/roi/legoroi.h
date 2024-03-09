#ifndef LEGOROI_H
#define LEGOROI_H

#include "misc/legotypes.h"
#include "viewmanager/viewroi.h"

typedef unsigned char (*ROIHandler)(const char*, char*, unsigned int);

class LegoEntity;
class LegoTextureContainer;
class LegoTextureInfo;
class LegoStorage;
class LegoAnim;
class LegoAnimNodeData;
class LegoTreeNode;

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
	LegoROI* FUN_100a8ce0(const LegoChar* p_name, LegoROI* p_roi);
	LegoResult FUN_100a8da0(LegoTreeNode* p_node, const Matrix4& p_matrix, LegoTime p_time, LegoROI* p_roi);
	LegoResult SetFrame(LegoAnim* p_anim, LegoTime p_time);
	LegoResult FUN_100a9170(LegoFloat p_red, LegoFloat p_green, LegoFloat p_blue, LegoFloat p_alpha);
	LegoResult FUN_100a9210(LegoTextureInfo* p_textureInfo);

	float IntrinsicImportance() const override; // vtable+0x04
	void UpdateWorldBoundingVolumes() override; // vtable+0x18

	void SetDisplayBB(int p_displayBB);

	static LegoResult FUN_100a8cb0(LegoAnimNodeData* p_data, LegoTime p_time, Matrix4& p_matrix);
	static void FUN_100a81b0(const LegoChar* p_error, const LegoChar* p_name);
	static void configureLegoROI(int p_roi);
	static void FUN_100a9d30(ROIHandler p_func);
	static LegoBool FUN_100a9bf0(const LegoChar* p_param, float& p_red, float& p_green, float& p_blue, float& p_alpha);
	static LegoBool ColorAliasLookup(
		const LegoChar* p_param,
		float& p_red,
		float& p_green,
		float& p_blue,
		float& p_alpha
	);
	static LegoBool FUN_100a9cf0(const LegoChar* p_param, unsigned char* paletteEntries, LegoU32 p_numEntries);

	inline const LegoChar* GetName() const { return m_name; }
	inline LegoEntity* GetEntity() { return m_entity; }

	inline void SetEntity(LegoEntity* p_entity) { m_entity = p_entity; }

	// SYNTHETIC: LEGO1 0x100a82b0
	// LegoROI::`scalar deleting destructor'

private:
	LegoChar* m_name;        // 0xe4
	BoundingSphere m_sphere; // 0xe8
	undefined m_unk0x100;    // 0x100
	LegoEntity* m_entity;    // 0x104
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
