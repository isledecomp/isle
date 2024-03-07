#ifndef __LEGOMESH_H
#define __LEGOMESH_H

#include "decomp.h"
#include "misc/legocolor.h"
#include "misc/legotypes.h"

class LegoStorage;

// SIZE 0x1c
struct LegoMeshUnkComponent {
	~LegoMeshUnkComponent()
	{
		if (m_unk0x08) {
			delete m_unk0x08;
		}
		if (m_unk0x0c) {
			delete m_unk0x0c;
		}
		if (m_unk0x10) {
			delete m_unk0x10;
		}
		if (m_unk0x14) {
			delete m_unk0x14;
		}
		if (m_unk0x18) {
			delete m_unk0x18;
		}
	}

	undefined m_unk0x00[8]; // 0x00
	undefined* m_unk0x08;   // 0x08
	undefined* m_unk0x0c;   // 0x0c
	undefined* m_unk0x10;   // 0x10
	undefined* m_unk0x14;   // 0x14
	undefined* m_unk0x18;   // 0x18
};

// VTABLE: LEGO1 0x100dd228
// SIZE 0x24
class LegoMesh {
public:
	enum {
		e_flat,
		e_gouraud,
		e_wireframe
	};

	LegoMesh();
	virtual ~LegoMesh();
	LegoColor GetColor() { return m_color; }
	void SetColor(LegoColor p_color) { m_color = p_color; }
	LegoFloat GetAlpha() { return m_alpha; }
	LegoU8 GetShading() { return m_shading; }
	void SetShading(LegoU8 p_shading) { m_shading = p_shading; }
	LegoU8 GetUnknown0x0d() { return m_unk0x0d; }
	const LegoChar* GetTextureName() { return m_textureName; }
	const LegoChar* GetMaterialName() { return m_materialName; }
	LegoBool GetUnknown0x21() { return m_unk0x21; }
	LegoResult Read(LegoStorage* p_storage);

	// SYNTHETIC: LEGO1 0x100d3840
	// LegoMesh::`scalar deleting destructor'

protected:
	LegoColor m_color;               // 0x04
	LegoFloat m_alpha;               // 0x08
	LegoU8 m_shading;                // 0x0c
	LegoU8 m_unk0x0d;                // 0x0d
	LegoMeshUnkComponent* m_unk0x10; // 0x10 - unused, except in destructor
	undefined4 m_unk0x14;            // 0x14 - unused
	LegoChar* m_textureName;         // 0x18
	LegoChar* m_materialName;        // 0x1c
	undefined m_unk0x20;             // 0x20 - unused
	LegoBool m_unk0x21;              // 0x21
};

#endif // __LEGOMESH_H
