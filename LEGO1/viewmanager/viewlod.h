#ifndef VIEWLOD_H
#define VIEWLOD_H

#include "decomp.h"
#include "realtime/roi.h"
#include "tgl/tgl.h"

//////////////////////////////////////////////////////////////////////////////
// ViewLOD
//

// VTABLE: LEGO1 0x100dbd70
// VTABLE: BETA10 0x101c34a8
// SIZE 0x0c
class ViewLOD : public LODObject {
public:
	enum {
		c_hasMesh = 0x10
	};

	// FUNCTION: BETA10 0x1018e570
	ViewLOD(Tgl::Renderer* pRenderer) : m_meshBuilder(NULL), m_flags(3) {}

	~ViewLOD() override;

	// FUNCTION: LEGO1 0x100a6f30
	// FUNCTION: BETA10 0x10174db0
	double AveragePolyArea() const override { return 2 * 3.14159 * 10.0 / NumPolys(); } // vtable+0x04

	// FUNCTION: LEGO1 0x100a6f50
	// FUNCTION: BETA10 0x10174de0
	int NVerts() const override { return NumPolys() * 2; } // vtable+0x08

	Tgl::MeshBuilder* GetMeshBuilder() { return m_meshBuilder; }
	const Tgl::MeshBuilder* GetMeshBuilder() const { return m_meshBuilder; }
	unsigned int GetFlags() { return m_flags; }
	unsigned char SkipReadingData() { return m_flags & 0xffffff04; }
	unsigned char IsExtraLOD() { return m_flags & 0xffffff08; }

	void SetFlag(unsigned char p_flag) { m_flags |= p_flag; }
	void ClearFlag(unsigned char p_flag) { m_flags &= ~p_flag; }

	// SYNTHETIC: LEGO1 0x100a6f60
	// SYNTHETIC: BETA10 0x10174f10
	// ViewLOD::`scalar deleting destructor'

protected:
	Tgl::MeshBuilder* m_meshBuilder; // 0x04
	unsigned int m_flags;            // 0x08
};

#endif // VIEWLOD_H
