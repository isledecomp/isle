#ifndef VIEWLOD_H
#define VIEWLOD_H

#include "decomp.h"
#include "realtime/roi.h"
#include "tgl/tgl.h"

//////////////////////////////////////////////////////////////////////////////
// ViewLOD
//

// VTABLE: LEGO1 0x100dbd70
// SIZE 0x0c
class ViewLOD : public LODObject {
public:
	ViewLOD(Tgl::Renderer* pRenderer) : m_meshGroup(NULL), m_unk0x08(3) {}
	~ViewLOD() override;

	// FUNCTION: LEGO1 0x100a6f30
	double AveragePolyArea() const override { return 2 * 3.14159 * 10.0 / NumPolys(); } // vtable+0x04

	// FUNCTION: LEGO1 0x100a6f50
	int NVerts() const override { return NumPolys() * 2; } // vtable+0x08

	Tgl::Group* GetGeometry() { return m_meshGroup; }
	const Tgl::Group* GetGeometry() const { return m_meshGroup; }
	unsigned char GetUnknown0x08Test() { return m_unk0x08 & 0xffffff08; }

	// SYNTHETIC: LEGO1 0x100a6f60
	// ViewLOD::`scalar deleting destructor'

protected:
	// TODO: m_meshGroup unconfirmed (based on 1996)
	Tgl::Group* m_meshGroup; // 0x04
	undefined4 m_unk0x08;    // 0x08
};

#endif // VIEWLOD_H
