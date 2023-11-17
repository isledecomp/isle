#include "viewroi.h"

#include "../decomp.h"

DECOMP_SIZE_ASSERT(ViewROI, 0xe0)

// OFFSET: LEGO1 0x100a9eb0
float ViewROI::IntrinsicImportance() const
{
	return .5;
} // for now

// OFFSET: LEGO1 0x100a9ec0
const Tgl::Group* ViewROI::GetGeometry() const
{
	return geometry;
}

// OFFSET: LEGO1 0x100a9ed0
Tgl::Group* ViewROI::GetGeometry()
{
	return geometry;
}

// OFFSET: LEGO1 0x100a9ee0
void ViewROI::UpdateWorldData(const MatrixData& parent2world)
{
	OrientableROI::UpdateWorldData(parent2world);
	if (geometry) {
		//		Tgl::FloatMatrix4 tgl_mat;
		Matrix4 mat;
		SETMAT4(mat, m_local2world.GetMatrix());
		Tgl::Result result = geometry->SetTransformation(mat);
		// assert(Tgl::Succeeded(result));
	}
}

// OFFSET: LEGO1 0x100aa250 TEMPLATE
// ViewROI::`scalar deleting destructor'
inline ViewROI::~ViewROI()
{
	// SetLODList() will decrease refCount of LODList
	SetLODList(0);
	delete geometry;
}
