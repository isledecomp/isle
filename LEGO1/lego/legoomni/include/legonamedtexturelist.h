#ifndef LEGONAMEDTEXTURELIST_H
#define LEGONAMEDTEXTURELIST_H

#include "legonamedtexture.h"
#include "mxlist.h"

// VTABLE: LEGO1 0x100d8110
// class MxCollection<LegoNamedTexture *>

// VTABLE: LEGO1 0x100d8128
// class MxList<LegoNamedTexture *>

// VTABLE: LEGO1 0x100d8140
// class MxPtrList<LegoNamedTexture>

// VTABLE: LEGO1 0x100d8158
// SIZE 0x18
class LegoNamedTextureList : public MxPtrList<LegoNamedTexture> {
public:
	LegoNamedTextureList() : MxPtrList<LegoNamedTexture>(TRUE) {}

	// SYNTHETIC: LEGO1 0x1004f040
	// LegoNamedTextureList::`scalar deleting destructor'
};

// TEMPLATE: LEGO1 0x1004eec0
// MxCollection<LegoNamedTexture *>::Compare

// TEMPLATE: LEGO1 0x1004eed0
// MxCollection<LegoNamedTexture *>::~MxCollection<LegoNamedTexture *>

// TEMPLATE: LEGO1 0x1004ef20
// MxCollection<LegoNamedTexture *>::Destroy

// TEMPLATE: LEGO1 0x1004ef30
// MxList<LegoNamedTexture *>::~MxList<LegoNamedTexture *>

// TEMPLATE: LEGO1 0x1004efc0
// MxPtrList<LegoNamedTexture>::Destroy

// TEMPLATE: LEGO1 0x1004f0b0
// MxPtrList<LegoNamedTexture>::~MxPtrList<LegoNamedTexture>

// SYNTHETIC: LEGO1 0x1004f100
// MxCollection<LegoNamedTexture *>::`scalar deleting destructor'

// SYNTHETIC: LEGO1 0x1004f170
// MxList<LegoNamedTexture *>::`scalar deleting destructor'

// SYNTHETIC: LEGO1 0x1004f220
// MxPtrList<LegoNamedTexture>::`scalar deleting destructor'

#endif // LEGONAMEDTEXTURELIST_H
