#ifndef __LEGOTREE_H
#define __LEGOTREE_H

#ifdef _DEBUG
#include <stdio.h>
#endif
#include "legotypes.h"

class LegoStorage;

// VTABLE: LEGO1 0x100db778
// SIZE 0x04
class LegoTreeNodeData {
public:
	LegoTreeNodeData() {}
	// FUNCTION: LEGO1 0x1009a0e0
	virtual ~LegoTreeNodeData() {}

	// FUNCTION: LEGO1 0x10099fe0
	virtual LegoResult Read(LegoStorage* p_storage) { return SUCCESS; } // vtable+0x04

	// FUNCTION: LEGO1 0x10099ff0
	virtual LegoResult Write(LegoStorage* p_storage) { return SUCCESS; } // vtable+0x08

	// SYNTHETIC: LEGO1 0x1009a000
	// LegoTreeNodeData::`scalar deleting destructor'
};

// VTABLE: LEGO1 0x100db764
// SIZE 0x10
class LegoTreeNode {
public:
	LegoTreeNode();
	virtual ~LegoTreeNode();
	LegoTreeNodeData* GetData() { return m_data; }
	void SetData(LegoTreeNodeData* p_data) { m_data = p_data; }
	LegoU32 GetNumChildren() { return m_numChildren; }
	void SetNumChildren(LegoU32 p_numChildren) { m_numChildren = p_numChildren; }
	LegoTreeNode* GetChild(LegoU32 p_i) { return m_children[p_i]; }
	void SetChild(LegoU32 p_i, LegoTreeNode* p_child) { m_children[p_i] = p_child; }
	LegoTreeNode** GetChildren() { return m_children; }
	void SetChildren(LegoTreeNode** p_children) { m_children = p_children; }

	// SYNTHETIC: LEGO1 0x10099d80
	// LegoTreeNode::`scalar deleting destructor'

protected:
	LegoTreeNodeData* m_data;  // 0x04
	LegoU32 m_numChildren;     // 0x08
	LegoTreeNode** m_children; // 0x0c
};

// VTABLE: LEGO1 0x100db768
// SIZE 0x08
class LegoTree {
public:
	LegoTree();
	virtual ~LegoTree();
	LegoTreeNode* GetRoot() { return m_root; }
	void SetRoot(LegoTreeNode* p_root) { m_root = p_root; }
	virtual LegoResult Read(LegoStorage* p_storage);  // vtable+0x04
	virtual LegoResult Write(LegoStorage* p_storage); // vtable+0x08

	// SYNTHETIC: LEGO1 0x10099de0
	// LegoTree::`scalar deleting destructor'

protected:
	LegoResult Read(LegoStorage* p_storage, LegoTreeNode*& p_node);
	LegoResult Write(LegoStorage* p_storage, LegoTreeNode* p_node);
	void Delete(LegoTreeNode* p_node);

	// FUNCTION: LEGO1 0x10099f70
	virtual LegoTreeNodeData* CreateData() { return new LegoTreeNodeData(); } // vtable+0x0c

	LegoTreeNode* m_root; // 0x04
};

#endif // __LEGOTREE_H
