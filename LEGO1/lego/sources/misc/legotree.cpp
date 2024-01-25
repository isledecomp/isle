#include "legotree.h"

#include "decomp.h"
#include "legostorage.h"

DECOMP_SIZE_ASSERT(LegoTreeNodeData, 0x04)
DECOMP_SIZE_ASSERT(LegoTreeNode, 0x010)
DECOMP_SIZE_ASSERT(LegoTree, 0x08)

// FUNCTION: LEGO1 0x10099d60
LegoTreeNode::LegoTreeNode()
{
	m_data = NULL;
	m_numChildren = 0;
	m_children = NULL;
}

// FUNCTION: LEGO1 0x10099da0
LegoTreeNode::~LegoTreeNode()
{
	if (m_data) {
		delete m_data;
	}
	if (m_children) {
		delete[] m_children;
	}
}

// FUNCTION: LEGO1 0x10099dd0
LegoTree::LegoTree()
{
	m_root = NULL;
}

// FUNCTION: LEGO1 0x10099e00
LegoTree::~LegoTree()
{
	if (m_root) {
		Delete(m_root);
	}
}

// FUNCTION: LEGO1 0x10099e20
LegoResult LegoTree::Read(LegoStorage* p_storage)
{
	return Read(p_storage, m_root);
}

// FUNCTION: LEGO1 0x10099e40
LegoResult LegoTree::Write(LegoStorage* p_storage)
{
	return Write(p_storage, m_root);
}

// FUNCTION: LEGO1 0x10099e60
LegoResult LegoTree::Read(LegoStorage* p_storage, LegoTreeNode*& p_node)
{
	LegoResult result;
	p_node = new LegoTreeNode();
	p_node->SetData(CreateData());
	if ((result = p_node->GetData()->Read(p_storage)) != SUCCESS) {
		return result;
	}
	LegoU32 numChildren;
	if ((result = p_storage->Read(&numChildren, sizeof(numChildren))) != SUCCESS) {
		return result;
	}
	if (numChildren) {
		p_node->SetChildren(new LegoTreeNode*[numChildren]);
		for (LegoU32 i = 0; i < numChildren; i++) {
			LegoTreeNode* node;
			if ((result = Read(p_storage, node)) != SUCCESS) {
				return result;
			}
			p_node->SetNumChildren(p_node->GetNumChildren() + 1);
			p_node->SetChild(i, node);
		}
	}
	return SUCCESS;
}

// FUNCTION: LEGO1 0x1009a020
LegoResult LegoTree::Write(LegoStorage* p_storage, LegoTreeNode* p_node)
{
	LegoResult result;
	if (p_node->GetData()) {
		if ((result = p_node->GetData()->Write(p_storage)) != SUCCESS) {
			return result;
		}
	}
	LegoU32 numChildren = p_node->GetNumChildren();
	if ((result = p_storage->Write(&numChildren, sizeof(numChildren))) != SUCCESS) {
		return result;
	}
	for (LegoU32 i = 0; i < p_node->GetNumChildren(); i++) {
		if ((result = Write(p_storage, p_node->GetChild(i))) != SUCCESS) {
			return result;
		}
	}
	return SUCCESS;
}

// FUNCTION: LEGO1 0x1009a0a0
void LegoTree::Delete(LegoTreeNode* p_node)
{
	for (LegoU32 i = 0; i < p_node->GetNumChildren(); i++) {
		Delete(p_node->GetChild(i));
	}
	delete p_node;
}
