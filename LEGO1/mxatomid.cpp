#include "mxatomid.h"
#include "mxomni.h"

// OFFSET: LEGO1 0x100acf90
MxAtomId::MxAtomId(const char *p_str, LookupMode p_mode)
{
  if (!MxOmni::GetInstance())
    return;

  if (!AtomIdTree())
    return;

  TreeValue *value = try_to_open(p_str, p_mode);
  m_internal = value->m_str.GetData();
  value->RefCountInc();
}

// OFFSET: LEGO1 0x100acfd0
MxAtomId::~MxAtomId()
{
  // TODO
}

// OFFSET: LEGO1 0x100ad1c0
MxAtomId &MxAtomId::operator=(const MxAtomId &id)
{
  // TODO
  return *this;
}

// OFFSET: LEGO1 0x100ad210
TreeValue *MxAtomId::try_to_open(const char *p_str, LookupMode p_mode)
{
  TreeValue *value = new TreeValue(p_str);
  TreeNode *node;

  switch (p_mode) {
    case LookupMode_LowerCase:
    case LookupMode_LowerCase2:
      value->m_str.ToLowerCase();
      break;
    case LookupMode_UpperCase:
      value->m_str.ToUpperCase();
      break;
  }

  MxBinaryTree *tree = AtomIdTree();
  // get the closest node that matches the given value
  node = tree->Search(value);
  
  // pointer reuse???
  TreeNode *ptr_reuse = node;

  // is the node an exact match?
  if (tree->m_root == node || 
      strcmp(value->m_str.GetData(), node->m_value->m_str.GetData()) > 0) {
    ptr_reuse = tree->m_root;
  }

  ptr_reuse = ptr_reuse->m_child0;
  if (ptr_reuse == AtomIdTree()->m_root) {
    delete value;
    value = ptr_reuse->m_value;
  } else {

  }

  // LAB_100ad42b


  return value;
}
