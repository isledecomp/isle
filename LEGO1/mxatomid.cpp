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
  Destroy();
}

// OFFSET: LEGO1 0x100acfe0
void MxAtomId::Destroy()
{
  if (*m_internal == '\0')
    return;

  if (!MxOmni::GetInstance())
    return;

  if (!AtomIdTree())
    return;

  TreeValue value = TreeValue(m_internal);
  TreeValue *p = &value;

  // 100ad052
  MxBinaryTree *tree = AtomIdTree();
  TreeNode *root = tree->m_root;

  // should inline Search but NOT TreeValueCompare
  TreeNode *node = tree->Search(p);
  
  TreeNode *ass = node;
  if (node == root->m_parent || TreeValueCompare(p, node->m_value)) {
    ass = root->m_parent;
  }

  node->m_value->RefCountDec();
}

// OFFSET: LEGO1 0x100ad1c0
MxAtomId &MxAtomId::operator=(const MxAtomId &atomId)
{
  // TODO
  const char *temp = m_internal;
  if (m_internal)
    Destroy();

  if (atomId.m_internal && MxOmni::GetInstance() && AtomIdTree())
    try_to_open(temp, LookupMode_Exact);

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

  // LAB_100ad2a1
  MxBinaryTree *tree = AtomIdTree();
  // get the closest node that matches the given value
  // should NOT inline
  node = tree->Search(value);
  
  // pointer reuse???
  TreeNode *ptr_reuse = node;

  // is the node an exact match?
  if (tree->m_root == node || TreeValueCompare(value, node->m_value)) {
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

// OFFSET: LEGO1 0x100ad7e0
void MxAtomId::Clear()
{
  Destroy();
  m_internal = NULL;
}
