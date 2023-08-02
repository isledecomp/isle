#ifndef MXBINARYTREE_H
#define MXBINARYTREE_H

#include "mxstring.h"

enum RBNodeColor
{
  RBNodeColor_Red = 0,
  RBNodeColor_Black = 1,
};

// SIZE 0x14
class TreeValue {
public:
  TreeValue(const char *p_str)
  {
    m_str = p_str;
    m_t0 = 0;
  }

  void RefCountInc();
  void RefCountDec();

  MxString m_str;
  MxU16 m_t0;
  MxU16 m_t1;
};

// SIZE 0x14
class TreeNode {
public:
  TreeNode *m_child0; // +0 // string sorts after
  TreeNode *m_parent; // +4 // parent node
  TreeNode *m_child1; // +8 // string sorts before
  TreeValue *m_value; // +c
  RBNodeColor m_color; // +10 // BLACK or RED.
};

// TODO: helper to avoid using a non-default constructor
inline TreeNode *newTreeNode(TreeNode *p_parent, RBNodeColor p_color)
{
  TreeNode *t = new TreeNode();
  t->m_parent = p_parent;
  t->m_color = p_color;
  return t;
}

// SIZE 0x10
class MxBinaryTree
{
public:
  // Dummy node to represent null value.
  static TreeNode *g_Node_Nil;
  MxBinaryTree()
  {
    if (!g_Node_Nil) {
      g_Node_Nil = newTreeNode(NULL, RBNodeColor_Black);
      g_Node_Nil->m_child0 = NULL;
      g_Node_Nil->m_child1 = NULL;
    }

    m_root = newTreeNode(g_Node_Nil, RBNodeColor_Red);
  }
  ~MxBinaryTree();

  void LeftRotate(TreeNode *);
  void RightRotate(TreeNode *);
  void Insert(TreeNode **, TreeNode *, TreeNode *, TreeValue *&);
  void Successor(TreeNode* &p_node);
  void Predecessor(TreeNode *&p_node);
  int TreeValueCompare(TreeValue *&p_val0, TreeValue *&p_val1);
  TreeNode *minimum(TreeNode *p_node);
  TreeNode *maximum(TreeNode *p_node);
  TreeNode *Search(TreeValue *&);
  TreeNode *Find(TreeValue *&);

  int m_p0; // +0
  TreeNode *m_root; // +4
  int m_p2; // +8
  int m_nodeCount; // +c
};

// OFFSET: LEGO1 0x100ad120
inline int MxBinaryTree::TreeValueCompare(TreeValue *&p_val0, TreeValue *&p_val1)
{
  // For strcmp, a result greater than 0 means that b > a.
  // So: for this function, return TRUE if:
  // * string values are non-equal
  // * string values are in order: p_val0 < p_val1

  return strcmp(p_val0->m_str.GetData(), p_val1->m_str.GetData()) > 0;
}

inline TreeNode *MxBinaryTree::Find(TreeValue *&p_value)
{
  TreeNode *node = Search(p_value);
  
  // we should only get the root back if the tree is empty.
  if (m_root == node || TreeValueCompare(p_value, node->m_value)) {
    node = m_root; // ??
  }

  return node->m_child0;
}

#endif //MXBINARYTREE_H