#ifndef __AST_H
#define __AST_H

#include "pg_header.h"

#define MAX_COLNAME_LENGTH 128

#define CFREE(a) do { 	\
	if (a) pfree(a);       \
	a = NULL;		          \
}while(0)

#define FCLOSE(a) do { 	\
	if (a) fclose(a);       \
	a = NULL;		          \
}while(0)

#define CERROR(msg)  do {  \
  yyerror(scanner,mod,msg);  \
  return 1; \
}while(0)

#define cnewNode(size, tag) \
({                      \
     CNode *_result;  \
     Assert((size) >= sizeof(CNode));    /* 检测申请的内存大小，>>=sizeof(Node) */ \
     _result = (CNode *) palloc(size);   /* 申请内存 */ \
     _result->type = (tag);             /*设置TypeTag */ \
     _result;                   		/*返回值*/\
})
#define makeCNode(_type_) ((_type_ *)cnewNode(sizeof(_type_),C_##_type_))
#define cnodeTag(nodeptr) (((const CNode *)(nodeptr))->type)
#define CNodeSetTag(nodeptr,t)	(((CNode*)(nodeptr))->type = (t))  
#define IsC(nodeptr,_type_)		(cnodeTag(nodeptr) == C_##_type_)  /* IsA(stmt,T_Stmt)*/
#define cforeach(cell, l)	\
	for ((cell) = clist_head(l); (cell) != NULL; (cell) = clnext(cell))

#define CNIL					((CList *) NULL)
#define clnext(lc)				((lc)->next)
#define clfirst(lc)				((lc)->data.ptr_value)
#define clist_make1(x1)      clcons(x1, CNIL)
#define IsPointerCList(l)    ((l) == CNIL || IsC((l), CList))

typedef enum CNodeTag
{
    C_Node,
    C_CList,
    C_Cpro,
    C_CproList
} CNodeTag;

typedef struct CNode
{
    CNodeTag type;
} CNode;

typedef struct CListCell CListCell;

struct CListCell
{
  union
  {
    void    *ptr_value;   /* data */
    int     int_value;
  }       data;
  CListCell    *next;  
};

typedef struct CList
{
  CNodeTag   type;   /* T_List T_IntList .... */
  int       length; /* length of this list */
  CListCell  *head;
  CListCell  *tail;
} CList;

typedef struct CproList
{
  CNodeTag             type;
  unsigned int        cpunum;
  unsigned long int   pidnum;
} CproList;

typedef struct Cpro
{
  CNodeTag             type;
  CList           *cproList;
} Cpro;

typedef struct
{
    FILE        *src;
    int         cnum;

	bool		cproIsNull;
    Cpro        *cpro;

} module;


CList	*clappend(CList *list, void *datum);
CList	*clcons(void *datum, CList *list);
CList	*new_clist(CNodeTag type);
void	check_clist_invariants(const CList *list);
void	new_head_ccell(CList *list);
void	new_tail_ccell(CList *list);
void	clist_free(CList *list);
void	delete_cpro(Cpro *cpro);
void	delete_cpro_module(module *mod);

static inline CListCell * clist_head(const CList *l){	return l ? l->head : NULL;}
static inline CListCell * clist_tail(CList *l)		{	return l ? l->tail : NULL;}
static inline int clist_length(const CList *l)		{	return l ? l->length : 0;}

int parse_module(module *mod);
module *new_module_from_file(const char *filename);
module *new_module_from_stdin(void);
module *new_module_from_string(char *src);

#endif
