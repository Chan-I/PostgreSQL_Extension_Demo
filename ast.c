#include "ast.h"
#include "parser.h"
#include "scanner.h"
#include "cpro.h"

CList *
clcons(void *datum, CList *list)
{
	Assert(IsPointerCList(list));

	if (list == CNIL)
		list = new_clist(C_CList);
	else
		new_head_ccell(list);

	clfirst(list->head) = datum;
	return list;
}

CList *
new_clist(CNodeTag type)
{
	CList	   *new_list;
	CListCell   *new_head;

	new_head = (CListCell *) palloc(sizeof(*new_head));
	new_head->next = NULL;
	/* new_head->data is left undefined! */

	new_list = (CList *) palloc(sizeof(*new_list));
	new_list->type = type;
	new_list->length = 1;
	new_list->head = new_head;
	new_list->tail = new_head;

	return new_list;
}

void
new_head_ccell(CList *list)
{
	CListCell   *new_head;

	new_head = (CListCell *) palloc(sizeof(*new_head));
	new_head->next = list->head;

	list->head = new_head;
	list->length++;
}

void
new_tail_ccell(CList *list)
{
	CListCell   *new_tail;

	new_tail = (CListCell *) palloc(sizeof(*new_tail));
	new_tail->next = NULL;

	list->tail->next = new_tail;
	list->tail = new_tail;
	list->length++;
}

CList *
clappend(CList *list, void *datum)
{
	Assert(IsPointerCList(list));

	if (list == CNIL)
		list = new_clist(C_CList);
	else
		new_tail_ccell(list);

	clfirst(list->tail) = datum;
	return list;
}

void
check_clist_invariants(const CList *list)
{
	if (list == CNIL)
		return;

	Assert(list->length > 0);
	Assert(list->head != NULL);
	Assert(list->tail != NULL);

	if (list->length == 1)
		Assert(list->head == list->tail);
	if (list->length == 2)
		Assert(list->head->next == list->tail);
	Assert(list->tail->next == NULL);
}

static void
clist_free_private(CList *list, bool deep)
{
	CListCell   *cell;

	check_clist_invariants(list);

	cell = clist_head(list);
	while (cell != NULL)
	{
		CListCell   *tmp = cell;

		cell = clnext(cell);
		if (deep)
			CFREE(clfirst(tmp));
		CFREE(tmp);
	}

	CFREE(list);
}

void
clist_free(CList *list)
{
	clist_free_private(list, true);
}

module *
new_module_from_file(const char *filename)
{
    module *mod = (module *) palloc(sizeof(module));
    mod->src = fopen(filename, "r");
    return mod;
}

module *
new_module_from_stdin(void)
{
    module *mod = (module *) palloc(sizeof(module));
    mod->src = stdin;
    return mod;
}

module *
new_module_from_string(char *src)
{
    module *mod = (module *) palloc(sizeof(module));
    mod->src = fmemopen(src, strlen(src)+1, "r");
    return mod;
}

int
parse_module(module *mod)
{
    yyscan_t sc;
    int res;

    yylex_init(&sc);
    yyset_in(mod->src, sc);

#ifdef _YYDEBUG
    yydebug = 1;
#endif

    res = yyparse(sc, mod);

    return res;
}

void
delete_cpro(Cpro *cpro)
{
    if (cpro -> cproList != CNIL)
    {
        clist_free(cpro -> cproList);
    }
}

void
delete_cpro_module(module *mod)
{
    if (!mod -> cproIsNull)
    {
        delete_cpro(mod -> cpro);
        mod -> cproIsNull = true;
        CFREE(mod->cpro);
    }
    FCLOSE(mod -> src);
    CFREE(mod);
}
