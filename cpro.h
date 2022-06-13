#ifndef __CPRO_H__
#define __CPRO_H__

#include "ast.h"

#define CPRO_MIN (60)
#define CPRO_DAY (3600 * 24)

#define xpfree(var_) \
	do { \
		if (var_ != NULL) \
		{ \
			pfree(var_); \
			var_ = NULL; \
		} \
	} while (0)

#define xpstrdup(tgtvar_, srcvar_) \
	do { \
		if (srcvar_) \
			tgtvar_ = pstrdup(srcvar_); \
		else \
			tgtvar_ = NULL; \
	} while (0)

#define xstreq(tgtvar_, srcvar_) \
	(((tgtvar_ == NULL) && (srcvar_ == NULL)) || \
	 ((tgtvar_ != NULL) && (srcvar_ != NULL) && (strcmp(tgtvar_, srcvar_) == 0)))


#define PG_CONNECT_PARAMS "hostaddr=127.0.0.1 port=%d user=%s dbname=%s"


typedef unsigned long long int CPRO_ULLONG;

typedef struct cprodbstatSharedState
{
	LWLock		*lock;                       /* protects hashtable search/modification */
	bool            is_enable;              /* Whether to enable the feature or not */
	int             cwc_snapid;
	slock_t         elock;                  /* protects the variable `is_enable` */
} cprodbstatSharedState;

typedef struct cprodbstatworkernode
{
	char addr[32];
	int port;
} cprodbstatworkernode;

typedef struct cprostorage
{
	CPRO_ULLONG *cpro_arr;
	int cpu_num;
} cprostorage;


Size	cprodbstat_memsize(void);
bool	beentryCheckState(PgBackendStatus *bs);
char	*CurrentUserName(void);
char	*parse_cpro_list(cprostorage *cpro);
char	*timestamptz_2_str_en(TimestampTz t);
char	*timestamptz_2_str_st(TimestampTz t);
int		GetCpuNum(void);
void	CproWorkerMain(Datum arg);
void	cleanupcproinfo(Relation heap,AttrNumber columnnum,TimestampTz currenttime);
void	collect_cpro_info(cprostorage *cpro);
void	cpro_info(cprostorage *cpro);
TimestampTz	timestamp2timestamptz(Timestamp timestamp);

#endif
