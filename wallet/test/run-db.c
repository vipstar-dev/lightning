  #include <lightningd/log.h>

static void db_test_fatal(const char *fmt, ...);
#define db_fatal db_test_fatal

static void db_log_(struct log *log UNUSED, enum log_level level UNUSED, bool call_notifier UNUSED, const char *fmt UNUSED, ...)
{
}
#define log_ db_log_

#include "wallet/db.c"

#include "test_utils.h"

#include <common/amount.h>
#include <common/memleak.h>
#include <stdio.h>
#include <unistd.h>

/* AUTOGENERATED MOCKS START */
/* Generated stub for bigsize_get */
size_t bigsize_get(const u8 *p UNNEEDED, size_t max UNNEEDED, bigsize_t *val UNNEEDED)
{ fprintf(stderr, "bigsize_get called!\n"); abort(); }
/* Generated stub for bigsize_put */
size_t bigsize_put(u8 buf[BIGSIZE_MAX_LEN] UNNEEDED, bigsize_t v UNNEEDED)
{ fprintf(stderr, "bigsize_put called!\n"); abort(); }
/* Generated stub for fatal */
void   fatal(const char *fmt UNNEEDED, ...)
{ fprintf(stderr, "fatal called!\n"); abort(); }
/* AUTOGENERATED MOCKS END */

static char *db_err;
static void db_test_fatal(const char *fmt, ...)
{
	va_list ap;

	/* Fail hard if we're complaining about not being in transaction */
	assert(!strstarts(fmt, "No longer in transaction"));

	va_start(ap, fmt);
	db_err = tal_vfmt(NULL, fmt, ap);
	va_end(ap);
}

void plugin_hook_db_sync(struct db *db UNNEEDED, const char **changes UNNEEDED, const char *final UNNEEDED)
{
}

static struct db *create_test_db(void)
{
	struct db *db;
	char *dsn, filename[] = "/tmp/ldb-XXXXXX";

	int fd = mkstemp(filename);
	if (fd == -1)
		return NULL;
	close(fd);

	dsn = tal_fmt(NULL, "sqlite3://%s", filename);
	db = db_open(NULL, dsn);
	tal_free(dsn);
	return db;
}

static bool test_empty_db_migrate(struct lightningd *ld)
{
	struct db *db = create_test_db();
	CHECK(db);
	db_begin_transaction(db);
	CHECK(db_get_version(db) == -1);
	db_commit_transaction(db);
	db_migrate(ld, db, NULL);
	db_begin_transaction(db);
	CHECK(db_get_version(db) == ARRAY_SIZE(dbmigrations) - 1);
	db_commit_transaction(db);

	tal_free(db);
	return true;
}

static bool test_primitives(void)
{
	struct db_stmt *stmt;
	struct db *db = create_test_db();
	db_err = NULL;
	db_begin_transaction(db);
	CHECK(db->in_transaction);
	db_commit_transaction(db);
	CHECK(!db->in_transaction);
	db_begin_transaction(db);
	db_commit_transaction(db);

	db_begin_transaction(db);
	stmt = db_prepare_v2(db, SQL("SELECT name FROM sqlite_master WHERE type='table';"));
	CHECK_MSG(db_exec_prepared_v2(stmt), "db_exec_prepared must succeed");
	CHECK_MSG(!db_err, "Simple correct SQL command");
	tal_free(stmt);

	stmt = db_prepare_v2(db, SQL("not a valid SQL statement"));
	CHECK_MSG(!db_exec_prepared_v2(stmt), "db_exec_prepared must fail");
	CHECK_MSG(db_err, "Failing SQL command");
	tal_free(stmt);
	db_err = tal_free(db_err);
	db_commit_transaction(db);
	CHECK(!db->in_transaction);
	tal_free(db);

	return true;
}

static bool test_vars(struct lightningd *ld)
{
	struct db *db = create_test_db();
	char *varname = "testvar";
	CHECK(db);
	db_migrate(ld, db, NULL);

	db_begin_transaction(db);
	/* Check default behavior */
	CHECK(db_get_intvar(db, varname, 42) == 42);

	/* Check setting and getting */
	db_set_intvar(db, varname, 1);
	CHECK(db_get_intvar(db, varname, 42) == 1);

	/* Check updating */
	db_set_intvar(db, varname, 2);
	CHECK(db_get_intvar(db, varname, 42) == 2);
	db_commit_transaction(db);

	tal_free(db);
	return true;
}

int main(void)
{
	setup_locale();
	setup_tmpctx();

	bool ok = true;
	/* Dummy for migration hooks */
	struct lightningd *ld = tal(NULL, struct lightningd);
	ld->config = test_config;

	ok &= test_empty_db_migrate(ld);
	ok &= test_vars(ld);
	ok &= test_primitives();

	tal_free(ld);
	tal_free(tmpctx);
	return !ok;
}
