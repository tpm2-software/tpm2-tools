
#ifndef TPM_TABLE_H_
#define TPM_TABLE_H_

#include <stdbool.h>
#include <stddef.h>

typedef struct tpm_table tpm_table;

typedef int (*tpm_table_callback)(const char *key, const char *value, void *userdata);

/**
 * Creates a new table that stores elements in stack order. Ie the last push
 * is the first element.
 * @return A new table or NULL on error.
 */
tpm_table *tpm_table_new(void);

/**
 * Pushes a new key and value to the table, copying the contents of key
 * and value.
 * @param t
 *  The table to push to.
 * @param key
 *  The key to push.
 * @param value
 *  The value to push.
 * @note
 *  Keys DO NOT have to be unique.
 * @return
 *  true on success, false otheriwse.
 */
bool tpm_table_push(tpm_table *t, const char *key, const char *value);

/**
 * Retrieves the size of the table.
 * @param t
 *  The table whose size to query.
 * @return
 *  The size of the table.
 */
size_t tpm_table_size(tpm_table *t);

/**
 * Table iterator. For each item in the stack, calls the callback routine.
 * @param t
 *  The table to iterate over.
 * @param cb
 *  The callback routine to call for each key value pair.
 * @param userdata
 *  A pointer to user supplied data.
 * @return
 *  Whatever the user returns from the callback. 0 keeps iterating to the end.
 */
int tpm_table_foreach(tpm_table *t, tpm_table_callback cb, void *userdata);

/**
 * Frees all memory of a table.
 * @param t
 *  The table to free.
 */
void tpm_table_free(tpm_table *t);

#endif /* TPM_TABLE_H_ */
