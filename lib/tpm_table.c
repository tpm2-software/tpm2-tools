#include "tpm_table.h"

#include <stdlib.h>
#include <string.h>


typedef struct entry entry;
struct entry {
	char *key;
	char *value;
	entry *next;
};

struct tpm_table {
	size_t size;
	entry *head;
};

tpm_table *tpm_table_new(void) {

	return calloc(sizeof(tpm_table), 1);
}

bool tpm_table_push(tpm_table *t, const char *key, const char *value) {

	entry *e = malloc(sizeof(*e));
	if (!e) {
		return false;
	}

	e->key = strdup(key);
	if (!e->key) {
		free(e);
		return false;
	}

	e->value = strdup(value);
	if (!e->value) {
		free(e->key);
		free(e);
		return false;
	}

	t->size++;
	e->next = t->head;
	t->head = e;

	return true;
}

size_t tpm_table_size(tpm_table *t) {

	return t->size;
}

int tpm_table_foreach(tpm_table *t, tpm_table_callback cb, void *userdata) {

	size_t i;
	entry *e = t->head;
	for (i=0; i < t->size; i++) {
		int rc = cb(e->key, e->value, userdata);
		if (rc) {
			return rc;
		}
		e = e->next;
	}

	return 0;
}

void tpm_table_free(tpm_table *t) {

	size_t i;
	entry *e = t->head;
	for(i=0; i < t->size; i++) {
		entry *old = e;
		free(e->key);
		free(e->value);
		e = e->next;
		free(old);
	}
	free(t);
}
