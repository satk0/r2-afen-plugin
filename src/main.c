/* radare - Copyright 2024 - satk0 */

#define R_LOG_ORIGIN "core.afen"

#include <r_core.h>

typedef struct RAfenRepl {
	char *old_name;
	char *new_name;
} RAfenRepl;

static R_TH_LOCAL RList *old_names;
static R_TH_LOCAL RList *new_names;
static R_TH_LOCAL HtUP *ht; // hash table

// afen parser
static int r_parse_afen(RParse *p, const char *data, char *str) {
	char *input = strdup (data);

	//RCmd *rcmd = (RCmd *) p->user;
	//RCore *core = (RCore *) rcmd->data;
	RCore *core = (RCore *) p->analb.anal->user;

	int i, n = r_list_length (old_names);
	R_LOG_INFO ("offset: 0x%08" PFMT64x "\n", core->offset);
	RAnalFunction *fcn = r_anal_get_function_at (core->anal, core->offset);

	if (fcn) {
		R_LOG_INFO ("Function at 0x%08" PFMT64x "\n", fcn->addr);
	} else {
		R_LOG_INFO ("No Function at 0x%08" PFMT64x "\n", core->offset);
		return false;
	}

	RAfenRepl *repl = ht_up_find (ht, fcn->addr, NULL);
	if (repl) {
		R_LOG_INFO ("LOL");
		R_LOG_INFO ("New name: %s", repl->new_name);
		R_LOG_INFO ("Old name: %s", repl->old_name);
	}



	if (n) {
		RListIter *sio = old_names->head;
		RListIter *sin = new_names->head;

		for (i = 0; i < n; i++) {
			input = r_str_replace_all (input, sio->data, sin->data);

			sio = r_list_iter_get_next (sio);
			sin = r_list_iter_get_next (sin);
		}

	}

	strcpy (str, input);
	return true;
}

// RParse plugin Definition Info
RParsePlugin r_parse_plugin_afen = {
	.name = "afen",
	.desc = "Afen parse plugin",
	.parse = r_parse_afen,
};

static inline void repl_value_free(HtUPKv *kv) {
	RAfenRepl *repl = (RAfenRepl *) kv->value;
	if (repl) {
		R_FREE (repl->old_name);
		R_FREE (repl->new_name);
	}
}


// sets afen parser
static int r_core_init_afen(void *user, const char *input) {
	RCmd *rcmd = (RCmd *) user;
	RCore *core = (RCore *) rcmd->data;

	r_parse_plugin_add (core->parser, &r_parse_plugin_afen);

	/*<ut64 fcnptr, RAfenRepl *repl>*/ ht = ht_up_new (NULL, repl_value_free, NULL);
	if (!ht) {
		R_LOG_ERROR ("Fail to initialize hashtable");
		ht_up_free (ht);
		return false;
	}

	old_names = r_list_new ();
	new_names = r_list_new ();
	// newf instead of new
	
	return true;
}

static int r_core_fini_afen(void *user, const char *input) {
	r_list_free (old_names);
	r_list_free (new_names);
	old_names = NULL;
	new_names = NULL;

	ht_up_free (ht);
	ht = NULL;

	return true;
}

static int r_core_call_afen(void *user, const char *input) {
	RCore *core = (RCore *) user;

	if (r_str_startswith (input, "afen")) {
		RAnalFunction *fcn = r_anal_get_function_at (core->anal, core->offset);

		if (fcn) {
			r_cons_printf ("Function at 0x%08" PFMT64x "\n", fcn->addr);
		} else {
			r_cons_printf ("No Function at 0x%08" PFMT64x "\n", core->offset);
			return false;
		}

		int argc;
		R_LOG_INFO ("test: %s", input);
		char **argv = r_str_argv (input, &argc);
		R_LOG_INFO ("test: %d", argc);

		if (argc != 3) {
			r_cons_printf ("Usage: afen new_name old_name\n");
			return true;
		}

		if (!argv) {
			R_LOG_ERROR ("Can't get args");
			return false;
		}

		RAfenRepl *repl = (RAfenRepl*) malloc (sizeof (RAfenRepl));
		repl->new_name = argv[1];
		repl->old_name = argv[2];
		

		R_LOG_INFO ("Repl:");
		R_LOG_INFO ("New Name: %s", repl->new_name);
		R_LOG_INFO ("Old Name: %s", repl->old_name);
		ht_up_insert (ht, fcn->addr, repl);
		R_LOG_INFO ("LOL0");

		r_list_append (new_names, argv[1]);
		r_list_append (old_names, argv[2]);

		return true;
	}
	return false;
}


// RCore plugin Definition Info
RCorePlugin r_core_plugin_afen = {
	.meta = {
		.name = "core-afen",
		.desc = "Rename expressions",
		.author = "satk0",
		.license = "GPLv3",
	},
	.call = r_core_call_afen,
	.init = r_core_init_afen,
	.fini = r_core_fini_afen
};


#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_CORE,
	.data = &r_core_plugin_afen,
	.version = R2_VERSION
};
#endif
