/* radare - Copyright 2024 - satk0 */

#define R_LOG_ORIGIN "core.afen"

#include <r_core.h>

static char* old_name_str;
static char* new_name_str;

// afen parser
static int r_afen_parse(RParse *p, const char *data, char *str) {
	int res = true;
	char *input = strdup (data);

	if (old_name_str && new_name_str)
		input = r_str_replace_all (input, old_name_str, new_name_str);

	strcpy (str, input);
	return res;
}

// sets afen parser
static int r_cmd_init(void *user, const char *input) {
	RCmd *rcmd = (RCmd *) user;
	RCore *core = (RCore *) rcmd->data;

	old_name_str = (char*) r_malloc(50 * sizeof(char));
	new_name_str = (char*) r_malloc(50 * sizeof(char));

	core->parser->cur->parse = r_afen_parse;
	
	return true;
}

static int r_cmd_fini(void *user, const char *input) {
	r_free(old_name_str);
	r_free(new_name_str);

	return true;
}

static int r_cmd_afen_client(void *user, const char *input) {
	if (r_str_startswith (input, "afen")) {
		RList *splitted = r_str_split_list((char*)input, " ", 3);
		int num_of_spaces = r_list_length(splitted);

		if (num_of_spaces != 3) {
			r_cons_printf("Usage: afen new_name old_name\n");
			return true;
		}

		RListIter *s_iter = NULL;
		s_iter = splitted->head;

		RListIter *new_name = r_list_iter_get_next(s_iter);
		RListIter *old_name = r_list_iter_get_next(new_name);

		strcpy(old_name_str, old_name->data);
		strcpy(new_name_str, new_name->data);

		r_cons_printf ("old_name = %s\n", (char*) old_name->data);
		r_cons_printf ("new_name = %s\n", (char*) new_name->data);

		return true;
	}
	return false;
}

// PLUGIN Definition Info
RCorePlugin r_core_plugin_afen = {
	.meta = {
		.name = "core-afen",
		.desc = "Rename expressions",
		.author = "satk0",
		.license = "GPLv3",
	},
	.call = r_cmd_afen_client,
	.init = r_cmd_init,
	.fini = r_cmd_fini
};


#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_CORE,
	.data = &r_core_plugin_afen,
	.version = R2_VERSION
};
#endif
