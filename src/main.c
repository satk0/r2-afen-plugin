/* radare - Copyright 2023 - yourname */

#define R_LOG_ORIGIN "core.afen"

#include <r_core.h>

static int (*parsefnc)(RParse *p, const char *data, char *str);

static int parse_modified(RParse *p, const char *data, char *str) {
	int res = parsefnc(p, data, str);
	char *input = strdup (data);
	input = r_str_replace_all (input, "eax, 0", "LOCALVAR");
	strcpy (str, input);
	r_cons_printf ("test");
	return res;
}

static int r_cmd_afen_client(void *user, const char *input) {
	RCore *core = (RCore *) user;

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

		r_cons_printf ("new_name = %s\n", (char*) new_name->data);
		r_cons_printf ("old_name = %s\n", (char*) old_name->data);
		
		RList *list = core->parser->parsers;
		struct r_parse_plugin_t *plugin = core->parser->cur;

		parsefnc = plugin->parse;
		plugin->parse = parse_modified;

		int n = r_list_length(list);
		r_cons_printf ("length of parsers: %d\n", n);
		r_cons_printf ("Cur plugin desc: %s\n", plugin->desc);
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
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_CORE,
	.data = &r_core_plugin_afen,
	.version = R2_VERSION
};
#endif
