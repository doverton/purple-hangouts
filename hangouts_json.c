/*
 * Hangouts Plugin for libpurple/Pidgin
 * Copyright (c) 2015-2016 Eion Robb, Mike Ruprecht
 * 
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "hangouts_json.h"

#include <debug.h>

gchar *
json_encode(JsonNode *node, gsize *len)
{
	gchar *data;
	JsonGenerator *generator = json_generator_new();
	
	json_generator_set_root(generator, node);
	
	data = json_generator_to_data(generator, len);
	
	g_object_unref(generator);
	
	return data;
}

gchar *
json_pretty_encode(JsonNode *node, gsize *len)
{
	gchar *data;
	JsonGenerator *generator = json_generator_new();
	
	g_object_set(generator, "pretty", TRUE, NULL);
	g_object_set(generator, "indent-char", '\t', NULL);
	g_object_set(generator, "indent", 1, NULL);
	
	json_generator_set_root(generator, node);
	
	data = json_generator_to_data(generator, len);
	
	g_object_unref(generator);
	
	return data;
}

gchar *
json_encode_array(JsonArray *array, gsize *len)
{
	JsonNode *node = json_node_new(JSON_NODE_ARRAY);
	gchar *json;
	
	json_node_set_array(node, array);
	json = json_encode(node, len);
	
	json_node_free(node);
	return json;
}

gchar *
json_encode_object(JsonObject *object, gsize *len)
{
	JsonNode *node = json_node_new(JSON_NODE_OBJECT);
	gchar *json;
	
	json_node_set_object(node, object);
	json = json_encode(node, len);
	
	json_node_free(node);
	return json;
}

JsonNode *
json_decode(const gchar *data, gssize len)
{
	JsonParser *parser = json_parser_new();
	JsonNode *root = NULL;
	
	if (!data || !json_parser_load_from_data(parser, data, len, NULL))
	{
		purple_debug_error("hangouts", "Error parsing JSON: %s\n", data);
	} else {
		root = json_parser_get_root(parser);
		if (root != NULL) {
			root = json_node_copy(root);
		}
	}
	g_object_unref(parser);
	
	return root;
}

JsonArray *
json_decode_array(const gchar *data, gssize len)
{
	JsonNode *root = json_decode(data, len);
	JsonArray *ret;
	
	g_return_val_if_fail(root, NULL);
	
	if (!JSON_NODE_HOLDS_ARRAY(root)) {
		// That ain't my belly button!
		json_node_free(root);
		return NULL;
	}

	ret = json_node_dup_array(root);

	json_node_free(root);
	
	return ret;
}

JsonObject *
json_decode_object(const gchar *data, gssize len)
{
	JsonNode *root = json_decode(data, len);
	JsonObject *ret;
	
	g_return_val_if_fail(root, NULL);
	
	if (!JSON_NODE_HOLDS_OBJECT(root)) {
		// That ain't my thumb, neither!
		json_node_free(root);
		return NULL;
	}
	
	ret = json_node_dup_object(root);

	json_node_free(root);

	return ret;
}

#if JSON_CHECK_VERSION(0, 14, 0)

JsonNode *
hangouts_json_path_query(JsonNode *root, const gchar *expr, GError **error)
{
	JsonNode *ret;
	JsonNode *node;
	JsonArray *result;

	if (g_str_equal(expr, "$")) {
		return root;
	}
	
	node = json_path_query(expr, root, error);

	if (error != NULL)
	{
		json_node_free(node);
		return NULL;
	}

	result = json_node_get_array(node);
	if (json_array_get_length(result) == 0) 
	{
		json_node_free(node);
		return NULL;		
	}
	ret = json_array_dup_element(result, 0);
	json_node_free(node);
	return ret;

}

gchar *
hangouts_json_path_query_string(JsonNode *root, const gchar *expr, GError **error)
{
	gchar *ret;
	JsonNode *rslt;

	rslt = hangouts_json_path_query(root, expr, error);

	if (rslt == NULL)
	{
		return NULL;
	}

	ret = g_strdup(json_node_get_string(rslt));
	json_node_free(rslt);
	return ret;
}

gint64
hangouts_json_path_query_int(JsonNode *root, const gchar *expr, GError **error)
{
	gint64 ret;
	JsonNode *rslt;

	rslt = hangouts_json_path_query(root, expr, error);

	if (rslt == NULL)
	{
		return 0;
	}

	ret = json_node_get_int(rslt);
	json_node_free(rslt);
	return ret;
}

#endif /* JSON_CHECK_VERSION(0, 14, 0) */

gchar *
hangouts_json_extract_sid(JsonNode *node)
{
	gchar *sid = NULL;
#if JSON_CHECK_VERSION(0, 14, 0)
	sid = hangouts_json_path_query_string(node, "$[0][1][1]", NULL);
#else
	if (JSON_NODE_HOLDS_ARRAY(node)) {
		JsonArray *outer = json_node_get_array(node);
		JsonArray *inner1 = json_array_get_array_element(outer, 0);
		JsonArray *inner2 = json_array_get_array_element(inner1, 1);
		sid = g_strdup(json_array_get_string_element(inner2, 1));
	}
#endif
	return sid;
}

gchar *
hangouts_json_extract_gsid(JsonNode *node)
{
	gchar *gsid = NULL;
#if JSON_CHECK_VERSION(0, 14, 0)
	gsid = hangouts_json_path_query_string(node, "$[1][1][0].gsid", NULL);
#else
	if (JSON_NODE_HOLDS_ARRAY(node)) {
		JsonArray *outer = json_node_get_array(node);
		JsonArray *inner1 = json_array_get_array_element(outer, 1);
		JsonArray *inner2 = json_array_get_array_element(inner1, 1);
		JsonObject *object = json_array_get_object_element(inner2, 0);
		gsid = g_strdup(json_object_get_string_member(object, "gsid"));
	}
#endif
	return gsid;
}

gchar *
hangouts_json_person_extract_display_name(JsonNode *node)
{
	gchar *alias = NULL;
#if JSON_CHECK_VERSION(0, 14, 0)
	alias = hangouts_json_path_query_string(node, "$.name[*].displayName", NULL);
#else
	if (JSON_NODE_HOLDS_OBJECT(node)) {
		JsonObject *object = json_node_get_object(node);
		JsonArray *names = json_object_get_array_member(object, "name");

		if (names) {
			int len = json_array_get_length(names);
			int i;

			for (i = 0; i < len; i++) {
				JsonObject *name = json_array_get_object_element(names, i);
				if (name) {
					const gchar *d = json_object_get_string_member(name, "displayName");
					if (d) {
						alias = g_strdup(d);
						break;
					}
				}
			}
		}
	}
#endif
	return alias;
}

gchar *
hangouts_json_person_extract_photo(JsonNode *node)
{
	gchar *photo = NULL;
#if JSON_CHECK_VERSION(0, 14, 0)
	photo = hangouts_json_path_query_string(node, "$.photo[*].url", NULL);
#else
	if (JSON_NODE_HOLDS_OBJECT(node)) {
		JsonObject *object = json_node_get_object(node);
		JsonArray *photos = json_object_get_array_member(object, "photo");

		if (photos) {
			int len = json_array_get_length(photos);
			int i;

			for (i = 0; i < len; i++) {
				JsonObject *url = json_array_get_object_element(photos, i);
				if (url) {
					const gchar *u = json_object_get_string_member(url, "url");
					if (u) {
						photo = g_strdup(u);
						break;
					}
				}
			}
		}
	}
#endif
	return photo;
}

gchar *
hangouts_json_person_extract_app_type(JsonNode *node)
{
	gchar *appType = NULL;
#if JSON_CHECK_VERSION(0, 14, 0)
	appType = hangouts_json_path_query_string(node, "$.inAppReachability[*].appType", NULL);
#else
	if (JSON_NODE_HOLDS_OBJECT(node)) {
		JsonObject *object = json_node_get_object(node);
		JsonArray *reaches = json_object_get_array_member(object, "inAppReachability");

		if (reaches) {
			int len = json_array_get_length(reaches);
			int i;

			for (i = 0; i < len; i++) {
				JsonObject *reach = json_array_get_object_element(reaches, i);
				if (reach) {
					const gchar *a = json_object_get_string_member(reach, "appType");
					if (a) {
						appType = g_strdup(a);
						break;
					}
				}
			}
		}
	}
#endif
	return appType;
}


gchar *
hangouts_json_tidy_blank_arrays(const gchar *json)
{
	static GRegex *tidy_regex = NULL;
	
	if (tidy_regex == NULL) {
		tidy_regex = g_regex_new("\"(\\\\\"|.)*?\"(*SKIP)(*FAIL)|\\[\\](*SKIP)(*FAIL)|(?<=,|\\[)\\s*(?=,|\\])", G_REGEX_OPTIMIZE, 0, NULL);
	}
	
	return g_regex_replace_literal(tidy_regex, json, -1, 0, "null", 0, NULL);
}

