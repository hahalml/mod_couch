/* 
 * FreeSWITCH Modular Media Switching Software Library / Soft-Switch Application
 * Copyright (C) 2005-2011, Anthony Minessale II <anthm@freeswitch.org>
 *
 * Version: MPL 1.1
 *
 * The contents of this file are subject to the Mozilla Public License Version
 * 1.1 (the "License"); you may not use this file except in compliance with
 * the License. You may obtain a copy of the License at
 * http://www.mozilla.org/MPL/
 *
 * Software distributed under the License is distributed on an "AS IS" basis,
 * WITHOUT WARRANTY OF ANY KIND, either express or implied. See the License
 * for the specific language governing rights and limitations under the
 * License.
 *
 * The Original Code is FreeSWITCH Modular Media Switching Software Library / Soft-Switch Application
 *
 * The Initial Developer of the Original Code is
 * Anthony Minessale II <anthm@freeswitch.org>
 * Portions created by the Initial Developer are Copyright (C)
 * the Initial Developer. All Rights Reserved.
 *
 * Based on mod_curl_xml. Original Contributors:
 * 
 * Anthony Minessale II <anthm@freeswitch.org>
 * Bret McDanel <trixter AT 0xdecafbad.com>
 * Justin Cassidy <xachenant@hotmail.com>
 *
 * Ariel Monaco <amonaco@gmail.com>
 *
 * mod_couchdb.c -- Experimental Couchdb Binding for FreeSWITCH
 */
#include <switch.h>
#include <switch_curl.h>

SWITCH_MODULE_LOAD_FUNCTION(mod_couchdb_load);
SWITCH_MODULE_SHUTDOWN_FUNCTION(mod_couchdb_shutdown);
SWITCH_MODULE_DEFINITION(mod_couchdb, mod_couchdb_load, mod_couchdb_shutdown, NULL);

struct xml_binding {
	char *url;
	char *doc;
	char *bindings;
	char *cred;
	char *bind_local;
	uint32_t enable_cacert_check;
	char *ssl_cert_file;
	char *ssl_key_file;
	char *ssl_key_password;
	char *ssl_version;
	char *ssl_cacert_file;
	uint32_t enable_ssl_verifyhost;
	int auth_scheme;
	int timeout;
};

static int keep_files_around = 0;
static int dump_data_console = 0;

typedef struct xml_binding xml_binding_t;

#define XML_CURL_MAX_BYTES 1024 * 1024

struct config_data {
	char *name;
	int fd;
	switch_size_t bytes;
	switch_size_t max_bytes;
	int err;
};

typedef struct hash_node {
	switch_hash_t *hash;
	struct hash_node *next;
} hash_node_t;

static struct {
	switch_memory_pool_t *pool;
	hash_node_t *hash_root;
	hash_node_t *hash_tail;
} globals;

#define COUCHDB_SYNTAX "[file|console|both|none]"

SWITCH_STANDARD_API(couchdb_cli_function)
{
	if (session) {
		return SWITCH_STATUS_FALSE;
	}

	if (zstr(cmd)) {
		goto usage;
	}

	if (!strcasecmp(cmd, "file")) {
		keep_files_around = 1;
        dump_data_console = 0;
	} else if (!strcasecmp(cmd, "console")) {
		keep_files_around = 0;
        dump_data_console = 1;
	} else if (!strcasecmp(cmd, "both")) {
		keep_files_around = 1;
        dump_data_console = 1;
	} else if (!strcasecmp(cmd, "none")) {
		keep_files_around = 0;
        dump_data_console = 0;
	} else {
		goto usage;
	}

	stream->write_function(stream, "OK\n");
	return SWITCH_STATUS_SUCCESS;

  usage:
	stream->write_function(stream, "USAGE: %s\n", COUCHDB_SYNTAX);
	return SWITCH_STATUS_SUCCESS;
}

static size_t file_callback(void *ptr, size_t size, size_t nmemb, void *data)
{
	register unsigned int realsize = (unsigned int) (size * nmemb);
	struct config_data *config_data = data;
	int x;

	config_data->bytes += realsize;

	if (config_data->bytes > config_data->max_bytes) {
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "Oversized file detected [%d bytes]\n", (int) config_data->bytes);
		config_data->err = 1;
		return 0;
	}

	x = write(config_data->fd, ptr, realsize);
	if (x != (int) realsize) {
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "Short write! %d out of %d\n", x, realsize);
	}
	return x;
}

static switch_xml_t fetch_translate_data(const char *section, const char *tag_name, const char *key_name, const char *key_value, switch_event_t *params, void *user_data)
{
	char filename[512] = "";
	switch_CURL *curl_handle = NULL;
	struct config_data config_data;
	switch_xml_t xml = NULL;
	char *data = NULL;
	switch_uuid_t uuid;
	char uuid_str[SWITCH_UUID_FORMATTED_LENGTH + 1];
  
    // amonaco: binding used for mapping parameters
	xml_binding_t *binding = (xml_binding_t *) user_data;

	switch_curl_slist_t *slist = NULL;
	long httpRes = 0;
	char hostname[256] = "";
	char *uri = NULL;

    strncpy(hostname, switch_core_get_switchname(), sizeof(hostname));

	if (!binding) {
		return NULL;
	}

    /* This module always uses GET */
    uri = malloc(strlen(binding->url) + strlen(binding->doc) + 2);
    switch_assert(uri);
    sprintf(uri, "/%s/%s", binding->url, binding->doc);


	switch_uuid_get(&uuid);
	switch_uuid_format(uuid_str, &uuid);

	switch_snprintf(filename, sizeof(filename), "%s%s.tmp.json", SWITCH_GLOBAL_dirs.temp_dir, uuid_str);
	curl_handle = switch_curl_easy_init();

	if (!strncasecmp(binding->url, "https", 5)) {
		switch_curl_easy_setopt(curl_handle, CURLOPT_SSL_VERIFYPEER, 0);
		switch_curl_easy_setopt(curl_handle, CURLOPT_SSL_VERIFYHOST, 0);
	}

	memset(&config_data, 0, sizeof(config_data));

	config_data.name = filename;
	config_data.max_bytes = XML_CURL_MAX_BYTES;

	if ((config_data.fd = open(filename, O_CREAT | O_RDWR | O_TRUNC, S_IRUSR | S_IWUSR)) > -1) {
		if (!zstr(binding->cred)) {
			switch_curl_easy_setopt(curl_handle, CURLOPT_HTTPAUTH, binding->auth_scheme);
			switch_curl_easy_setopt(curl_handle, CURLOPT_USERPWD, binding->cred);
		}

        /* Set CURL options */
		switch_curl_easy_setopt(curl_handle, CURLOPT_POST, 0);
		switch_curl_easy_setopt(curl_handle, CURLOPT_FOLLOWLOCATION, 1);
		switch_curl_easy_setopt(curl_handle, CURLOPT_MAXREDIRS, 10);
		switch_curl_easy_setopt(curl_handle, CURLOPT_URL, uri);
        
        // amonaco: file_callback is passed to libcurl to write 
        // data to file, config_data is the pointer with the data in
        // question.
        //
        // at this point data is already in it's xml version,
        // but we should have a stored version of the json data
  
		switch_curl_easy_setopt(curl_handle, CURLOPT_WRITEFUNCTION, file_callback);

		switch_curl_easy_setopt(curl_handle, CURLOPT_WRITEDATA, (void *) &config_data);
		switch_curl_easy_setopt(curl_handle, CURLOPT_USERAGENT, "freeswitch-xml/1.0");

		if (binding->timeout) {
			switch_curl_easy_setopt(curl_handle, CURLOPT_TIMEOUT, binding->timeout);
			switch_curl_easy_setopt(curl_handle, CURLOPT_NOSIGNAL, 1);
		}

		if (binding->enable_cacert_check) {
			switch_curl_easy_setopt(curl_handle, CURLOPT_SSL_VERIFYPEER, TRUE);
		}

		if (binding->ssl_cert_file) {
			switch_curl_easy_setopt(curl_handle, CURLOPT_SSLCERT, binding->ssl_cert_file);
		}

		if (binding->ssl_key_file) {
			switch_curl_easy_setopt(curl_handle, CURLOPT_SSLKEY, binding->ssl_key_file);
		}

		if (binding->ssl_key_password) {
			switch_curl_easy_setopt(curl_handle, CURLOPT_SSLKEYPASSWD, binding->ssl_key_password);
		}

		if (binding->ssl_version) {
			if (!strcasecmp(binding->ssl_version, "SSLv3")) {
				switch_curl_easy_setopt(curl_handle, CURLOPT_SSLVERSION, CURL_SSLVERSION_SSLv3);
			} else if (!strcasecmp(binding->ssl_version, "TLSv1")) {
				switch_curl_easy_setopt(curl_handle, CURLOPT_SSLVERSION, CURL_SSLVERSION_TLSv1);
			}
		}

		if (binding->ssl_cacert_file) {
			switch_curl_easy_setopt(curl_handle, CURLOPT_CAINFO, binding->ssl_cacert_file);
		}

		if (binding->enable_ssl_verifyhost) {
			switch_curl_easy_setopt(curl_handle, CURLOPT_SSL_VERIFYHOST, 2);
		}

		if (binding->bind_local) {
			curl_easy_setopt(curl_handle, CURLOPT_INTERFACE, binding->bind_local);
		}

        // amonaco: at this point &config_data should still be empty

		switch_curl_easy_perform(curl_handle);
		switch_curl_easy_getinfo(curl_handle, CURLINFO_RESPONSE_CODE, &httpRes);
		switch_curl_easy_cleanup(curl_handle);

        // amonaco: at this point &config_data has json data,
        // file has been written w/ json data

		switch_curl_slist_free_all(slist);
		close(config_data.fd);

	} else {
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "Error Opening temp file!\n");
	}

	if (config_data.err) {
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "Error encountered! [%s]\ndata: [%s]\n", binding->url, data);
		xml = NULL;
	} else {
		if (httpRes == 200) {

            // amonaco: write a wrapper function around
            // !switch_xml_parse_str()! that translates json
            // to xml (thus avoiding opening another fd):
            // switch_xml_parse_str(translate_json_file(filename))
   
			if (!(xml = switch_xml_parse_file(filename))) {
				switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "Error Parsing Result! [%s]\ndata: [%s]\n", binding->url, data);
			}

		} else {
			switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "Received HTTP error %ld trying to fetch %s\ndata: [%s]\n", httpRes, binding->url, data);
			xml = NULL;
		}
	}

    /* Dump data to console for debug */
    if (dump_data_console) {
        // review this (char *) cast
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_CONSOLE, "Generated XML dump:\n%s\n", (char *) &config_data); 
		// switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_CONSOLE, "Original JSON dump:\n%s\n", &json_data);
    }

	/* Debug by leaving the file behind for review */
	if (keep_files_around) {
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_CONSOLE, "Genarated XML is in %s\n", filename);
	} else {
		if (unlink(filename) != 0) {
			switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "Generated response file [%s] delete failed\n", filename);
		}
	}

	switch_safe_free(data);
    switch_safe_free(uri);

	return xml;
}

#define ENABLE_PARAM_VALUE "enabled"
static switch_status_t do_config(void)
{
	char *cf = "couchdb_curl.conf";
    switch_channel_t *channel = NULL;
	switch_xml_t cfg, xml, bindings_tag, binding_tag, param;
	xml_binding_t *binding = NULL;
	int x = 0;

	if (!(xml = switch_xml_open_cfg(cf, &cfg, NULL))) {
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "open of %s failed\n", cf);
		return SWITCH_STATUS_TERM;
	}

	if (!(bindings_tag = switch_xml_child(cfg, "bindings"))) {
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "Missing <bindings> tag!\n");
		goto done;
	}

	for (binding_tag = switch_xml_child(bindings_tag, "binding"); binding_tag; binding_tag = binding_tag->next) {
		char *bname = (char *) switch_xml_attr_soft(binding_tag, "name");
		char *url = NULL;
		char *doc = NULL;
		char *bind_local = NULL;
		char *bind_cred = NULL;
		char *bind_mask = NULL;
		int timeout = 0;
		uint32_t enable_cacert_check = 0;
		char *ssl_cert_file = NULL;
		char *ssl_key_file = NULL;
		char *ssl_key_password = NULL;
		char *ssl_version = NULL;
		char *ssl_cacert_file = NULL;
		uint32_t enable_ssl_verifyhost = 0;
		// hash_node_t *hash_node;
		int auth_scheme = CURLAUTH_BASIC;

		for (param = switch_xml_child(binding_tag, "param"); param; param = param->next) {
			char *var = (char *) switch_xml_attr_soft(param, "name");
			char *val = (char *) switch_xml_attr_soft(param, "value");

			if (!strcasecmp(var, "backend-url")) {
				bind_mask = (char *) switch_xml_attr_soft(param, "binding");
				if (val) {
					url = val;
				}
			} else if (!strcasecmp(var, "doc-index-var")) {
				doc = val;
			} else if (!strcasecmp(var, "gateway-credentials")) {
				bind_cred = val;
			} else if (!strcasecmp(var, "auth-scheme")) {
				if (*val == '=') {
					auth_scheme = 0;
					val++;
				}

				if (!strcasecmp(val, "basic")) {
					auth_scheme |= CURLAUTH_BASIC;
				} else if (!strcasecmp(val, "digest")) {
					auth_scheme |= CURLAUTH_DIGEST;
				} else if (!strcasecmp(val, "NTLM")) {
					auth_scheme |= CURLAUTH_NTLM;
				} else if (!strcasecmp(val, "GSS-NEGOTIATE")) {
					auth_scheme |= CURLAUTH_GSSNEGOTIATE;
				} else if (!strcasecmp(val, "any")) {
					auth_scheme = CURLAUTH_ANY;
				}
	
			} else if (!strcasecmp(var, "timeout")) {
				int tmp = atoi(val);
				if (tmp >= 0) {
					timeout = tmp;
				} else {
					switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "Can't set a negative timeout!\n");
				}
			} else if (!strcasecmp(var, "enable-cacert-check") && switch_true(val)) {
				enable_cacert_check = 1;
			} else if (!strcasecmp(var, "ssl-cert-path")) {
				ssl_cert_file = val;
			} else if (!strcasecmp(var, "ssl-key-path")) {
				ssl_key_file = val;
			} else if (!strcasecmp(var, "ssl-key-password")) {
				ssl_key_password = val;
			} else if (!strcasecmp(var, "ssl-version")) {
				ssl_version = val;
			} else if (!strcasecmp(var, "ssl-cacert-file")) {
				ssl_cacert_file = val;
			} else if (!strcasecmp(var, "enable-ssl-verifyhost") && switch_true(val)) {
				enable_ssl_verifyhost = 1;
			} else if (!strcasecmp(var, "bind-local")) {
				bind_local = val;
			}
		}

		if (!url) {
			switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "Binding has no url!\n");
            // amonaco: remember to cleanup
			// if (vars_map)
		    //		switch_core_hash_destroy(&vars_map);
			continue;
		}

		if (!(binding = malloc(sizeof(*binding)))) {
	        /* No more bindings */	
			goto done;
		}
		memset(binding, 0, sizeof(*binding));

		binding->auth_scheme = auth_scheme;
		binding->timeout = timeout;
		binding->url = strdup(url);
		binding->doc = strdup(doc);
		switch_assert(binding->url);

		if (bind_local != NULL) {
			binding->bind_local = strdup(bind_local);
		}

		if (bind_mask) {
			binding->bindings = strdup(bind_mask);
		}

		if (bind_cred) {
			binding->cred = strdup(bind_cred);
		}

		binding->enable_cacert_check = enable_cacert_check;

		if (ssl_cert_file) {
			binding->ssl_cert_file = strdup(ssl_cert_file);
		}

		if (ssl_key_file) {
			binding->ssl_key_file = strdup(ssl_key_file);
		}

		if (ssl_key_password) {
			binding->ssl_key_password = strdup(ssl_key_password);
		}

		if (ssl_version) {
			binding->ssl_version = strdup(ssl_version);
		}

		if (ssl_cacert_file) {
			binding->ssl_cacert_file = strdup(ssl_cacert_file);
		}

		binding->enable_ssl_verifyhost = enable_ssl_verifyhost;

        // amonaco: check mandatory field doc-index-var above
        // and map / dup variable for building the url
        //

        if (session) 
            channel = switch_core_session_get_channel(session);
        doc = switch_channel_get_variable(channel, "sip_auth_username");

        if (!zstr(doc)) {
            // error
        }

		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_NOTICE, "Binding [%s] CouchDB Backend [%s] [%s]\n",
						  zstr(bname) ? "N/A" : bname, binding->url, binding->bindings ? binding->bindings : "all");

		switch_xml_bind_search_function(fetch_translate_data, switch_xml_parse_section_string(binding->bindings), binding);
		x++;
		binding = NULL;
	}

  done:
	switch_xml_free(xml);

	return x ? SWITCH_STATUS_SUCCESS : SWITCH_STATUS_FALSE;
}

SWITCH_MODULE_LOAD_FUNCTION(mod_couchdb_load)
{
	switch_api_interface_t *xml_curl_api_interface;

	/* connect my internal structure to the blank pointer passed to me */
	*module_interface = switch_loadable_module_create_module_interface(pool, modname);

	memset(&globals, 0, sizeof(globals));
	globals.pool = pool;
	globals.hash_root = NULL;
	globals.hash_tail = NULL;

	if (do_config() != SWITCH_STATUS_SUCCESS) {
		return SWITCH_STATUS_FALSE;
	}

	SWITCH_ADD_API(xml_curl_api_interface, "couchdb", "CouchDB Bindings", couchdb_cli_function, COUCHDB_SYNTAX);

	switch_console_set_complete("add couchdb file");
	switch_console_set_complete("add couchdb console");
	switch_console_set_complete("add couchdb both");
	switch_console_set_complete("add couchdb none");

	/* indicate that the module should continue to be loaded */
	return SWITCH_STATUS_SUCCESS;
}

SWITCH_MODULE_SHUTDOWN_FUNCTION(mod_couchdb_shutdown)
{
	hash_node_t *ptr = NULL;

	while (globals.hash_root) {
		ptr = globals.hash_root;
		switch_core_hash_destroy(&ptr->hash);
		globals.hash_root = ptr->next;
		switch_safe_free(ptr);
	}

	switch_xml_unbind_search_function_ptr(fetch_translate_data);

	return SWITCH_STATUS_SUCCESS;
}

/* For Emacs:
 * Local Variables:
 * mode:c
 * indent-tabs-mode:t
 * tab-width:4
 * c-basic-offset:4
 * End:
 * For VIM:
 * vim:set softtabstop=4 shiftwidth=4 tabstop=4:
 */
