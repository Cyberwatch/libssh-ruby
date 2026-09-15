#include "libssh_ruby.h"

static ID id_host, id_port, id_user, id_timeout, id_key_exchange, id_hmac_c_s,
          id_hmac_s_c, id_hostkeys, id_publickey_accepted_types,
          id_stricthostkeycheck;

void Init_libssh_options(void) {
  id_host                     = rb_intern("host");
  id_port                     = rb_intern("port");
  id_user                     = rb_intern("user");
  id_timeout                  = rb_intern("timeout");
  id_key_exchange             = rb_intern("key_exchange");
  id_hmac_c_s                 = rb_intern("hmac_c_s");
  id_hmac_s_c                 = rb_intern("hmac_s_c");
  id_hostkeys                 = rb_intern("hostkeys");
  id_publickey_accepted_types = rb_intern("publickey_accepted_types");
  id_stricthostkeycheck       = rb_intern("stricthostkeycheck");
}

void libssh_ruby_free_options(struct libssh_ruby_options *options) {
  if (!options) return;
  ruby_xfree(options->host);
  ruby_xfree(options->user);
  ruby_xfree(options);
}

/*
 * Configure the session with the given options.
 * Forward the return code of ssh_options_set.
 * The caller must free() *error.
 * Does not require the GVL.
 */
int libssh_ruby_apply_options(struct libssh_ruby_options *options,
                              ssh_session session,
                              char **error) {
  int rc = SSH_OK;
  *error = NULL;

  if (options->host) {
    // Host is first because it may set the user and port too.
    rc = ssh_options_set(session, SSH_OPTIONS_HOST, options->host);
    if (rc < 0) {
      if (asprintf(error, "Invalid host: %s", options->host) == -1)
        *error = NULL;
      return rc;
    }
  }

  if (options->port) {
    rc = ssh_options_set(session, SSH_OPTIONS_PORT, &options->port);
    if (rc < 0) {
      if (asprintf(error, "Invalid port: %u", options->port) == -1)
        *error = NULL;
      return rc;
    }
  }

  if (options->user) {
    rc = ssh_options_set(session, SSH_OPTIONS_USER, options->user);
    if (rc < 0) {
      if (asprintf(error, "Invalid user: %s", options->user) == -1)
        *error = NULL;
      return rc;
    }
  }

  if (options->timeout) {
    rc = ssh_options_set(session, SSH_OPTIONS_TIMEOUT, &options->timeout);
    if (rc < 0) {
      if (asprintf(error, "Invalid timeout: %ld", options->timeout) == -1)
        *error = NULL;
      return rc;
    }
  }

  if (options->key_exchange) {
    rc = ssh_options_set(session, SSH_OPTIONS_KEY_EXCHANGE, options->key_exchange);
    if (rc < 0) {
      if (asprintf(error, "Invalid key exchange methods: %s", options->key_exchange) == -1)
        *error = NULL;
      return rc;
    }
  }

  if (options->hmac_c_s) {
    rc = ssh_options_set(session, SSH_OPTIONS_HMAC_C_S, options->hmac_c_s);
    if (rc < 0) {
      if (asprintf(error, "Invalid client-to-server HMAC algorithms: %s", options->hmac_c_s) == -1)
        *error = NULL;
      return rc;
    }
  }

  if (options->hmac_s_c) {
    rc = ssh_options_set(session, SSH_OPTIONS_HMAC_S_C, options->hmac_s_c);
    if (rc < 0) {
      if (asprintf(error, "Invalid server-to-client HMAC algorithms: %s", options->hmac_s_c) == -1)
        *error = NULL;
      return rc;
    }
  }

  if (options->hostkeys) {
    rc = ssh_options_set(session, SSH_OPTIONS_HOSTKEYS, options->hostkeys);
    if (rc < 0) {
      if (asprintf(error, "Invalid server host key types: %s", options->hostkeys) == -1)
        *error = NULL;
      return rc;
    }
  }

  if (options->publickey_accepted_types) {
    rc = ssh_options_set(session, SSH_OPTIONS_PUBLICKEY_ACCEPTED_TYPES, options->publickey_accepted_types);
    if (rc < 0) {
      if (asprintf(error, "Invalid public key algorithms: %s", options->publickey_accepted_types) == -1)
        *error = NULL;
      return rc;
    }
  }

  if (options->stricthostkeycheck != -1) {
    rc = ssh_options_set(session, SSH_OPTIONS_STRICTHOSTKEYCHECK, &options->stricthostkeycheck);
    if (rc < 0) {
      if (asprintf(error, "Invalid strict host key check flag: %d", options->stricthostkeycheck) == -1)
        *error = NULL;
      return rc;
    }
  }

  return rc;
}

// libssh_ruby_clone_options ///////////////////////////////////////////////////

struct copy_options_args {
  VALUE in;
  struct libssh_ruby_options *out;
};

static char* clone_string(VALUE string) {
  char* source = StringValuePtr(string);
  size_t length = RSTRING_LEN(string);
  char* copy = ruby_xmalloc(length + 1);
  memcpy(copy, source, length);
  copy[length] = '\0';
  return copy;
}

static char* get_string(VALUE options, ID name) {
  VALUE value = rb_funcallv_public(options, name, 0, NULL);
  return NIL_P(value) ? NULL : clone_string(value);
}

static unsigned int get_uint(VALUE options, ID name) {
  VALUE value = rb_funcallv_public(options, name, 0, NULL);
  return NIL_P(value) ? 0 : NUM2UINT(value);
}

static long get_long(VALUE options, ID name) {
  VALUE value = rb_funcallv_public(options, name, 0, NULL);
  return NIL_P(value) ? 0 : NUM2LONG(value);
}

static int get_bool(VALUE options, ID name) {
  VALUE value = rb_funcallv_public(options, name, 0, NULL);
  return NIL_P(value) ? -1 : RTEST(value);
}

static VALUE copy_options(VALUE data) {
  struct copy_options_args *args = (void*) data;
  VALUE in = args->in;
  struct libssh_ruby_options* out = args->out;

  out->host                     = get_string(in, id_host);
  out->port                     = get_uint  (in, id_port);
  out->user                     = get_string(in, id_user);
  out->timeout                  = get_long  (in, id_timeout);
  out->key_exchange             = get_string(in, id_key_exchange);
  out->hmac_c_s                 = get_string(in, id_hmac_c_s);
  out->hmac_s_c                 = get_string(in, id_hmac_s_c);
  out->hostkeys                 = get_string(in, id_hostkeys);
  out->publickey_accepted_types = get_string(in, id_publickey_accepted_types);
  out->stricthostkeycheck       = get_bool  (in, id_stricthostkeycheck);

  return Qnil;
}

/*
 * Convert Ruby’s LibSSH::Options into C’s libssh_ruby_options.
 * The caller must free the returned value with libssh_ruby_free_options.
 */
struct libssh_ruby_options* libssh_ruby_clone_options(VALUE options) {
  int state;
  struct copy_options_args args = {
    .in  = options,
    .out = RB_ZALLOC(struct libssh_ruby_options),
  };
  rb_protect(copy_options, (VALUE) &args, &state);
  if (state) {
    libssh_ruby_free_options(args.out);
    rb_jump_tag(state);
  }
  return args.out;
}
