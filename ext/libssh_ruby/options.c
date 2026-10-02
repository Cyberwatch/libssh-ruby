#include "libssh_ruby.h"

static ID id_host, id_port, id_user, id_timeout, id_key_exchange, id_hmac_c_s,
          id_hmac_s_c, id_hostkeys, id_publickey_accepted_types,
          id_stricthostkeycheck, id_password, id_key, id_proxy_jump;

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
  id_password                 = rb_intern("password");
  id_key                      = rb_intern("key");
  id_proxy_jump               = rb_intern("proxy_jump");
}

void libssh_ruby_free_options(struct libssh_ruby_options *options) {
  if (!options) return;

  if (options->password)
    memset(options->password, 0, strlen(options->password));

  ruby_xfree(options->host);
  ruby_xfree(options->user);
  ruby_xfree(options->key_exchange);
  ruby_xfree(options->hmac_c_s);
  ruby_xfree(options->hmac_s_c);
  ruby_xfree(options->hostkeys);
  ruby_xfree(options->publickey_accepted_types);
  ruby_xfree(options->password);
  ssh_key_free(options->key);
  libssh_ruby_free_options(options->proxy_jump);
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
                              const char* *error) {
  if (options->host) {
    // Host is first because it may set the user and port too.
    int rc = ssh_options_set(session, SSH_OPTIONS_HOST, options->host);
    if (rc < 0) {
      *error = "Invalid host.";
      return rc;
    }
  }

  if (options->port) {
    int rc = ssh_options_set(session, SSH_OPTIONS_PORT, &options->port);
    if (rc < 0) {
      *error = "Invalid port.";
      return rc;
    }
  }

  if (options->user) {
    int rc = ssh_options_set(session, SSH_OPTIONS_USER, options->user);
    if (rc < 0) {
      *error = "Invalid user.";
      return rc;
    }
  }

  if (options->timeout) {
    int rc = ssh_options_set(session, SSH_OPTIONS_TIMEOUT, &options->timeout);
    if (rc < 0) {
      *error = "Invalid timeout.";
      return rc;
    }
  }

  if (options->key_exchange) {
    int rc = ssh_options_set(session, SSH_OPTIONS_KEY_EXCHANGE, options->key_exchange);
    if (rc < 0) {
      *error = "Invalid key exchange methods.";
      return rc;
    }
  }

  if (options->hmac_c_s) {
    int rc = ssh_options_set(session, SSH_OPTIONS_HMAC_C_S, options->hmac_c_s);
    if (rc < 0) {
      *error = "Invalid client-to-server HMAC algorithms.";
      return rc;
    }
  }

  if (options->hmac_s_c) {
    int rc = ssh_options_set(session, SSH_OPTIONS_HMAC_S_C, options->hmac_s_c);
    if (rc < 0) {
      *error = "Invalid server-to-client HMAC algorithms.";
      return rc;
    }
  }

  if (options->hostkeys) {
    int rc = ssh_options_set(session, SSH_OPTIONS_HOSTKEYS, options->hostkeys);
    if (rc < 0) {
      *error = "Invalid server host key types.";
      return rc;
    }
  }

  if (options->publickey_accepted_types) {
    int rc = ssh_options_set(session, SSH_OPTIONS_PUBLICKEY_ACCEPTED_TYPES, options->publickey_accepted_types);
    if (rc < 0) {
      *error = "Invalid public key algorithms.";
      return rc;
    }
  }

  if (options->stricthostkeycheck != -1) {
    int rc = ssh_options_set(session, SSH_OPTIONS_STRICTHOSTKEYCHECK, &options->stricthostkeycheck);
    if (rc < 0) {
      *error = "Invalid strict host key check flag.";
      return rc;
    }
  }

  return 0;
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

static ssh_key get_key(VALUE options, ID name) {
  VALUE value = rb_funcallv_public(options, name, 0, NULL);
  if (NIL_P(value))
    return NULL;

  ssh_key key = NULL;
  int rc = ssh_pki_import_privkey_base64(StringValueCStr(value), NULL, NULL, NULL, &key);
  if (rc != SSH_OK)
    rb_raise(rb_eArgError, "Invalid base64 private key.");

  return key;
}

static struct libssh_ruby_options* get_options(VALUE options, ID name) {
  VALUE value = rb_funcallv_public(options, name, 0, NULL);
  return NIL_P(value) ? NULL : libssh_ruby_clone_options(value);
}

static VALUE copy_options(VALUE data) {
  struct copy_options_args *args = (void*) data;
  VALUE in = args->in;
  struct libssh_ruby_options* out = args->out;

  out->host                     = get_string (in, id_host);
  out->port                     = get_uint   (in, id_port);
  out->user                     = get_string (in, id_user);
  out->timeout                  = get_long   (in, id_timeout);
  out->key_exchange             = get_string (in, id_key_exchange);
  out->hmac_c_s                 = get_string (in, id_hmac_c_s);
  out->hmac_s_c                 = get_string (in, id_hmac_s_c);
  out->hostkeys                 = get_string (in, id_hostkeys);
  out->publickey_accepted_types = get_string (in, id_publickey_accepted_types);
  out->stricthostkeycheck       = get_bool   (in, id_stricthostkeycheck);
  out->password                 = get_string (in, id_password);
  out->key                      = get_key    (in, id_key);
  out->proxy_jump               = get_options(in, id_proxy_jump);

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
