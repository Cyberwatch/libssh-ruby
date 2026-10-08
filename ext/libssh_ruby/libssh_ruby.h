#ifndef LIBSSH_RUBY_H
#define LIBSSH_RUBY_H 1

/* Don't use deprecated functions */
#define LIBSSH_LEGACY_0_4

#include <ruby/ruby.h>
#include <libssh/libssh.h>
#include <libssh/callbacks.h>

extern VALUE rb_mLibSSH;

void Init_libssh_ruby(void);
void Init_libssh_options(void);
void Init_libssh_session(void);
void Init_libssh_channel(void);
void Init_libssh_key(void);
void Init_libssh_pki(void);

struct libssh_ruby_error {
  const char* host;    // Borrowed from libssh_ruby_options.
  const char* message; // Static literal.
};

// libssh_ruby_session’s error is accessed from multiple threads, each proxy
// jump having its own.
typedef _Atomic struct libssh_ruby_error libssh_ruby_error;

// C equivalent of LibSSH::Options.
struct libssh_ruby_options {
  char*        host;                      // SSH_OPTIONS_HOST
  unsigned int port;                      // SSH_OPTIONS_PORT
  char*        user;                      // SSH_OPTIONS_USER
  long         timeout;                   // SSH_OPTIONS_TIMEOUT
  char*        key_exchange;              // SSH_OPTIONS_KEY_EXCHANGE
  char*        hmac_c_s;                  // SSH_OPTIONS_HMAC_C_S
  char*        hmac_s_c;                  // SSH_OPTIONS_HMAC_S_C
  char*        hostkeys;                  // SSH_OPTIONS_HOSTKEYS
  char*        publickey_accepted_types;  // SSH_OPTIONS_PUBLICKEY_ACCEPTED_TYPES
  int          stricthostkeycheck;        // SSH_OPTIONS_STRICTHOSTKEYCHECK

  ssh_key      host_publickey;
  char*        password;
  ssh_key      key;

  struct libssh_ruby_options *proxy_jump;
};

struct libssh_ruby_options* libssh_ruby_clone_options(VALUE options);
int libssh_ruby_apply_options(struct libssh_ruby_options *options, ssh_session session, libssh_ruby_error *error);
void libssh_ruby_free_options(struct libssh_ruby_options *options);

struct libssh_ruby_proxy_jump {
  struct ssh_jump_callbacks_struct callbacks;
  struct libssh_ruby_options *options; // Borrowed.
  libssh_ruby_error *error; // From the root libssh_ruby_session.
};

// Underlying structure behind LibSSH::Session.
struct libssh_ruby_session {
  ssh_session session;
  struct libssh_ruby_options *options;
  struct libssh_ruby_proxy_jump *proxy_jumps;
  char* proxy_jump_uris;
  libssh_ruby_error error;
};

ssh_session libssh_ruby_get_session(VALUE session);

void libssh_ruby_set_error(libssh_ruby_error *error, struct libssh_ruby_options *context, const char* message);
[[noreturn]] void libssh_ruby_raise(VALUE session);

// Moves an ssh_key’s ownership into a LibSSH::Key. Frees the key on error.
VALUE libssh_ruby_wrap_key(ssh_key key);
ssh_key libssh_ruby_unwrap_key(VALUE key);

#endif /* LIBSSH_RUBY_H */
