#ifndef LIBSSH_RUBY_H
#define LIBSSH_RUBY_H 1

/* Don't use deprecated functions */
#define LIBSSH_LEGACY_0_4

#include <ruby/ruby.h>
#include <libssh/libssh.h>

extern VALUE rb_mLibSSH;
extern VALUE rb_cLibSSHKey;

void Init_libssh_ruby(void);
void Init_libssh_options(void);
void Init_libssh_session(void);
void Init_libssh_channel(void);
void Init_libssh_error(void);
void Init_libssh_key(void);
void Init_libssh_pki(void);

// C equivalent of LibSSH::Options.
struct libssh_ruby_options {
  char*        host;                      // SSH_OPTIONS_HOST
  unsigned int port;                      // SSH_OPTIONS_PORT
  char*        user;                      // SSH_OPTIONS_USER
  long         timeout;                   // SSH_OPTIONS_TIMEOUT
  const char*  key_exchange;              // SSH_OPTIONS_KEY_EXCHANGE
  const char*  hmac_c_s;                  // SSH_OPTIONS_HMAC_C_S
  const char*  hmac_s_c;                  // SSH_OPTIONS_HMAC_S_C
  const char*  hostkeys;                  // SSH_OPTIONS_HOSTKEYS
  const char*  publickey_accepted_types;  // SSH_OPTIONS_PUBLICKEY_ACCEPTED_TYPES
  int          stricthostkeycheck;        // SSH_OPTIONS_STRICTHOSTKEYCHECK
};

struct libssh_ruby_options* libssh_ruby_clone_options(VALUE options);
int libssh_ruby_apply_options(struct libssh_ruby_options *options, ssh_session session, char **error);
void libssh_ruby_free_options(struct libssh_ruby_options *options);

// Underlying structure behind LibSSH::Session.
struct libssh_ruby_session {
  ssh_session session;
  struct libssh_ruby_options *options;
};

ssh_session libssh_ruby_get_session(VALUE session);
[[noreturn]] void libssh_ruby_raise(ssh_session session);

struct KeyHolderStruct {
  ssh_key key;
};
typedef struct KeyHolderStruct KeyHolder;

KeyHolder *libssh_ruby_key_holder(VALUE key);

#endif /* LIBSSH_RUBY_H */
