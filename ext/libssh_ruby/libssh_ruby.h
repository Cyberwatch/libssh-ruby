#ifndef LIBSSH_RUBY_H
#define LIBSSH_RUBY_H 1

/* Don't use deprecated functions */
#define LIBSSH_LEGACY_0_4

#include <ruby/ruby.h>
#include <libssh/libssh.h>

extern VALUE rb_mLibSSH;
extern VALUE rb_cLibSSHKey;

void Init_libssh_ruby(void);
void Init_libssh_session(void);
void Init_libssh_channel(void);
void Init_libssh_error(void);
void Init_libssh_key(void);
void Init_libssh_pki(void);
void Init_libssh_scp(void);

void libssh_ruby_raise(ssh_session session);

// Underlying structure behind LibSSH::Session.
struct libssh_ruby_session {
  ssh_session session;
};

ssh_session libssh_ruby_get_session(VALUE session);

struct KeyHolderStruct {
  ssh_key key;
};
typedef struct KeyHolderStruct KeyHolder;

KeyHolder *libssh_ruby_key_holder(VALUE key);

#endif /* LIBSSH_RUBY_H */
