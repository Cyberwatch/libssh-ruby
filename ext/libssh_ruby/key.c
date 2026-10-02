#include "libssh_ruby.h"

struct libssh_ruby_key {
  ssh_key key;
};

typedef struct libssh_ruby_key KeyHolder;

VALUE rb_cLibSSHKey;
VALUE rb_mLibSSHPKI;

static void key_free(void *);
static size_t key_memsize(const void *);

static const rb_data_type_t key_type = {
    "ssh_key",
    {NULL, key_free, key_memsize,},
    NULL,
    NULL,
    RUBY_TYPED_WB_PROTECTED | RUBY_TYPED_FREE_IMMEDIATELY,
};

static void key_free(void *arg) {
  KeyHolder *holder = arg;
  if (holder->key != NULL) {
    ssh_key_free(holder->key);
  }
  ruby_xfree(holder);
}

static size_t key_memsize(RB_UNUSED_VAR(const void *arg)) {
  return sizeof(KeyHolder);
}

static VALUE do_wrap_key(VALUE data) {
  struct libssh_ruby_key *holder;
  VALUE object = TypedData_Make_Struct(rb_cLibSSHKey, struct libssh_ruby_key, &key_type, holder);
  holder->key = *(ssh_key*) data;
  return object;
}

VALUE libssh_ruby_wrap_key(ssh_key key) {
  int state;
  // Ensure the key is freed when TypedData_Make_Struct raises an exception.
  VALUE wrapper = rb_protect(do_wrap_key, (VALUE) &key, &state);
  if (state) {
    ssh_key_free(key);
    rb_jump_tag(state);
  }
  return wrapper;
}

static struct libssh_ruby_key *libssh_ruby_key_holder(VALUE key) {
  KeyHolder *holder;
  TypedData_Get_Struct(key, KeyHolder, &key_type, holder);
  return holder;
}

/*
 * @overload sha1
 *  Return the hash in SHA1 form.
 *  @return [String]
 *  @see http://api.libssh.org/stable/group__libssh__pki.html
 */
static VALUE m_sha1(VALUE self) {
  KeyHolder *holder;
  unsigned char *c_hash;
  size_t len;
  VALUE hash;

  holder = libssh_ruby_key_holder(self);
  ssh_get_publickey_hash(holder->key, SSH_PUBLICKEY_HASH_SHA1, &c_hash, &len);
  hash = rb_str_new((char *)c_hash, len);
  ssh_clean_pubkey_hash(&c_hash);

  return hash;
}

/*
 * @overload type
 *  Return the type of a SSH key.
 *  @return [Fixnum]
 *  @see http://api.libssh.org/stable/group__libssh__pki.html ssh_key_type
 */
static VALUE m_type(VALUE self) {
  return INT2FIX(ssh_key_type(libssh_ruby_key_holder(self)->key));
}

/*
 * @overload type_str
 *  Return the type of a SSH key in string format.
 *  @return [String]
 *  @see http://api.libssh.org/stable/group__libssh__pki.html ssh_key_type and
 *    ssh_key_type_to_char
 */
static VALUE m_type_str(VALUE self) {
  return rb_str_new_cstr(
      ssh_key_type_to_char(ssh_key_type(libssh_ruby_key_holder(self)->key)));
}

/*
 * @overload public?
 *  Check if the key is a public key.
 *  @return [Boolean]
 *  @see http://api.libssh.org/stable/group__libssh__pki.html ssh_key_is_public
 */
static VALUE m_public_p(VALUE self) {
  return ssh_key_is_public(libssh_ruby_key_holder(self)->key) ? Qtrue : Qfalse;
}

/*
 * @overload private?
 *  Check if the key is a private key.
 *  @return [Boolean]
 *  @see http://api.libssh.org/stable/group__libssh__pki.html ssh_key_is_private
 */
static VALUE m_private_p(VALUE self) {
  return ssh_key_is_private(libssh_ruby_key_holder(self)->key) ? Qtrue : Qfalse;
}

/*
 * @overload import_privkey_base64(key_data)
 *  Read a private key from memory. Raises an ArgumentError on invalid data.
 *  @param [String] key_data
 *  @return [LibSSH::Key]
 *  @see http://api.libssh.org/stable/group__libssh__pki.html ssh_pki_import_privkey_base64
 */
static VALUE m_pki_import_privkey_base64(RB_UNUSED_VAR(VALUE self), VALUE key_data) {
  ssh_key key;
  if (ssh_pki_import_privkey_base64(StringValueCStr(key_data), NULL, NULL, NULL, &key) != SSH_OK)
    rb_raise(rb_eArgError, "Invalid base64 private key.");
  return libssh_ruby_wrap_key(key);
}

/*
 * @overload export_privkey_to_pubkey(privkey)
 *  Convert a private key to a public key. Raises an ArgumentError on invalid data.
 *  @param [LibSSH::Key] privkey Private key.
 *  @return [LibSSH::Key] Public key.
 *  @see http://api.libssh.org/stable/group__libssh__pki.html ssh_pki_export_privkey_to_pubkey
 */
static VALUE m_pki_export_privkey_to_pubkey(RB_UNUSED_VAR(VALUE self), VALUE privkey) {
  ssh_key pubkey;
  KeyHolder *privkey_holder = libssh_ruby_key_holder(privkey);
  if (ssh_pki_export_privkey_to_pubkey(privkey_holder->key, &pubkey) != SSH_OK)
    rb_raise(rb_eArgError, "Could not extract public key from private key.");
  return libssh_ruby_wrap_key(pubkey);
}

/*
 * @overload export_pubkey_base64(key)
 *  Convert a public key to a base64 encoded key. Raises an ArgumentError on invalid data.
 *  @param [LibSSH::Key] key
 *  @return [String] Base64-encoded key.
 *  @see http://api.libssh.org/stable/group__libssh__pki.html ssh_pki_export_pubkey_base64
 */
static VALUE m_pki_export_pubkey_base64(RB_UNUSED_VAR(VALUE self), VALUE key) {
  KeyHolder *holder = libssh_ruby_key_holder(key);
  char *b64 = NULL;
  int rc = ssh_pki_export_pubkey_base64(holder->key, &b64);
  VALUE rv = Qnil;
  if (rc == SSH_OK) {
    rv = rb_str_new2(b64);
  } else {
    rb_raise(rb_eArgError, "Could not export public key into base64.");
  }
  SSH_STRING_FREE_CHAR(b64);
  return rv;
}

/*
 * Document-class: LibSSH::Key
 * Wrapper for ssh_key struct in libssh.
 *
 * @since 0.1.0
 * @see http://api.libssh.org/stable/group__libssh__pki.html
 */

void Init_libssh_key(void) {
  rb_cLibSSHKey = rb_define_class_under(rb_mLibSSH, "Key", rb_cObject);
  rb_undef_alloc_func(rb_cLibSSHKey);

#define E(name) \
  rb_define_const(rb_cLibSSHKey, "KEYTYPE_" #name, INT2FIX(SSH_KEYTYPE_##name))
  E(UNKNOWN);
  E(DSS);
  E(RSA);
  E(RSA1);
  E(ECDSA);
#ifdef HAVE_CONST_SSH_KEYTYPE_ED25519
  E(ED25519);
#endif
#undef E

  rb_define_method(rb_cLibSSHKey, "sha1",       m_sha1,       0);
  rb_define_method(rb_cLibSSHKey, "type",       m_type,       0);
  rb_define_method(rb_cLibSSHKey, "type_str",   m_type_str,   0);
  rb_define_method(rb_cLibSSHKey, "public?",    m_public_p,   0);
  rb_define_method(rb_cLibSSHKey, "private?",   m_private_p,  0);
}

/*
 * Document-class: LibSSH::PKI
 * Bindings for the ssh_pki_* functions.
 *
 * @since 0.5.0
 * @see http://api.libssh.org/stable/group__libssh__pki.html
 */

void Init_libssh_pki(void) {
  rb_mLibSSHPKI = rb_define_class_under(rb_mLibSSH, "PKI", rb_cObject);
  rb_define_module_function(rb_mLibSSHPKI, "import_privkey_base64", m_pki_import_privkey_base64, 1);
  rb_define_module_function(rb_mLibSSHPKI, "export_privkey_to_pubkey", m_pki_export_privkey_to_pubkey, 1);
  rb_define_module_function(rb_mLibSSHPKI, "export_pubkey_base64", m_pki_export_pubkey_base64, 1);
}
