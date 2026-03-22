const c = @cImport({
    @cDefine("OPENSSL_GNUC_CLANG_PRAGMA(arg)", "");
    @cInclude("openssl/ssl.h");
    @cInclude("openssl/err.h");
    @cInclude("openssl/evp.h");
    @cInclude("openssl/x509.h");
    @cInclude("openssl/pem.h");
    @cInclude("openssl/bio.h");
    @cInclude("openssl/ec.h");
    @cInclude("openssl/rand.h");
    @cInclude("openssl/hmac.h");
    @cInclude("openssl/sha.h");
    @cInclude("openssl/nid.h");
});

// Re-export all from c import at namespace level
// Source files use `ssl.X509`, `ssl.EVP_PKEY`, etc.
// We need all those available. Since usingnamespace is gone in 0.16,
// re-export via comptime
comptime {
    for (@typeInfo(c).@"struct".decls) |decl| {
        _ = decl;
    }
}

// Users access symbols as ssl_mod.X509 etc.
// This file IS the ssl module, so we export c directly
pub usingnamespace c;
