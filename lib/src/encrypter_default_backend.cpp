#include "encrypter_backend.hpp"
#include "openssl/encrypter_openssl_backend.hpp"

namespace encapi {

EncrypterBackend& default_encrypter_backend() {
	static openssl::OpenSSLEncrypterBackend backend;
	return backend;
}

}
