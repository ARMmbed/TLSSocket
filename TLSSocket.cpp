/*
 * PackageLicenseDeclared: Apache-2.0
 * Copyright (c) 2017 ARM Limited
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#include "TLSSocket.h"

#define TRACE_GROUP "TLSx"
#include "mbed-trace/mbed_trace.h"
#include "mbedtls/debug.h"

TLSSocket::TLSSocket() : _ssl_ca_pem(NULL) {
    tls_init();
}

TLSSocket::~TLSSocket() {
    tls_free();
    close();
}

void TLSSocket::set_root_ca_cert(const char* root_ca_pem) {
    _ssl_ca_pem = root_ca_pem;
}

void TLSSocket::set_client_cert_key(const char* client_cert_pem, 
        const char* client_private_key_pem) {
    _ssl_cli_pem = client_cert_pem;
    _ssl_pk_pem = client_private_key_pem;
}


nsapi_error_t TLSSocket::connect(const char* hostname, uint16_t port) {
    nsapi_error_t _error = 0;
    const char DRBG_PERS[] = "mbed TLS client";

    set_blocking(false);

    /*
     * Initialize TLS-related stuf.
     */
    int ret;
    if ((ret = mbedtls_ctr_drbg_seed(_ctr_drbg, mbedtls_entropy_func, _entropy,
                        (const unsigned char *) DRBG_PERS,
                        sizeof (DRBG_PERS))) != 0) {
        print_mbedtls_error("mbedtls_crt_drbg_init", ret);
        _error = ret;
        return _error;
    }

    /* Parse CA certification */
    if ((ret = mbedtls_x509_crt_parse(_cacert, (unsigned char *)_ssl_ca_pem,
                        strlen(_ssl_ca_pem) + 1)) != 0) {
        print_mbedtls_error("mbedtls_x509_crt_parse", ret);
        _error = ret;
        return _error;
    }

    /* Parse client certification and private key if it exists. */
    bool isClientAuth = false;
    if((NULL != _ssl_cli_pem) && (NULL != _ssl_pk_pem)) {
        mbedtls_x509_crt_init(_clicert);
        if((ret = mbedtls_x509_crt_parse(_clicert, (unsigned char *)_ssl_cli_pem,
                strlen(_ssl_cli_pem) + 1)) != 0) {
            print_mbedtls_error("mbedtls_x509_crt_parse", ret);
            _error = ret;
            return _error;
        }
    	mbedtls_pk_init(_pkctx);
        if((ret = mbedtls_pk_parse_key(_pkctx, (unsigned char *)_ssl_pk_pem,
                strlen(_ssl_pk_pem) + 1, NULL, 0)) != 0) {
            print_mbedtls_error("mbedtls_pk_parse_key", ret);
            _error = ret;
            return _error;
        }
        isClientAuth = true;
    }

    if ((ret = mbedtls_ssl_config_defaults(_ssl_conf,
                    MBEDTLS_SSL_IS_CLIENT,
                    MBEDTLS_SSL_TRANSPORT_STREAM,
                    MBEDTLS_SSL_PRESET_DEFAULT)) != 0) {
        print_mbedtls_error("mbedtls_ssl_config_defaults", ret);
        _error = ret;
        return _error;
    }

    mbedtls_ssl_conf_ca_chain(_ssl_conf, _cacert, NULL);
    mbedtls_ssl_conf_rng(_ssl_conf, mbedtls_ctr_drbg_random, _ctr_drbg);

    /* It is possible to disable authentication by passing
     * MBEDTLS_SSL_VERIFY_NONE in the call to mbedtls_ssl_conf_authmode()
     */
    mbedtls_ssl_conf_authmode(_ssl_conf, MBEDTLS_SSL_VERIFY_REQUIRED);

#if MBED_CONF_TLS_SOCKET_DEBUG_LEVEL > 0
    mbedtls_ssl_conf_verify(_ssl_conf, my_verify, NULL);
    mbedtls_ssl_conf_dbg(_ssl_conf, my_debug, NULL);
    mbedtls_debug_set_threshold(MBED_CONF_TLS_SOCKET_DEBUG_LEVEL);
#endif

    if ((ret = mbedtls_ssl_setup(_ssl, _ssl_conf)) != 0) {
        print_mbedtls_error("mbedtls_ssl_setup", ret);
        _error = ret;
        return _error;
    }

    mbedtls_ssl_set_hostname(_ssl, hostname);

    mbedtls_ssl_set_bio(_ssl, static_cast<void *>(this),
                                ssl_send, ssl_recv, NULL );

    if(isClientAuth) {
        if((ret = mbedtls_ssl_conf_own_cert(_ssl_conf, _clicert, _pkctx)) != 0) {
            print_mbedtls_error("mbedtls_ssl_conf_own_cert", ret);
            _error = ret;
            return _error;
        }
    }

    /* Connect to the server */
    tr_info("Connecting to %s:%d", hostname, port);
    ret = TCPSocket::connect(hostname, port);
    if (ret != NSAPI_ERROR_OK) {
        tr_error("Failed to connect: %d", ret);
        TCPSocket::close();
        return _error;
    }
    tr_info("Connected.");

    /* Start the handshake, the rest will be done in onReceive() */
    tr_info("Starting the TLS handshake...");
    do {
        ret = mbedtls_ssl_handshake(_ssl);
    } while (ret != 0 && (ret == MBEDTLS_ERR_SSL_WANT_READ ||
            ret == MBEDTLS_ERR_SSL_WANT_WRITE));
    if (ret < 0) {
        print_mbedtls_error("mbedtls_ssl_handshake", ret);
        TCPSocket::close();
        return ret;
    }

    /* It also means the handshake is done, time to print info */
    tr_info("TLS connection to %s:%d established\r\n", hostname, port);

    /* Prints the server certificate and verify it. */
    const size_t buf_size = 1024;
    char* buf = new char[buf_size];
    mbedtls_x509_crt_info(buf, buf_size, "\r    ",
                    mbedtls_ssl_get_peer_cert(_ssl));
    tr_debug("Server certificate:\r\n%s\r\n", buf);

    uint32_t flags = mbedtls_ssl_get_verify_result(_ssl);
    if( flags != 0 ) {
        /* Verification failed. */
        mbedtls_x509_crt_verify_info(buf, buf_size, "\r  ! ", flags);
        tr_error("Certificate verification failed:\r\n%s", buf);
    } else {
        /* Verification succeeded. */
        tr_info("Certificate verification passed");
    }
    delete[] buf;

    return 0;
}

nsapi_error_t TLSSocket::connect(const char* hostname, uint16_t port, const char* root_ca_pem, 
            const char* client_cert_pem, const char* client_pk_pem) {
    set_root_ca_cert(root_ca_pem); 
    set_client_cert_key(client_cert_pem, client_pk_pem);
    return connect(hostname, port);
}


nsapi_error_t TLSSocket::send(const void *data, nsapi_size_t size) {
    int ret = 0;
    unsigned int offset = 0;
    do {
        ret = mbedtls_ssl_write(_ssl,
                                (const unsigned char *) data + offset,
                                size - offset);
        if (ret > 0)
            offset += ret;
    } while (offset < size && (ret > 0 || ret == MBEDTLS_ERR_SSL_WANT_READ ||
            ret == MBEDTLS_ERR_SSL_WANT_WRITE));
    if (ret < 0) {
        print_mbedtls_error("mbedtls_ssl_write", ret);
        return -1;
    }
    return offset;
}

nsapi_size_or_error_t TLSSocket::recv(void *data, nsapi_size_t size) {
    int ret = 0;
    unsigned int offset = 0;
    do {
        ret = mbedtls_ssl_read(_ssl, (unsigned char *) data + offset,
                                size - offset);
        if (ret > 0)
            offset += ret;
    } while ((0 < ret && ret < size) || ret == MBEDTLS_ERR_SSL_WANT_READ || 
            ret == MBEDTLS_ERR_SSL_WANT_WRITE);
    if ((ret < 0) && (ret != MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY)) {
        print_mbedtls_error("mbedtls_ssl_read", ret);
        return ret;
    }
    /* MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY is not considered as error. 
     * Just ignre here. Once connection is closed, mbedtls_ssl_read() 
     * will return 0.
     */
    return offset;
}

void TLSSocket::print_mbedtls_error(const char *name, int err) {
    char *buf = new char[128];
    mbedtls_strerror(err, buf, sizeof (buf));
    tr_err("%s() failed: -0x%04x (%d): %s", name, -err, err, buf);
    delete[] buf;
}


#if MBED_CONF_TLS_SOCKET_DEBUG_LEVEL > 0

void TLSSocket::my_debug(void *ctx, int level, const char *file, int line,
                        const char *str)
{
    const char *p, *basename;
    (void) ctx;

    /* Extract basename from file */
    for(p = basename = file; *p != '\0'; p++) {
        if(*p == '/' || *p == '\\') {
            basename = p + 1;
        }
    }

    tr_debug("%s:%04d: |%d| %s", basename, line, level, str);
}


int TLSSocket::my_verify(void *data, mbedtls_x509_crt *crt, int depth, uint32_t *flags)
{
    const uint32_t buf_size = 1024;
    char *buf = new char[buf_size];
    (void) data;

    tr_debug("\nVerifying certificate at depth %d:\n", depth);
    mbedtls_x509_crt_info(buf, buf_size - 1, "  ", crt);
    tr_debug("%s", buf);

    if (*flags == 0)
        tr_info("No verification issue for this certificate\n");
    else
    {
        mbedtls_x509_crt_verify_info(buf, buf_size, "  ! ", *flags);
        tr_info("%s\n", buf);
    }

    delete[] buf;

    return 0;
}

#endif /* MBED_CONF_TLS_SOCKET_DEBUG_LEVEL > 0 */


int TLSSocket::ssl_recv(void *ctx, unsigned char *buf, size_t len) {
    int recv = -1;
    TCPSocket *socket = static_cast<TCPSocket *>(ctx);
    recv = socket->recv(buf, len);

    if(NSAPI_ERROR_WOULD_BLOCK == recv){
        return MBEDTLS_ERR_SSL_WANT_READ;
    }else if(recv < 0){
        print_mbedtls_error("Socket recv error %d\n", recv);
        return -1;
    }else{
        return recv;
    }
}

int TLSSocket::ssl_send(void *ctx, const unsigned char *buf, size_t len) {
    int size = -1;
    TCPSocket *socket = static_cast<TCPSocket *>(ctx);
    size = socket->send(buf, len);

    if(NSAPI_ERROR_WOULD_BLOCK == size){
        return MBEDTLS_ERR_SSL_WANT_WRITE;
    }else if(size < 0){
        print_mbedtls_error("Socket send error %d\n", size);
        return -1;
    }else{
        return size;
    }
}

void TLSSocket::tls_init() {
    _entropy = new mbedtls_entropy_context;
    _ctr_drbg = new mbedtls_ctr_drbg_context;
    _cacert = new mbedtls_x509_crt;
    _clicert = new mbedtls_x509_crt;
    _pkctx = new mbedtls_pk_context;
    _ssl = new mbedtls_ssl_context;
    _ssl_conf = new mbedtls_ssl_config;

    mbedtls_entropy_init(_entropy);
    mbedtls_ctr_drbg_init(_ctr_drbg);
    mbedtls_x509_crt_init(_cacert);
    mbedtls_x509_crt_init(_clicert);
    mbedtls_ssl_init(_ssl);
    mbedtls_ssl_config_init(_ssl_conf);
    mbedtls_pk_init(_pkctx);
#ifdef MBED_CONF_TLS_SOCKET_ROOT_CA_CERT_PEM
    set_root_ca_pem(MBED_CONF_TLS_SOCKET_ROOT_CA_CERT_PEM);
#endif
}

void TLSSocket::tls_free() {
    mbedtls_entropy_free(_entropy);
    mbedtls_ctr_drbg_free(_ctr_drbg);
    mbedtls_x509_crt_free(_cacert);
    mbedtls_x509_crt_free(_clicert);
    mbedtls_ssl_free(_ssl);
    mbedtls_ssl_config_free(_ssl_conf);
    mbedtls_pk_free(_pkctx);

    delete _entropy;
    delete _ctr_drbg;
    delete _cacert;
    delete _clicert;
    delete _ssl;
    delete _ssl_conf;
    delete _pkctx;
}