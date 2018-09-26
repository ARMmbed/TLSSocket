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

#ifndef _MBED_HTTPS_TLS_SOCKET_WRAPPER_H_
#define _MBED_HTTPS_TLS_SOCKET_WRAPPER_H_

#include "netsocket/Socket.h"

#include "mbedtls/platform.h"
#include "mbedtls/ssl.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/error.h"


/**
 * \brief TLSSocket a wrapper around Socket for interacting with TLS servers
 */
class TLSSocketWrapper : public Socket {
public:
    /* Create a TLSSocketWrapper
     *
     * @param transport    Underlying transport socket to wrap
     * @param hostname     Hostname of the remote host, used for certificate checking
     */
    TLSSocketWrapper(Socket *transport, const char *hostname = NULL);

    /** Destroy a socket wrapper
     *
     *  Closes socket wrapper if the socket wrapper is still open
     */
    virtual ~TLSSocketWrapper();

    /** Specify that transport does not get closed
     *
     *  By default, closing or destroying the socket wrapper will close the
     *  transport socket.
     *  Calling this will make the wrapper leave the transport socket open.
     */
    void keep_transport_open();

    void set_hostname(const char *hostname);

    /** Sets the certification of Root CA.
     *
     * @param root_ca Root CA Certificate in any mbed-TLS supported format.
     * @param len     Length of certificate (including terminating 0 for PEM).
     */
    nsapi_error_t set_root_ca_cert(const void *root_ca, size_t len);

    /** Sets the certification of Root CA.
     *
     * @param root_ca_pem Root CA Certificate in PEM format
     */
    nsapi_error_t set_root_ca_cert(const char *root_ca_pem);

    /** Sets client certificate, and client private key.
     *
     * @param client_cert Client certification in any mbed-TLS supported format.
     * @param client_private_key Client private key in PEM format.
     */
    nsapi_error_t set_client_cert_key(const void *client_cert_pem, size_t client_cert_len,
                                      const void *client_private_key_pem, size_t client_private_key_len);

    /** Sets client certificate, and client private key.
     *
     * @param client_cert_pem Client certification in PEM format.
     * @param client_private_key Client private key in PEM format.
     */
    nsapi_error_t set_client_cert_key(const char *client_cert_pem, const char *client_private_key_pem);

    /** Initiates TLS Handshake
     *
     *  Initiates a TLS hanshake to a remote speer
     *  Underlying transport socket should already be connected
     *
     *  Root CA certification must be set by set_ssl_ca_pem() before
     *  call this function.
     *
     *  @return         0 on success, negative error code on failure
     */
    nsapi_error_t do_handshake();

    /** Send data over a TLS socket
     *
     *  The socket must be connected to a remote host. Returns the number of
     *  bytes sent from the buffer.
     *
     *  @param data     Buffer of data to send to the host
     *  @param size     Size of the buffer in bytes
     *  @return         Number of sent bytes on success, negative error
     *                  code on failure
     */
    virtual nsapi_error_t send(const void *data, nsapi_size_t size);

    /** Receive data over a TLS socket
     *
     *  The socket must be connected to a remote host. Returns the number of
     *  bytes received into the buffer.
     *
     *  @param data     Destination buffer for data received from the host
     *  @param size     Size of the buffer in bytes
     *  @return         Number of received bytes on success, negative error
     *                  code on failure. If no data is available to be received
     *                  and the peer has performed an orderly shutdown,
     *                  recv() returns 0.
     */
    virtual nsapi_size_or_error_t recv(void *data, nsapi_size_t size);

    virtual nsapi_error_t close();
    virtual nsapi_error_t connect(const SocketAddress &address);
    virtual nsapi_size_or_error_t sendto(const SocketAddress &address, const void *data, nsapi_size_t size);
    virtual nsapi_size_or_error_t recvfrom(SocketAddress *address,
        void *data, nsapi_size_t size);
    virtual nsapi_error_t bind(const SocketAddress &address);
    virtual void set_blocking(bool blocking);
    virtual void set_timeout(int timeout);
    virtual void sigio(mbed::Callback<void()> func);
    virtual nsapi_error_t setsockopt(int level, int optname, const void *optval, unsigned optlen);
    virtual nsapi_error_t getsockopt(int level, int optname, void *optval, unsigned *optlen);
    virtual Socket *accept(nsapi_error_t *error = NULL);
    virtual nsapi_error_t listen(int backlog = 1);

    mbedtls_x509_crt *get_own_cert();
    int set_own_cert(mbedtls_x509_crt *);
    mbedtls_x509_crt *get_ca_chain();
    void set_ca_chain(mbedtls_x509_crt *);
    mbedtls_ssl_config *get_ssl_config();
    void set_ssl_config(mbedtls_ssl_config *);

protected:
    /**
     * Helper for pretty-printing mbed TLS error codes
     */
    static void print_mbedtls_error(const char *name, int err);

#if MBED_CONF_TLS_SOCKET_DEBUG_LEVEL > 0
    /**
     * Debug callback for mbed TLS
     * Just prints on the USB serial port
     */
    static void my_debug(void *ctx, int level, const char *file, int line,
                        const char *str);

    /**
     * Certificate verification callback for mbed TLS
     * Here we only use it to display information on each cert in the chain
     */
    static int my_verify(void *data, mbedtls_x509_crt *crt, int depth, uint32_t *flags);

#endif /* MBED_CONF_TLS_SOCKET_DEBUG_LEVEL > 0 */

    /**
     * Receive callback for Mbed TLS
     */
    static int ssl_recv(void *ctx, unsigned char *buf, size_t len);

    /**
     * Send callback for Mbed TLS
     */
    static int ssl_send(void *ctx, const unsigned char *buf, size_t len);

private:
    bool _keep_transport_open;
    bool _handshake_completed;
    Socket *_transport;

    mbedtls_entropy_context* _entropy;
    mbedtls_ctr_drbg_context* _ctr_drbg;
    mbedtls_x509_crt* _cacert;
    bool _cacert_allocated;
    mbedtls_x509_crt* _clicert;
    bool _clicert_allocated;
    mbedtls_pk_context* _pkctx;
    mbedtls_ssl_context* _ssl;
    mbedtls_ssl_config* _ssl_conf;
    bool _ssl_conf_allocated;

    /* Allocates required memory */
    void tls_init(void);
    /* Frees memory */
    void tls_free(void);
    /* Returns true if TLS context is allocated, false if freed */
    bool is_tls_allocated();
};

#endif // _MBED_HTTPS_TLS_SOCKET_WRAPPER_H_
