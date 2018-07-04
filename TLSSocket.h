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

#ifndef _MBED_HTTPS_TLS_TCP_SOCKET_H_
#define _MBED_HTTPS_TLS_TCP_SOCKET_H_

#include "netsocket/TCPSocket.h"
#include "netsocket/TLSSocket.h"

#include "mbedtls/platform.h"
#include "mbedtls/ssl.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/error.h"


/**
 * \brief TLSSocket a wrapper around TCPSocket for interacting with TLS servers
 */
class TLSTCPSocket : public TLSSocketWrapper {
public:
    /** Create an uninitialized socket
     *
     *  Must call open to initialize the socket on a network stack.
     */
    TLSTCPSocket();

    /** Create a socket on a network interface
     *
     *  Creates and opens a socket on the network stack of the given
     *  network interface.
     *
     *  @param stack    Network stack as target for socket
     */
    template <typename S>
    TLSTCPSocket(S *stack, const char *hostname) : TLSSocketWrapper(&tcp_socket, hostname)
    {
        tcp_socket.open(stack);
    }

    /** Opens a socket
     *
     *  Creates a network socket on the network stack of the given
     *  network interface. Not needed if stack is passed to the
     *  socket's constructor.
     *
     *  @param stack    Network stack as target for socket
     *  @return         0 on success, negative error code on failure
     */
    nsapi_error_t open(NetworkStack *stack) {
        return tcp_socket.open(stack);
    }

    template <typename S>
    nsapi_error_t open(S *stack) {
        return open(nsapi_create_stack(stack));
    }

private:
    TCPSocket tcp_socket;
};

#endif // _MBED_HTTPS_TLS_TCP_SOCKET_H_
