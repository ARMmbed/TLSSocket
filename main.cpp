

#include "mbed.h"
#include "mbed_trace.h"
#include "NetworkInterface.h"
#include "TLSSocket.h"

const char* HOST_NAME = "os.mbed.com";
const int PORT = 443;
const char* HTTPS_PATH = "/";

const char* cert = \
    "-----BEGIN CERTIFICATE-----\n" \
    "MIIDdTCCAl2gAwIBAgILBAAAAAABFUtaw5QwDQYJKoZIhvcNAQEFBQAwVzELMAkG\n" \
    "A1UEBhMCQkUxGTAXBgNVBAoTEEdsb2JhbFNpZ24gbnYtc2ExEDAOBgNVBAsTB1Jv\n" \
    "b3QgQ0ExGzAZBgNVBAMTEkdsb2JhbFNpZ24gUm9vdCBDQTAeFw05ODA5MDExMjAw\n" \
    "MDBaFw0yODAxMjgxMjAwMDBaMFcxCzAJBgNVBAYTAkJFMRkwFwYDVQQKExBHbG9i\n" \
    "YWxTaWduIG52LXNhMRAwDgYDVQQLEwdSb290IENBMRswGQYDVQQDExJHbG9iYWxT\n" \
    "aWduIFJvb3QgQ0EwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDaDuaZ\n" \
    "jc6j40+Kfvvxi4Mla+pIH/EqsLmVEQS98GPR4mdmzxzdzxtIK+6NiY6arymAZavp\n" \
    "xy0Sy6scTHAHoT0KMM0VjU/43dSMUBUc71DuxC73/OlS8pF94G3VNTCOXkNz8kHp\n" \
    "1Wrjsok6Vjk4bwY8iGlbKk3Fp1S4bInMm/k8yuX9ifUSPJJ4ltbcdG6TRGHRjcdG\n" \
    "snUOhugZitVtbNV4FpWi6cgKOOvyJBNPc1STE4U6G7weNLWLBYy5d4ux2x8gkasJ\n" \
    "U26Qzns3dLlwR5EiUWMWea6xrkEmCMgZK9FGqkjWZCrXgzT/LCrBbBlDSgeF59N8\n" \
    "9iFo7+ryUp9/k5DPAgMBAAGjQjBAMA4GA1UdDwEB/wQEAwIBBjAPBgNVHRMBAf8E\n" \
    "BTADAQH/MB0GA1UdDgQWBBRge2YaRQ2XyolQL30EzTSo//z9SzANBgkqhkiG9w0B\n" \
    "AQUFAAOCAQEA1nPnfE920I2/7LqivjTFKDK1fPxsnCwrvQmeU79rXqoRSLblCKOz\n" \
    "yj1hTdNGCbM+w6DjY1Ub8rrvrTnhQ7k4o+YviiY776BQVvnGCv04zcQLcFGUl5gE\n" \
    "38NflNUVyRRBnMRddWQVDf9VMOyGj/8N7yy5Y0b2qvzfvGn9LhJIZJrglfCm7ymP\n" \
    "AbEVtQwdpf5pLGkkeB6zpxxxYu7KyJesF12KwvhHhm4qxFYxldBniYUr+WymXUad\n" \
    "DKqC5JlR3XC321Y9YeRq4VzW9v493kHMB65jUr9TU/Qr6cf9tveCX4XSQRjbgbME\n" \
    "HMUfpIBvFSDJ3gyICh3WZlXi/EjJKSZp4A==\n" \
    "-----END CERTIFICATE-----";


/** Demonstrate download from a HTTP server through abstract socket interface
 *  Socket can be any connected socket, TCP or TLS
 */
int http_get(Socket *socket)
{
    const size_t buf_size = 1024;
    char *buf = new char[buf_size];

    // Send HTTP request
    /* "Connection: close" header is specified to detect end of the body
     * contents by connection close notification. If this is not specified,
     * connection is kept, and need to detect end of the content in another
     * way.
     */
    int len = snprintf(buf, buf_size,
                "GET %s HTTP/1.1\n"
                "Host: %s\n"
                "Connection: close\n"
                "\n", HTTPS_PATH, HOST_NAME);
    printf("\n%s", buf);
    int rc = 0;
    rc = socket->send(buf, len);
    if(rc < 0) {
        printf("send error.\n");
        return rc;
    }

    // Receive response from the server
    while((rc = socket->recv(buf, buf_size - 1)) > 0) {
        buf[rc] = '\0';
        printf("%s", buf);
    }
    if(rc < 0) {
        printf("\n! Read failed. err code = %d\n", rc);
        return rc;
    }

    delete[] buf;
    return 0;
}

int main(int argc, char* argv[]) {
    mbed_trace_init();

    printf("HelloTSLSocket, HTTPS example of TLSSocket\n");
    printf("\n");

    // Open a network interface
    NetworkInterface* network = NetworkInterface::get_default_instance();

    if (network->connect()) {
        printf("Unable to connect to network\n");
        return -1;
    }

    printf("Connected to network!\n");

#if 0
    // Create transport socket
    TCPSocket tcp;
    nsapi_error_t err = tcp.open(network);
    MBED_ASSERT(err == NSAPI_ERROR_OK);

    // Resolve target name
    SocketAddress addr;
    err = network->gethostbyname(HOST_NAME, &addr);
    MBED_ASSERT(err == NSAPI_ERROR_OK);
    addr.set_port(PORT);

    // Connect the trasport
    printf("Connecting to %s\n", HOST_NAME);

    err = tcp.connect(addr);
    MBED_ASSERT(err == NSAPI_ERROR_OK);

    // Create a TLS socket
    TLSSocketWrapper tls(&tcp, HOST_NAME);
#else
    TLSSocket tls(network);
    // Connect the trasport
    printf("Connecting to %s\n", HOST_NAME);

    nsapi_error_t err = tls.connect(HOST_NAME, PORT);
    MBED_ASSERT(err == NSAPI_ERROR_OK);
#endif

    // Set root CA certificate
    tls.set_root_ca_cert(cert);

    // Start TLS handshake
    printf("Start TLS handshake\n");
    if(tls.do_handshake() != 0) {
        printf("Failed to connect to the server.");
        return -1;
    }

    err = http_get(&tls);
    if (err == 0) {
        printf("HTTP Download succesfull\n");
    }

    printf("Closing TLS\n");
    tls.close();


    // Done
    printf("HelloTSLSocket DONE.\n");

}
