#include <openssl/ssl.h>
#include <Python.h>

typedef struct
{
    ssize_t ob_refcnt;
    void *ob_type;
    void *SSL_SESSION;
    void *PySSLContext;
} PySSLSession;

int get_ticket_bytes(const void *pysession, const unsigned char **out, size_t offset)
{
    if (strcmp(Py_TYPE(pysession)->tp_name, "_ssl.SSLSession") != 0)
    {
        printf("Expected '_ssl.SSLSession', got '%s'\n", Py_TYPE(pysession)->tp_name);
        return -1;
    }
    // PySSLSession *obj = (PySSLSession *)pysession;

    SSL_SESSION *session = *(SSL_SESSION **)(pysession + offset);
    // printf("Using pointer %p\n", session);
    if (!SSL_SESSION_has_ticket(session))
    {
        printf("No Ticket...\n");
        return -1;
    }
    const unsigned char *ticket;
    size_t len;
    SSL_SESSION_get0_ticket(session, &ticket, &len);
    *out = ticket;
    return len;
}