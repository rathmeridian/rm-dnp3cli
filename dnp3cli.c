/*
 * dnp3cli - a small interactive DNP3 (over TCP) master/client utility.
 *
 * Presents a menu of common DNP3 application commands and sends the selected
 * one to a target outstation over TCP (default port 20000). Intended for
 * commissioning, protocol testing, and authorized security assessment of
 * DNP3 outstations you own or are permitted to test.
 *
 * Build:   cc -O2 -Wall -Wextra -o dnp3cli dnp3cli.c
 * Usage:   ./dnp3cli [-p port] [-s master_addr] [-d outstation_addr] <target_ip>
 *
 * This implements just enough of the DNP3 Data Link, Transport and Application
 * layers to frame and transmit requests and to hex-dump the raw response.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <errno.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/time.h>

#define DNP3_DEFAULT_PORT 20000
#define DNP3_START0       0x05
#define DNP3_START1       0x64
#define LINK_CTRL_UNCONF  0xC4   /* DIR=1 PRM=1 FC=4 (Unconfirmed User Data) */
#define APP_CTRL_REQUEST  0xC0   /* FIR=1 FIN=1, |= app sequence            */
#define XPORT_SINGLE      0xC0   /* FIR=1 FIN=1, |= transport sequence      */

/* DNP3 application function codes */
#define FC_READ               0x01
#define FC_WRITE              0x02
#define FC_SELECT             0x03
#define FC_OPERATE            0x04
#define FC_DIRECT_OPERATE     0x05
#define FC_COLD_RESTART       0x0D
#define FC_WARM_RESTART       0x0E
#define FC_ENABLE_UNSOL       0x14
#define FC_DISABLE_UNSOL      0x15
#define FC_DELAY_MEASURE      0x17

static uint8_t g_app_seq   = 0;   /* application sequence number (0..15) */
static uint8_t g_xport_seq = 0;   /* transport sequence number   (0..63) */

/* ------------------------------------------------------------------ */
/* DNP3 CRC (polynomial 0x3D65, reflected 0xA6BC, result complemented) */
/* ------------------------------------------------------------------ */
static uint16_t dnp3_crc(const uint8_t *data, size_t len)
{
    uint16_t crc = 0;
    for (size_t i = 0; i < len; i++) {
        crc ^= data[i];
        for (int b = 0; b < 8; b++)
            crc = (crc & 1) ? (crc >> 1) ^ 0xA6BC : (crc >> 1);
    }
    return (uint16_t)(~crc & 0xFFFF);
}

/* Append a block's CRC (LSB first) at *out, advancing it. */
static size_t append_crc(uint8_t *out, const uint8_t *block, size_t block_len)
{
    uint16_t c = dnp3_crc(block, block_len);
    out[0] = (uint8_t)(c & 0xFF);
    out[1] = (uint8_t)((c >> 8) & 0xFF);
    return 2;
}

/* ------------------------------------------------------------------ */
/* Frame assembly                                                      */
/* ------------------------------------------------------------------ */
/*
 * Wrap a transport+application payload in a full DNP3 link-layer frame.
 * user_data = transport header byte + application fragment.
 * Returns the number of bytes written to frame[].
 */
static size_t build_link_frame(uint8_t *frame, size_t frame_cap,
                               uint16_t dest, uint16_t src,
                               const uint8_t *user_data, size_t user_len)
{
    size_t pos = 0;

    /* Link header (10 bytes incl. CRC). Length counts control + addresses
     * + user data, excluding the start bytes, the length field and all CRCs. */
    uint8_t hdr[8];
    hdr[0] = DNP3_START0;
    hdr[1] = DNP3_START1;
    hdr[2] = (uint8_t)(5 + user_len);        /* length */
    hdr[3] = LINK_CTRL_UNCONF;               /* control */
    hdr[4] = (uint8_t)(dest & 0xFF);
    hdr[5] = (uint8_t)((dest >> 8) & 0xFF);
    hdr[6] = (uint8_t)(src & 0xFF);
    hdr[7] = (uint8_t)((src >> 8) & 0xFF);

    if (pos + sizeof(hdr) + 2 > frame_cap) return 0;
    memcpy(frame + pos, hdr, sizeof(hdr));
    pos += sizeof(hdr);
    pos += append_crc(frame + pos, hdr, sizeof(hdr));

    /* User data in blocks of up to 16 bytes, each followed by its CRC. */
    size_t off = 0;
    while (off < user_len) {
        size_t chunk = user_len - off;
        if (chunk > 16) chunk = 16;
        if (pos + chunk + 2 > frame_cap) return 0;
        memcpy(frame + pos, user_data + off, chunk);
        pos += chunk;
        pos += append_crc(frame + pos, user_data + off, chunk);
        off += chunk;
    }
    return pos;
}

static void hexdump(const uint8_t *buf, size_t len)
{
    for (size_t i = 0; i < len; i += 16) {
        printf("    %04zx  ", i);
        for (size_t j = 0; j < 16; j++) {
            if (i + j < len) printf("%02x ", buf[i + j]);
            else             printf("   ");
        }
        printf(" ");
        for (size_t j = 0; j < 16 && i + j < len; j++) {
            uint8_t c = buf[i + j];
            putchar((c >= 32 && c < 127) ? c : '.');
        }
        putchar('\n');
    }
}

/*
 * Build an application request (app control + function code + objects),
 * wrap it with a transport header, frame it, send it, and print any reply.
 */
static int dnp3_request(int sock, uint16_t dest, uint16_t src,
                        uint8_t func, const uint8_t *objs, size_t obj_len)
{
    uint8_t app[256];
    size_t  app_len = 0;

    app[app_len++] = (uint8_t)(APP_CTRL_REQUEST | (g_app_seq & 0x0F));
    app[app_len++] = func;
    if (obj_len) {
        if (app_len + obj_len > sizeof(app)) {
            fprintf(stderr, "application fragment too large\n");
            return -1;
        }
        memcpy(app + app_len, objs, obj_len);
        app_len += obj_len;
    }
    g_app_seq = (uint8_t)((g_app_seq + 1) & 0x0F);

    /* Transport header + application fragment. */
    uint8_t user[300];
    size_t  user_len = 0;
    user[user_len++] = (uint8_t)(XPORT_SINGLE | (g_xport_seq & 0x3F));
    memcpy(user + user_len, app, app_len);
    user_len += app_len;
    g_xport_seq = (uint8_t)((g_xport_seq + 1) & 0x3F);

    uint8_t frame[600];
    size_t  frame_len = build_link_frame(frame, sizeof(frame),
                                         dest, src, user, user_len);
    if (frame_len == 0) {
        fprintf(stderr, "failed to build frame\n");
        return -1;
    }

    printf("  -> sending %zu bytes:\n", frame_len);
    hexdump(frame, frame_len);

    ssize_t n = send(sock, frame, frame_len, 0);
    if (n < 0) {
        perror("send");
        return -1;
    }

    /* Read whatever comes back (socket has a receive timeout set). */
    uint8_t resp[1024];
    n = recv(sock, resp, sizeof(resp), 0);
    if (n > 0) {
        printf("  <- received %zd bytes:\n", n);
        hexdump(resp, (size_t)n);
    } else if (n == 0) {
        printf("  <- outstation closed the connection\n");
        return -1;
    } else {
        if (errno == EAGAIN || errno == EWOULDBLOCK)
            printf("  <- no response (timeout)\n");
        else
            perror("recv");
    }
    return 0;
}

/* ------------------------------------------------------------------ */
/* Object builders                                                     */
/* ------------------------------------------------------------------ */

/* CROB (group 12 var 1) direct-operate for one control point. */
static size_t build_crob(uint8_t *o, uint8_t index, uint8_t control_code,
                         uint32_t on_ms, uint32_t off_ms)
{
    size_t p = 0;
    o[p++] = 0x0C;          /* group 12                          */
    o[p++] = 0x01;          /* variation 1                       */
    o[p++] = 0x17;          /* qualifier: 1-byte count, 1-byte index */
    o[p++] = 0x01;          /* count = 1                         */
    o[p++] = index;         /* point index                       */
    o[p++] = control_code;  /* control code                      */
    o[p++] = 0x01;          /* count field inside CROB           */
    o[p++] = (uint8_t)(on_ms & 0xFF);
    o[p++] = (uint8_t)((on_ms >> 8) & 0xFF);
    o[p++] = (uint8_t)((on_ms >> 16) & 0xFF);
    o[p++] = (uint8_t)((on_ms >> 24) & 0xFF);
    o[p++] = (uint8_t)(off_ms & 0xFF);
    o[p++] = (uint8_t)((off_ms >> 8) & 0xFF);
    o[p++] = (uint8_t)((off_ms >> 16) & 0xFF);
    o[p++] = (uint8_t)((off_ms >> 24) & 0xFF);
    o[p++] = 0x00;          /* status (0 on request)             */
    return p;
}

/* Analog output, 16-bit (group 41 var 2) direct-operate for one point. */
static size_t build_ao16(uint8_t *o, uint8_t index, int16_t value)
{
    size_t p = 0;
    o[p++] = 0x29;          /* group 41          */
    o[p++] = 0x02;          /* variation 2 (16-bit) */
    o[p++] = 0x17;          /* qualifier: 1-byte count, 1-byte index */
    o[p++] = 0x01;          /* count = 1         */
    o[p++] = index;         /* point index       */
    o[p++] = (uint8_t)(value & 0xFF);
    o[p++] = (uint8_t)(((uint16_t)value >> 8) & 0xFF);
    o[p++] = 0x00;          /* status            */
    return p;
}

static long prompt_long(const char *msg, long def)
{
    char line[64];
    printf("%s [%ld]: ", msg, def);
    fflush(stdout);
    if (!fgets(line, sizeof(line), stdin)) return def;
    if (line[0] == '\n' || line[0] == '\0') return def;
    return strtol(line, NULL, 0);
}

/* ------------------------------------------------------------------ */
/* Menu                                                                */
/* ------------------------------------------------------------------ */
static void print_menu(void)
{
    printf(
        "\n==================== DNP3 commands ====================\n"
        "  1) Read Class 0           (integrity poll)\n"
        "  2) Read Class 1/2/3/0     (full integrity poll)\n"
        "  3) Direct Operate CROB    LATCH ON\n"
        "  4) Direct Operate CROB    LATCH OFF\n"
        "  5) Direct Operate CROB    PULSE ON / TRIP\n"
        "  6) Direct Operate CROB    PULSE ON / CLOSE\n"
        "  7) Direct Operate Analog Output (16-bit)\n"
        "  8) Cold Restart\n"
        "  9) Warm Restart\n"
        " 10) Enable Unsolicited     (Class 1/2/3)\n"
        " 11) Disable Unsolicited    (Class 1/2/3)\n"
        " 12) Delay Measurement\n"
        "  0) Quit\n"
        "=======================================================\n"
        "select> ");
    fflush(stdout);
}

static void do_command(int sock, uint16_t dest, uint16_t src, int choice)
{
    uint8_t objs[64];
    size_t  n;

    switch (choice) {
    case 1: {
        uint8_t o[] = { 0x3C, 0x01, 0x06 };          /* class 0, all */
        dnp3_request(sock, dest, src, FC_READ, o, sizeof(o));
        break;
    }
    case 2: {
        uint8_t o[] = { 0x3C, 0x02, 0x06,            /* class 1 */
                        0x3C, 0x03, 0x06,            /* class 2 */
                        0x3C, 0x04, 0x06,            /* class 3 */
                        0x3C, 0x01, 0x06 };          /* class 0 */
        dnp3_request(sock, dest, src, FC_READ, o, sizeof(o));
        break;
    }
    case 3: case 4: case 5: case 6: {
        uint8_t  code;
        const char *name;
        switch (choice) {
            case 3: code = 0x03; name = "LATCH ON";        break;
            case 4: code = 0x04; name = "LATCH OFF";       break;
            case 5: code = 0x81; name = "PULSE ON / TRIP"; break;
            default:code = 0x41; name = "PULSE ON / CLOSE";break;
        }
        long idx = prompt_long("  control point index", 0);
        long on  = (code == 0x03 || code == 0x04)
                   ? 0 : prompt_long("  on-time (ms)", 1000);
        printf("  CROB %s on point %ld\n", name, idx);
        n = build_crob(objs, (uint8_t)idx, code,
                       (uint32_t)on, 0);
        dnp3_request(sock, dest, src, FC_DIRECT_OPERATE, objs, n);
        break;
    }
    case 7: {
        long idx = prompt_long("  analog output index", 0);
        long val = prompt_long("  value (-32768..32767)", 0);
        n = build_ao16(objs, (uint8_t)idx, (int16_t)val);
        dnp3_request(sock, dest, src, FC_DIRECT_OPERATE, objs, n);
        break;
    }
    case 8:
        dnp3_request(sock, dest, src, FC_COLD_RESTART, NULL, 0);
        break;
    case 9:
        dnp3_request(sock, dest, src, FC_WARM_RESTART, NULL, 0);
        break;
    case 10: {
        uint8_t o[] = { 0x3C, 0x02, 0x06, 0x3C, 0x03, 0x06, 0x3C, 0x04, 0x06 };
        dnp3_request(sock, dest, src, FC_ENABLE_UNSOL, o, sizeof(o));
        break;
    }
    case 11: {
        uint8_t o[] = { 0x3C, 0x02, 0x06, 0x3C, 0x03, 0x06, 0x3C, 0x04, 0x06 };
        dnp3_request(sock, dest, src, FC_DISABLE_UNSOL, o, sizeof(o));
        break;
    }
    case 12:
        dnp3_request(sock, dest, src, FC_DELAY_MEASURE, NULL, 0);
        break;
    default:
        printf("  unknown selection\n");
    }
}

static void usage(const char *prog)
{
    fprintf(stderr,
        "Usage: %s [-p port] [-s master_addr] [-d outstation_addr] <target_ip>\n"
        "  -p port              TCP port          (default %d)\n"
        "  -s master_addr       DNP3 source addr  (default 1)\n"
        "  -d outstation_addr   DNP3 dest addr    (default 10)\n",
        prog, DNP3_DEFAULT_PORT);
}

int main(int argc, char **argv)
{
    int      port = DNP3_DEFAULT_PORT;
    uint16_t src  = 1;
    uint16_t dest = 10;
    int      opt;

    while ((opt = getopt(argc, argv, "p:s:d:h")) != -1) {
        switch (opt) {
            case 'p': port = (int)strtol(optarg, NULL, 0);       break;
            case 's': src  = (uint16_t)strtol(optarg, NULL, 0);  break;
            case 'd': dest = (uint16_t)strtol(optarg, NULL, 0);  break;
            case 'h': usage(argv[0]); return 0;
            default:  usage(argv[0]); return 1;
        }
    }
    if (optind >= argc) { usage(argv[0]); return 1; }
    const char *ip = argv[optind];

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port   = htons((uint16_t)port);
    if (inet_pton(AF_INET, ip, &addr.sin_addr) != 1) {
        fprintf(stderr, "invalid IP address: %s\n", ip);
        return 1;
    }

    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) { perror("socket"); return 1; }

    printf("Connecting to %s:%d (master=%u -> outstation=%u) ...\n",
           ip, port, src, dest);
    if (connect(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("connect");
        close(sock);
        return 1;
    }
    printf("Connected.\n");

    /* 3-second receive timeout so the menu stays responsive. */
    struct timeval tv = { .tv_sec = 3, .tv_usec = 0 };
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    char line[32];
    for (;;) {
        print_menu();
        if (!fgets(line, sizeof(line), stdin)) break;
        int choice = (int)strtol(line, NULL, 10);
        if (choice == 0) break;
        do_command(sock, dest, src, choice);
    }

    close(sock);
    printf("Closed.\n");
    return 0;
}
