// firewall_daemon.cpp
//
// Standalone C++ zone-firewall daemon for the mininet-zone-segmentation
// project. Listens on a Unix domain socket; for each connection, reads
// fixed-size packet-header requests and replies with allow/deny verdicts,
// using the same zone/subnet/rule tables as firewall_rules.py.
//
// This mirrors -- deliberately does NOT share code with -- the Python
// implementation in firewall_rules.py. Sharing a process boundary here is
// the whole point of the exercise (a real standalone component, talking
// over a real IPC protocol), so the rule tables are hand-duplicated
// rather than loaded from a common source. See README.md for the
// tradeoff writeup.
//
// Design note on trust boundaries: the original POX controller
// (controller.py) classifies a packet's *source* zone by which switch
// port it arrived on, not by its claimed source IP -- that's a
// deliberate anti-spoofing property (a host can lie about its source IP
// in a packet, but it can't lie about which physical port it's plugged
// into). This daemon instead classifies both source and destination zone
// from the IP addresses in the request, because IP/port/protocol is all
// the wire protocol carries. In this topology every host's IP already
// falls inside its own zone's subnet, so behavior is identical -- but a
// production version of this daemon would take the ingress-port-derived
// zone as an input from the controller instead of re-deriving it from a
// spoofable source IP.

#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#include <csignal>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>
#include <thread>
#include <utility>

namespace {

// ---------------------------------------------------------------------
// Wire protocol: fixed-size, network-byte-order structs. #pragma pack(1)
// removes compiler-inserted alignment padding so sizeof() here matches
// exactly what the Python side computes with struct.calcsize("!IIHHB")
// and struct.calcsize("!BB") -- 13 bytes in, 2 bytes out, no surprises.
// ---------------------------------------------------------------------

#pragma pack(push, 1)
struct FilterRequest {
    uint32_t src_ip;    // IPv4, network byte order
    uint32_t dst_ip;    // IPv4, network byte order
    uint16_t src_port;  // network byte order; unused by current rules,
    uint16_t dst_port;  // carried for future port-based rules
    uint8_t protocol;   // IPPROTO_ICMP=1, IPPROTO_TCP=6, IPPROTO_UDP=17
};

struct FilterResponse {
    uint8_t verdict;  // 0 = DENY, 1 = ALLOW
    uint8_t rule_id;  // which rule produced the verdict, for logging
};
#pragma pack(pop)

static_assert(sizeof(FilterRequest) == 13, "wire format drifted");
static_assert(sizeof(FilterResponse) == 2, "wire format drifted");

constexpr uint8_t kRuleNone = 0;        // default allow, no rule matched
constexpr uint8_t kRuleBlockAllIp = 1;  // matched BLOCK_ALL_IP
constexpr uint8_t kRuleBlockIcmp = 2;   // matched BLOCK_ICMP

constexpr uint8_t kIpprotoIcmp = 1;

const char* kSocketPath = "/tmp/zone_firewall.sock";

// ---------------------------------------------------------------------
// Zone/subnet tables -- mirrors ZONES in firewall_rules.py.
// ---------------------------------------------------------------------

enum class Zone : uint8_t { DeptA, DeptB, DataCenter, Trust, Untrust, Unknown };

// Builds a host-byte-order IPv4 address from its four dotted-quad
// octets, at compile time, so the table below reads the same as the
// Python subnet literals it mirrors.
constexpr uint32_t IpV4(uint8_t a, uint8_t b, uint8_t c, uint8_t d) {
    return (static_cast<uint32_t>(a) << 24) | (static_cast<uint32_t>(b) << 16) |
           (static_cast<uint32_t>(c) << 8) | static_cast<uint32_t>(d);
}

struct SubnetZone {
    Zone zone;
    uint32_t network;      // host byte order
    uint32_t prefix_len;
    const char* name;      // for logging only
};

const SubnetZone kZones[] = {
    {Zone::DeptA, IpV4(10, 1, 1, 0), 24, "DeptA"},
    {Zone::DeptB, IpV4(10, 1, 2, 0), 24, "DeptB"},
    {Zone::DataCenter, IpV4(10, 1, 3, 0), 24, "DataCenter"},
    {Zone::Trust, IpV4(192, 47, 38, 0), 24, "Trust"},
    {Zone::Untrust, IpV4(108, 35, 24, 0), 24, "Untrust"},
};

// Rule tables -- mirrors BLOCK_ALL_IP / BLOCK_ICMP in firewall_rules.py.
// Linear scan over a handful of pairs is plenty fast for this rule
// count; a hash set or trie would only start to matter with hundreds of
// rules, which this project doesn't have.
const std::pair<Zone, Zone> kBlockAllIp[] = {
    {Zone::Untrust, Zone::DataCenter},
    {Zone::Trust, Zone::DataCenter},
};

const std::pair<Zone, Zone> kBlockIcmp[] = {
    {Zone::Untrust, Zone::DeptA},
    {Zone::Untrust, Zone::DeptB},
    {Zone::Untrust, Zone::DataCenter},
    {Zone::Trust, Zone::DeptB},
    {Zone::DeptA, Zone::DeptB},
    {Zone::DeptB, Zone::DeptA},
};

template <size_t N>
bool ContainsPair(const std::pair<Zone, Zone> (&table)[N], Zone src, Zone dst) {
    for (const auto& entry : table) {
        if (entry.first == src && entry.second == dst) return true;
    }
    return false;
}

// Classifies a host-byte-order IPv4 address into a zone by subnet
// containment, the same way firewall_rules.zone_for_ip does.
Zone ClassifyZone(uint32_t ip_host_order) {
    for (const auto& z : kZones) {
        uint32_t mask = z.prefix_len == 0 ? 0 : (~uint32_t(0) << (32 - z.prefix_len));
        if ((ip_host_order & mask) == (z.network & mask)) return z.zone;
    }
    return Zone::Unknown;
}

// Direct port of firewall_allowed() in firewall_rules.py: check the
// "block everything" table first, then (only for ICMP) the narrower
// "block ICMP" table. Anything left over is allowed.
FilterResponse Decide(Zone src_zone, Zone dst_zone, bool is_icmp) {
    if (ContainsPair(kBlockAllIp, src_zone, dst_zone)) {
        return {0, kRuleBlockAllIp};
    }
    if (is_icmp && ContainsPair(kBlockIcmp, src_zone, dst_zone)) {
        return {0, kRuleBlockIcmp};
    }
    return {1, kRuleNone};
}

// ---------------------------------------------------------------------
// Socket plumbing
// ---------------------------------------------------------------------

// read() can return fewer bytes than requested even on a blocking
// stream socket (short reads are legal for TCP-like sockets); loop
// until we have exactly `len` bytes or the peer closes the connection.
bool ReadFull(int fd, void* buf, size_t len) {
    uint8_t* p = static_cast<uint8_t*>(buf);
    size_t remaining = len;
    while (remaining > 0) {
        ssize_t n = read(fd, p, remaining);
        if (n <= 0) return false;  // 0 = peer closed, <0 = error
        p += n;
        remaining -= static_cast<size_t>(n);
    }
    return true;
}

bool WriteFull(int fd, const void* buf, size_t len) {
    const uint8_t* p = static_cast<const uint8_t*>(buf);
    size_t remaining = len;
    while (remaining > 0) {
        ssize_t n = write(fd, p, remaining);
        if (n <= 0) return false;
        p += n;
        remaining -= static_cast<size_t>(n);
    }
    return true;
}

// Runs on its own thread for the lifetime of one client connection.
// The rule/zone tables above are compile-time constants, so concurrent
// connections need no locking -- there's no shared mutable state on the
// decision path.
void HandleClient(int client_fd) {
    for (;;) {
        FilterRequest req;
        if (!ReadFull(client_fd, &req, sizeof(req))) break;

        uint32_t src_ip = ntohl(req.src_ip);
        uint32_t dst_ip = ntohl(req.dst_ip);
        uint8_t protocol = req.protocol;

        Zone src_zone = ClassifyZone(src_ip);
        Zone dst_zone = ClassifyZone(dst_ip);
        bool is_icmp = protocol == kIpprotoIcmp;

        FilterResponse resp = Decide(src_zone, dst_zone, is_icmp);

        if (!WriteFull(client_fd, &resp, sizeof(resp))) break;
    }
    close(client_fd);
}

volatile std::sig_atomic_t g_shutdown_requested = 0;

void HandleSignal(int) { g_shutdown_requested = 1; }

}  // namespace

int main() {
    std::signal(SIGINT, HandleSignal);
    std::signal(SIGTERM, HandleSignal);

    // A stale socket file from a previous (crashed) run would otherwise
    // make bind() fail with EADDRINUSE.
    unlink(kSocketPath);

    int listen_fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (listen_fd < 0) {
        perror("socket");
        return 1;
    }

    sockaddr_un addr{};
    addr.sun_family = AF_UNIX;
    std::strncpy(addr.sun_path, kSocketPath, sizeof(addr.sun_path) - 1);

    if (bind(listen_fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) < 0) {
        perror("bind");
        close(listen_fd);
        return 1;
    }

    if (listen(listen_fd, /*backlog=*/16) < 0) {
        perror("listen");
        close(listen_fd);
        return 1;
    }

    std::fprintf(stderr, "zone firewall daemon listening on %s\n", kSocketPath);

    while (!g_shutdown_requested) {
        int client_fd = accept(listen_fd, nullptr, nullptr);
        if (client_fd < 0) {
            if (g_shutdown_requested) break;
            continue;  // accept() can be interrupted by a signal; just retry
        }
        // Detached: each connection is handled independently and cleans
        // itself up on disconnect. Fine for this project's load (one
        // controller, one benchmark script); a production version would
        // use a thread pool to bound resource use under connection floods.
        std::thread(HandleClient, client_fd).detach();
    }

    close(listen_fd);
    unlink(kSocketPath);
    std::fprintf(stderr, "zone firewall daemon shut down\n");
    return 0;
}
