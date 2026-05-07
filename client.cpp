// Copyright (c)
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <arpa/inet.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <unistd.h>

#include <algorithm>
#include <array>
#include <cerrno>
#include <chrono>
#include <csignal>
#include <cstdint>
#include <cstring>
#include <ctime>
#include <iomanip>
#include <iostream>
#include <optional>
#include <random>
#include <sstream>
#include <stdexcept>
#include <string>
#include <string_view>

namespace {
using Clock = std::chrono::steady_clock;
constexpr std::string_view DEFAULT_BIND{"0.0.0.0:50000"};
constexpr std::string_view DEFAULT_STUN{"stun.fish.foo:3478"};
constexpr uint32_t STUN_COOKIE{0x2112A442};
volatile std::sig_atomic_t g_stop{0};

void Stop(int) { g_stop = 1; }
std::string Err(int e = errno) { return std::strerror(e); }

void Log(std::string_view tag, std::string_view msg)
{
    std::time_t t = std::time(nullptr);
    std::tm tm{};
    localtime_r(&t, &tm);
    char ts[16]{};
    std::strftime(ts, sizeof(ts), "%H:%M:%S", &tm);
    std::cout << ts << " [" << tag << "] " << msg << std::endl;
}

struct Fd {
    int v{-1};
    Fd() = default;
    explicit Fd(int fd) : v(fd) {}
    Fd(const Fd&) = delete;
    Fd& operator=(const Fd&) = delete;
    Fd(Fd&& o) noexcept : v(o.Release()) {}
    Fd& operator=(Fd&& o) noexcept
    {
        if (this != &o) Reset(o.Release());
        return *this;
    }
    ~Fd() { Reset(); }
    explicit operator bool() const { return v >= 0; }
    int Release()
    {
        int r = v;
        v = -1;
        return r;
    }
    void Reset(int fd = -1)
    {
        if (v >= 0) close(v);
        v = fd;
    }
};

struct Endpoint {
    sockaddr_in sa{};
    std::string ToString() const
    {
        char ip[INET_ADDRSTRLEN]{};
        inet_ntop(AF_INET, &sa.sin_addr, ip, sizeof(ip));
        return std::string(ip) + ":" + std::to_string(ntohs(sa.sin_port));
    }
};

uint16_t Port(std::string_view s)
{
    int port = std::stoi(std::string(s));
    if (port < 0 || port > 65535) throw std::runtime_error("port out of range");
    return static_cast<uint16_t>(port);
}

Endpoint Resolve(std::string_view text, int type)
{
    auto colon = text.rfind(':');
    if (colon == std::string_view::npos) throw std::runtime_error("endpoint missing port: " + std::string(text));
    std::string host{text.substr(0, colon)};
    std::string port{std::to_string(Port(text.substr(colon + 1)))};

    addrinfo hints{};
    hints.ai_family = AF_INET;
    hints.ai_socktype = type;
    addrinfo* res{nullptr};
    int rc = getaddrinfo(host.c_str(), port.c_str(), &hints, &res);
    if (rc != 0) throw std::runtime_error("resolve failed: " + std::string(gai_strerror(rc)));
    Endpoint ep;
    std::memcpy(&ep.sa, res->ai_addr, sizeof(sockaddr_in));
    freeaddrinfo(res);
    return ep;
}

Endpoint Local(int fd)
{
    Endpoint ep;
    socklen_t len = sizeof(ep.sa);
    if (getsockname(fd, reinterpret_cast<sockaddr*>(&ep.sa), &len) != 0) throw std::runtime_error("getsockname: " + Err());
    return ep;
}

void Reuse(int fd)
{
    int one = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
#ifdef SO_REUSEPORT
    setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &one, sizeof(one));
#endif
}

void Nonblock(int fd)
{
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0 || fcntl(fd, F_SETFL, flags | O_NONBLOCK) != 0) throw std::runtime_error("nonblock: " + Err());
}

Fd BindSocket(const Endpoint& ep, int type)
{
    Fd fd{socket(AF_INET, type, type == SOCK_STREAM ? IPPROTO_TCP : IPPROTO_UDP)};
    if (!fd) throw std::runtime_error("socket: " + Err());
    Reuse(fd.v);
    if (bind(fd.v, reinterpret_cast<const sockaddr*>(&ep.sa), sizeof(ep.sa)) != 0) throw std::runtime_error("bind: " + Err());
    Nonblock(fd.v);
    return fd;
}

Fd Listener(const Endpoint& bind_ep)
{
    Fd fd = BindSocket(bind_ep, SOCK_STREAM);
    if (listen(fd.v, 1) != 0) throw std::runtime_error("listen: " + Err());
    return fd;
}

Fd Connector(const Endpoint& bind_ep, const Endpoint& peer)
{
    Fd fd = BindSocket(bind_ep, SOCK_STREAM);
    if (connect(fd.v, reinterpret_cast<const sockaddr*>(&peer.sa), sizeof(peer.sa)) != 0) {
        if (errno != EINPROGRESS && errno != EWOULDBLOCK && errno != EALREADY && errno != EINTR) throw std::runtime_error(Err());
    }
    return fd;
}

bool Wait(int fd, bool write, double seconds)
{
    timeval tv{};
    tv.tv_sec = static_cast<decltype(tv.tv_sec)>(seconds);
    tv.tv_usec = static_cast<decltype(tv.tv_usec)>((seconds - static_cast<double>(tv.tv_sec)) * 1000000.0);
    fd_set fds;
    FD_ZERO(&fds);
    FD_SET(fd, &fds);
    int rc = select(fd + 1, write ? nullptr : &fds, write ? &fds : nullptr, nullptr, &tv);
    if (rc < 0 && errno != EINTR) throw std::runtime_error("select: " + Err());
    return rc > 0;
}

void SendLine(int fd, const std::string& line)
{
    std::string out = line + "\n";
    for (size_t n = 0; n < out.size();) {
#ifdef MSG_NOSIGNAL
        ssize_t rc = send(fd, out.data() + n, out.size() - n, MSG_NOSIGNAL);
#else
        ssize_t rc = send(fd, out.data() + n, out.size() - n, 0);
#endif
        if (rc > 0) {
            n += static_cast<size_t>(rc);
        } else if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR) {
            if (!Wait(fd, true, 5.0)) throw std::runtime_error("send timeout");
        } else {
            throw std::runtime_error("send: " + Err());
        }
    }
}

std::string RecvLine(int fd)
{
    std::string line;
    std::array<char, 128> buf{};
    while (line.find('\n') == std::string::npos) {
        if (!Wait(fd, false, 5.0)) throw std::runtime_error("recv timeout");
        ssize_t rc = recv(fd, buf.data(), buf.size(), 0);
        if (rc > 0) line.append(buf.data(), static_cast<size_t>(rc));
        else if (rc == 0) throw std::runtime_error("peer disconnected");
        else if (errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR) throw std::runtime_error("recv: " + Err());
    }
    line.resize(line.find('\n'));
    return line;
}

uint16_t U16(const uint8_t* p) { return static_cast<uint16_t>((p[0] << 8) | p[1]); }
uint32_t U32(const uint8_t* p) { return (uint32_t{p[0]} << 24) | (uint32_t{p[1]} << 16) | (uint32_t{p[2]} << 8) | p[3]; }
void Put16(uint8_t* p, uint16_t v) { p[0] = v >> 8; p[1] = v; }
void Put32(uint8_t* p, uint32_t v) { p[0] = v >> 24; p[1] = v >> 16; p[2] = v >> 8; p[3] = v; }

std::optional<Endpoint> StunAddr(const uint8_t* v, size_t n, bool xored)
{
    if (n < 8 || v[1] != 1) return std::nullopt;
    uint16_t port = U16(v + 2);
    uint32_t ip = U32(v + 4);
    if (xored) {
        port ^= STUN_COOKIE >> 16;
        ip ^= STUN_COOKIE;
    }
    Endpoint ep;
    ep.sa.sin_family = AF_INET;
    ep.sa.sin_port = htons(port);
    uint32_t net_ip = htonl(ip);
    std::memcpy(&ep.sa.sin_addr, &net_ip, sizeof(net_ip));
    return ep;
}

std::optional<Endpoint> StunParse(const uint8_t* p, size_t n, const std::array<uint8_t, 12>& txid)
{
    if (n < 20 || U16(p) != 0x0101 || U32(p + 4) != STUN_COOKIE || std::memcmp(p + 8, txid.data(), txid.size()) != 0) return std::nullopt;
    size_t end = 20 + U16(p + 2);
    for (size_t off = 20; off + 4 <= end && off + 4 <= n;) {
        uint16_t type = U16(p + off), len = U16(p + off + 2);
        off += 4;
        if (off + len > n) return std::nullopt;
        if (type == 0x0020 || type == 0x0001) return StunAddr(p + off, len, type == 0x0020);
        off += (size_t{len} + 3) & ~size_t{3};
    }
    return std::nullopt;
}

std::string Nonce()
{
    std::array<uint8_t, 16> bytes{};
    std::random_device rng;
    for (auto& b : bytes) b = static_cast<uint8_t>(rng());
    std::ostringstream s;
    s << std::hex << std::setfill('0');
    for (auto b : bytes) s << std::setw(2) << int(b);
    return s.str();
}

int RunStun(std::string bind, std::string server)
{
    Fd udp = BindSocket(Resolve(bind, SOCK_DGRAM), SOCK_DGRAM);
    Endpoint stun = Resolve(server, SOCK_DGRAM);
    std::array<uint8_t, 20> req{};
    std::array<uint8_t, 12> txid{};
    std::random_device rng;
    Put16(req.data(), 0x0001);
    Put32(req.data() + 4, STUN_COOKIE);
    for (auto& b : txid) b = static_cast<uint8_t>(rng());
    std::memcpy(req.data() + 8, txid.data(), txid.size());
    if (sendto(udp.v, req.data(), req.size(), 0, reinterpret_cast<sockaddr*>(&stun.sa), sizeof(stun.sa)) != static_cast<ssize_t>(req.size())) {
        throw std::runtime_error("STUN send: " + Err());
    }
    Log("UDP STUN", "bound " + Local(udp.v).ToString());
    if (!Wait(udp.v, false, 2.0)) throw std::runtime_error("STUN timeout");
    std::array<uint8_t, 2048> buf{};
    ssize_t n = recv(udp.v, buf.data(), buf.size(), 0);
    auto mapped = n > 0 ? StunParse(buf.data(), static_cast<size_t>(n), txid) : std::nullopt;
    if (!mapped) throw std::runtime_error("bad STUN response");
    Log("UDP STUN", server + " mapped us as " + mapped->ToString());
    return 0;
}

int Proof(Fd tcp, Fd& listener, Fd& connector, const std::string& nonce)
{
    connector.Reset();
    listener.Reset();
    SendLine(tcp.v, nonce);
    Log("proof", "sent " + nonce);
    Log("proof", "received " + RecvLine(tcp.v));
    return 0;
}

std::chrono::milliseconds RetryDelay(std::mt19937& rng)
{
    std::uniform_int_distribution<int> dist{500, 1500};
    return std::chrono::milliseconds{dist(rng)};
}

int RunPeer(std::string name, std::string peer_text, std::string bind)
{
    Endpoint bind_ep = Resolve(bind, SOCK_STREAM), peer = Resolve(peer_text, SOCK_STREAM);
    Fd listener = Listener(bind_ep), connector;
    std::string nonce = name + " " + Nonce();
    std::random_device seed;
    std::mt19937 rng{seed()};
    Clock::time_point next{};
    bool logged_connect = false;
    bool logged_failure = false;
    Log("bind", "TCP " + Local(listener.v).ToString() + " as " + name);
    Log("peer", peer.ToString());

    while (!g_stop) {
        if (!connector && Clock::now() >= next) {
            try {
                connector = Connector(bind_ep, peer);
                if (!logged_connect) {
                    Log("punch", "connect " + Local(connector.v).ToString() + " -> " + peer.ToString());
                    logged_connect = true;
                }
            } catch (const std::exception& e) {
                if (!logged_failure) {
                    Log("punch", std::string("connect setup failed: ") + e.what());
                    Log("listen", "listening; retrying TCP punch every 500-1500ms");
                    logged_failure = true;
                }
                next = Clock::now() + RetryDelay(rng);
            }
        }
        fd_set r, w;
        FD_ZERO(&r);
        FD_ZERO(&w);
        FD_SET(listener.v, &r);
        int maxfd = listener.v;
        if (connector) {
            FD_SET(connector.v, &w);
            maxfd = std::max(maxfd, connector.v);
        }
        timeval tv{0, 50'000};
        if (select(maxfd + 1, &r, &w, nullptr, &tv) < 0 && errno != EINTR) throw std::runtime_error("select: " + Err());

        if (connector && FD_ISSET(connector.v, &w)) {
            int err = 0;
            socklen_t len = sizeof(err);
            getsockopt(connector.v, SOL_SOCKET, SO_ERROR, &err, &len);
            if (err == 0) {
                return Proof(Fd{connector.Release()}, listener, connector, nonce);
            }
            if (!logged_failure) {
                Log("punch", "connect failed: " + Err(err));
                Log("listen", "listening; retrying TCP punch every 500-1500ms");
                logged_failure = true;
            }
            connector.Reset();
            next = Clock::now() + RetryDelay(rng);
        }
        if (FD_ISSET(listener.v, &r)) {
            sockaddr_in sa{};
            socklen_t len = sizeof(sa);
            int fd = accept(listener.v, reinterpret_cast<sockaddr*>(&sa), &len);
            if (fd < 0 && (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR)) continue;
            if (fd < 0) throw std::runtime_error("accept: " + Err());
            Nonblock(fd);
            return Proof(Fd{fd}, listener, connector, nonce);
        }
    }
    Log("done", "interrupted");
    return 130;
}

std::string Arg(int& i, int argc, char** argv)
{
    if (++i >= argc) throw std::runtime_error("missing option value");
    return argv[i];
}

int Main(int argc, char** argv)
{
    if (argc < 2 || std::string_view(argv[1]) == "--help") {
        std::cout << "usage: client stun [--bind IP:PORT] [--stun HOST:PORT]\n"
                     "       client peer --name NAME --peer IP:PORT [--bind IP:PORT]\n";
        return argc < 2 ? 2 : 0;
    }
    std::string cmd = argv[1], bind{DEFAULT_BIND}, stun{DEFAULT_STUN}, name, peer;
    for (int i = 2; i < argc; ++i) {
        std::string_view a{argv[i]};
        if (a == "--bind") bind = Arg(i, argc, argv);
        else if (a == "--stun") stun = Arg(i, argc, argv);
        else if (a == "--name") name = Arg(i, argc, argv);
        else if (a == "--peer") peer = Arg(i, argc, argv);
        else throw std::runtime_error("unknown option: " + std::string(a));
    }
    if (cmd == "stun") return RunStun(bind, stun);
    if (cmd == "peer") {
        if (name.empty() || peer.empty()) throw std::runtime_error("peer requires --name and --peer");
        return RunPeer(name, peer, bind);
    }
    throw std::runtime_error("unknown command: " + cmd);
}
} // namespace

int main(int argc, char** argv)
{
    std::signal(SIGINT, Stop);
#ifdef SIGPIPE
    std::signal(SIGPIPE, SIG_IGN);
#endif
    try {
        return Main(argc, argv);
    } catch (const std::exception& e) {
        std::cerr << "error: " << e.what() << std::endl;
        return 1;
    }
}
