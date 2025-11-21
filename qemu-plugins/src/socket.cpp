#include "socket.hpp"

#include "debug.hpp"
#include "main.hpp"

#include <MinimalSocket/Error.h>

#include <algorithm>
#include <utility>

namespace {
constexpr std::size_t kSocketChunk = 512;
constexpr std::size_t kMaxBuffered = 4096;

std::string trim_line(std::string line) {
    auto drop_leading = line.find_first_not_of(" \t\r");
    if (drop_leading == std::string::npos) {
        return {};
    }
    line.erase(0, drop_leading);
    while (!line.empty() && (line.back() == '\r' || line.back() == '\n' || line.back() == ' ' || line.back() == '\t')) {
        line.pop_back();
    }
    return line;
}
} // namespace

ScallopSocket::ScallopSocket(ScallopState &state, MinimalSocket::AddressFamily family)
    : state_(state), family_(family) {}

ScallopSocket::~ScallopSocket() { stop(); }

bool ScallopSocket::start(MinimalSocket::Port port) {
    if (running_) {
        return true;
    }

    // Make a new server
    server_ = std::make_unique<MinimalSocket::tcp::TcpServer<true>>(port, family_);
    try {
        // Server failed
        if (!server_->open()) {
            debug("[socket] failed to open control socket on port %u\n", static_cast<unsigned>(port));
            server_.reset();
            return false;
        }
    } catch (const std::exception &ex) {
        debug("[socket] open error: %s\n", ex.what());
        server_.reset();
        return false;
    }

    debug("open port %d", port);
    bound_port_ = port;
    running_ = true;
    accept_thread_ = std::thread(&ScallopSocket::acceptLoop, this);
    return true;
}

void ScallopSocket::stop() {
    if (!running_.exchange(false)) {
        return;
    }

    if (server_) {
        server_->shutDown();
    }

    {
        std::lock_guard<std::mutex> guard(active_client_mu_);
        if (active_client_) {
            active_client_->shutDown();
        }
    }

    if (accept_thread_.joinable()) {
        accept_thread_.join();
    }

    server_.reset();
    bound_port_ = 0;
}

void ScallopSocket::acceptLoop() {
    while (running_) {
        try {
            auto client = server_->acceptNewClient();
            if (!running_) {
                client.shutDown();
                break;
            }
            handleClient(std::move(client));
        } catch (const MinimalSocket::Error &err) {
            if (!running_) {
                break;
            }
            debug("[socket] accept error: %s\n", err.what());
        } catch (const std::exception &ex) {
            if (!running_) {
                break;
            }
            debug("[socket] unexpected accept exception: %s\n", ex.what());
        }
    }
}

void ScallopSocket::handleClient(MinimalSocket::tcp::TcpConnectionBlocking connection) {
    {
        std::lock_guard<std::mutex> guard(active_client_mu_);
        active_client_ = &connection;
    }

    const auto remote = MinimalSocket::to_string(connection.getRemoteAddress());
    debug("[socket] client connected from %s\n", remote.c_str());

    std::string buffer;
    buffer.reserve(kSocketChunk);

    try {
        while (running_) {
            std::string chunk = connection.receive(kSocketChunk, MinimalSocket::NULL_TIMEOUT);
            if (chunk.empty()) {
                break; // remote closed
            }

            buffer.append(chunk);

            std::size_t newline = std::string::npos;
            while ((newline = buffer.find('\n')) != std::string::npos) {
                std::string line = buffer.substr(0, newline);
                buffer.erase(0, newline + 1);
                line = trim_line(std::move(line));
                if (line.empty()) {
                    continue;
                }
                state_.enqueueRawRequest(line);
                try {
                    connection.send("ok\n");
                } catch (const std::exception &ex) {
                    debug("[socket] failed to send ack: %s\n", ex.what());
                }
            }

            if (buffer.size() > kMaxBuffered) {
                buffer.erase(0, buffer.size() - kMaxBuffered);
            }

            state_.update();
        }
    } catch (const MinimalSocket::Error &err) {
        if (running_) {
            debug("[socket] client error: %s\n", err.what());
        }
    } catch (const std::exception &ex) {
        if (running_) {
            debug("[socket] client exception: %s\n", ex.what());
        }
    }

    {
        std::lock_guard<std::mutex> guard(active_client_mu_);
        active_client_ = nullptr;
    }

    debug("[socket] client disconnected\n");
}
