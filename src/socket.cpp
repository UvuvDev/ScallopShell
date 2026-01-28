#include "socket.hpp"



std::unique_ptr<MinimalSocket::tcp::TcpClient<true>> PluginNetwork::tcp_client;
bool PluginNetwork::connected_ = false;

int PluginNetwork::initialize() {

    using namespace std::chrono_literals;

    std::this_thread::sleep_for(100ms);

    if (connected_) {
        tcp_client->shutDown();
    }

    static MinimalSocket::Port server_port = 31337;
    static std::string server_address = "127.0.0.1";

    try {
        tcp_client = std::make_unique<MinimalSocket::tcp::TcpClient<true>>(MinimalSocket::Address{server_address, server_port});
    }
    catch (const std::exception &ex) {
        fprintf(stderr, "[socket] failed to create TCP client: %s\n", ex.what());
        return 1;
    }
    

    for (int attempts = 0; attempts < 60; attempts++) {
        bool success = false;

        try {
            success = tcp_client->open();
        }
        catch (const std::exception &ex) {
            fprintf(stderr, "[socket] connect attempt %d failed: %s\n", attempts + 1, ex.what());
        }

        if (success) {
            connected_ = true;
            return 0;
        }

        std::this_thread::sleep_for(100ms);
    }

    return 1;

}

bool PluginNetwork::isConnected() {
    return connected_;
}

std::string PluginNetwork::sendCommand(std::string cmd) {

    if (!tcp_client || !connected_) {
        return {};
    }

    if (cmd.empty() || cmd.back() != '\n')
        cmd.push_back('\n');

    try {
        tcp_client->send(cmd);
        std::size_t message_max_size = 1000;
        std::string received_message = tcp_client->receive(message_max_size);

        // Empty response likely means connection closed
        if (received_message.empty()) {
            connected_ = false;
        }

        return received_message;
    }
    catch (...) {
        // Any exception means connection is dead
        connected_ = false;
        return "";
    }
}
