#pragma once
#include <string>
#include <stdio.h>
#include <memory>
#include <thread>
#include <chrono>
#include "MinimalSocket/tcp/TcpClient.h"

class PluginNetwork {
private:

    std::string error;
    static std::unique_ptr<MinimalSocket::tcp::TcpClient<true>> tcp_client;

public:

    static int initialize();
    static std::string sendCommand(std::string cmd);

};
