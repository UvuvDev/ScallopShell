#pragma once

#include <algorithm>
#include <exception>
#include <memory>
#include <iostream>
#include <functional>
#include <vector>
#include <unordered_map>
#include <thread>
#include <chrono>

class Event {
    protected:
        uint id;
    public:
        virtual bool check() = 0;

        uint getId() { return id; }
};

class EventHandler {
    protected:
        std::vector<std::shared_ptr<Event>> eventVector;
        std::vector<bool> eventStates;

        EventHandler();
    public:
        EventHandler(std::vector<std::shared_ptr<Event>>& eventVector);
        ~EventHandler();

        std::vector<bool>& getCurrentEvents(uint id);

        bool checkEvent(uint id);

        bool isValidID(uint id);

        std::vector<uint> getAllIDs();

        void startAsyncTask();
};