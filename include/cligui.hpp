#pragma once
#include <ftxui/component/component.hpp>
#include <ftxui/component/screen_interactive.hpp>
#include <ftxui/dom/elements.hpp>
#include "CLI11.hpp"

namespace ScallopUI {

    extern CLI::App app;
    ftxui::Component InputCli();
    ftxui::Component CliHistory();
    void initCliCommands();

}