#pragma once

#include <cstdint>
#include <vector>
#include <string>
#include <sstream>
#include <iomanip>
#include <algorithm>
#include <iostream>

#include <ftxui/component/component.hpp>
#include <ftxui/component/screen_interactive.hpp>
#include <ftxui/dom/elements.hpp>

#include "guihelpers.hpp"
#include "appstate.hpp"

namespace ScallopUI {

    // New AppState-aware version
    ftxui::Component MemoryDisplayWithState(AppStatePtr state, std::string followedReg,
                                             size_t size, uint64_t base_addr = 0,
                                             int bytesPerRow = 24, int visibleRows = 30);

    // Legacy wrapper for backward compatibility (creates internal state)
    ftxui::Component MemoryDisplay(std::vector<uint8_t>* data, std::string followedReg, size_t size,
                                   uint64_t base_addr = 0, int bytesPerRow = 24, int visibleRows = 30);

}
