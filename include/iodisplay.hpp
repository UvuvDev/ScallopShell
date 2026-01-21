
#include <ftxui/component/component.hpp>
#include <ftxui/component/screen_interactive.hpp>
#include <ftxui/dom/elements.hpp>

#include "guihelpers.hpp"
#include "emulatorAPI.hpp"

namespace ScallopUI {

    /**
     * Component that displays I/O from the emulator.
     * Fetches file descriptors dynamically from Emulator::getOutputFd()/getInputFd()
     * so it automatically works after emulator reset.
     */
    ftxui::Component ioDisplay();

}