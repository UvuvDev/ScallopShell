#include "cpupicker.hpp"

#include <fstream>
#include <sstream>
#include <vector>
#include <string>

using namespace ftxui;

namespace ScallopUI {

namespace {
    // Load ASCII art from assets file
    std::string loadAsset(const std::string& filename) {
        std::ifstream file(filename);
        if (!file.is_open()) {
            return "";
        }
        std::stringstream buffer;
        buffer << file.rdbuf();
        return buffer.str();
    }
}

Component cpuPicker() {
    class Impl : public ComponentBase {
    private:
        int selected_ = 0;
        std::vector<std::string> cpuEntries_;
        Component radiobox_;
        std::string cpuArt_;

        bool Focusable() const override { return true; }

        Element OnRender() override {
            auto headerColor = Color::CornflowerBlue;

            // Create header with CPU ASCII art
            std::vector<Element> artLines;
            std::istringstream artStream(cpuArt_);
            std::string line;
            while (std::getline(artStream, line)) {
                artLines.push_back(text(line));
            }

            auto header = vbox(artLines) | color(headerColor) | bold;

            auto content = vbox({
                header,
                separator(),
                radiobox_->Render() | vscroll_indicator | frame | size(HEIGHT, LESS_THAN, 16),
            }) | border;

            return content;
        }

    public:
        Impl() {
            // Load CPU ASCII art
            cpuArt_ = loadAsset("assets/CPU.txt");

            // Get the number of VCPUs from the emulator API
            int vcpuCount = Emulator::getVCPUCount();

            // Limit to 16 max
            if (vcpuCount > 16) {
                vcpuCount = 16;
            }

            // Create entries for each CPU
            for (int i = 0; i < vcpuCount; i++) {
                cpuEntries_.push_back("CPU " + std::to_string(i));
            }

            // Create the radiobox component
            radiobox_ = Radiobox(&cpuEntries_, &selected_);
            Add(radiobox_);
        }

        int getSelected() const {
            return selected_;
        }
    };

    return Make<Impl>();
}

}
