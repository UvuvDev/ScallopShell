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
        int selectedCpu_ = 0;
        int selectedThread_ = 0;
        int lastSelectedCpu_ = -1;
        std::vector<std::string> cpuEntries_;
        std::vector<std::string> threadEntries_;
        Component cpuRadiobox_;
        Component threadRadiobox_;
        Component container_;
        std::string cpuArt_;

        bool Focusable() const override { return true; }

        void updateSelection() {
            // Update thread list if CPU changed
            if (selectedCpu_ != lastSelectedCpu_) {
                threadEntries_ = Emulator::getVCPUThreadList(selectedCpu_);
                selectedThread_ = 0;
                lastSelectedCpu_ = selectedCpu_;
            }

            // Always update the global selected CPU and thread
            Emulator::setSelectedVCPU(selectedCpu_);
            if (selectedThread_ >= 0 && selectedThread_ < (int)threadEntries_.size()) {
                Emulator::setSelectedThread(threadEntries_[selectedThread_]);
            }
        }

        Element OnRender() override {
            updateSelection();

            auto headerColor = Color::CornflowerBlue;
            auto threadColor = Color::Magenta;

            // Create header with CPU ASCII art
            std::vector<Element> artLines;
            std::istringstream artStream(cpuArt_);
            std::string line;
            while (std::getline(artStream, line)) {
                artLines.push_back(text(line));
            }

            auto header = vbox(artLines) | color(headerColor) | bold;

            auto cpuSection = vbox({
                text("Select CPU:") | bold,
                cpuRadiobox_->Render() | vscroll_indicator | frame | size(HEIGHT, LESS_THAN, 16),
            });

            auto threadSection = vbox({
                text("Threads on CPU " + std::to_string(selectedCpu_) + ":") | bold | color(threadColor),
                threadRadiobox_->Render() | vscroll_indicator | frame | size(HEIGHT, LESS_THAN, 16),
            });

            auto content = vbox({
                header,
                separator(),
                hbox({
                    cpuSection | flex,
                    separator(),
                    threadSection | flex,
                }),
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

            // Initialize thread list for CPU 0
            threadEntries_ = Emulator::getVCPUThreadList(0);
            lastSelectedCpu_ = 0;

            // Initialize global selection state
            Emulator::setSelectedVCPU(0);
            if (!threadEntries_.empty()) {
                Emulator::setSelectedThread(threadEntries_[0]);
            }

            // Create the radiobox components
            cpuRadiobox_ = Radiobox(&cpuEntries_, &selectedCpu_);
            threadRadiobox_ = Radiobox(&threadEntries_, &selectedThread_);

            // Create horizontal container for both radioboxes
            container_ = Container::Horizontal({
                cpuRadiobox_,
                threadRadiobox_,
            });
            Add(container_);
        }

        int getSelectedCpu() const {
            return selectedCpu_;
        }

        int getSelectedThread() const {
            return selectedThread_;
        }
    };

    return Make<Impl>();
}

}
