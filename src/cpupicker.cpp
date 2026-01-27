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
        int lastVcpuCount_ = -1;
        std::vector<std::string> cpuEntries_;
        std::vector<std::string> threadEntries_;
        Component cpuRadiobox_;
        Component threadRadiobox_;
        Component container_;
        std::string cpuArt_;
        Box renderBox_;

        bool Focusable() const override { return true; }

        bool OnEvent(Event e) override {
            // Hover-to-focus
            if (e.is_mouse()) {
                const auto& m = e.mouse();
                if (renderBox_.Contain(m.x, m.y) && !Focused()) {
                    TakeFocus();
                }
            }
            return ComponentBase::OnEvent(e);
        }

        void refreshVCPUList() {
            // Query current VCPU count from backend
            int vcpuCount = Emulator::getVCPUCount();
            if (vcpuCount > 16) {
                vcpuCount = 16;
            }

            // Only rebuild if count changed
            if (vcpuCount != lastVcpuCount_ && vcpuCount > 0) {
                cpuEntries_.clear();
                for (int i = 0; i < vcpuCount; i++) {
                    cpuEntries_.push_back("CPU " + std::to_string(i));
                }
                lastVcpuCount_ = vcpuCount;

                // Clamp selection if needed
                if (selectedCpu_ >= vcpuCount) {
                    selectedCpu_ = vcpuCount - 1;
                }
            }
        }

        void updateSelection() {
            // Refresh VCPU list from backend
            refreshVCPUList();

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
            }) | border | reflect(renderBox_);

            if (Focused())
                return content | color(Color::Magenta);

            return content;
        }

    public:
        Impl() {
            // Load CPU ASCII art
            cpuArt_ = loadAsset("assets/CPU.txt");

            // Initialize with at least one CPU entry (will be refreshed dynamically)
            cpuEntries_.push_back("CPU 0");
            lastVcpuCount_ = 1;

            // Initialize thread list for CPU 0
            threadEntries_.push_back("thread_0_0");
            lastSelectedCpu_ = 0;

            // Initialize global selection state
            Emulator::setSelectedVCPU(0);
            Emulator::setSelectedThread(threadEntries_[0]);

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
