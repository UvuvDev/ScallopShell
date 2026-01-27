#include "disasmdisplay.hpp"
#include "emulatorAPI.hpp"

#include <unordered_set>

using namespace ftxui;

namespace ScallopUI {


    Component DisasmDisplay(AppStatePtr state) {
        class Impl : public ComponentBase {
        private:
            int rows;
            int currentTopRow = 0;
            int min_top = 37;
            int instructionCount = 0;
            int maxTopRow = 0;
            Box renderedArea;         
            bool follow_tail = true; 
            int totalLines = 0;
            int lastTotalLines = 0;  
            std::vector<Box> rowBoxes;
            std::vector<Box> checkboxBoxes;
            std::vector<uint64_t> rowAddresses;
            std::unordered_set<uint64_t> breakpoints;
            AppStatePtr state_;

            void setBreakpoint(uint64_t address, bool enabled) {
                if (enabled) {
                    // Only send to the backend when the breakpoint is newly enabled.
                    if (!breakpoints.contains(address)) {
                        std::string comment;
                        Emulator::addBreakpoint(address, comment);
                    }
                    breakpoints.insert(address);
                    return;
                }

                // We currently don't have a removeBreakpoint API, so just clear locally.
                breakpoints.erase(address);
            }

            bool Focusable() const override { return true; }

            bool OnEvent(Event e) override {
                
                if (e == Event::ArrowUp) {
                    if (currentTopRow > 0) currentTopRow--;
                    follow_tail = false;
                    return true;
                }

                if (e == Event::PageUp) {
                    currentTopRow = std::max(0, currentTopRow - min_top);
                    follow_tail = false;
                    return true;
                }

                if (e == Event::ArrowDown) {
                    int maxTopRow = std::max(0, totalLines - min_top);
                    if (currentTopRow < maxTopRow) currentTopRow++;
                    if (currentTopRow >= maxTopRow) follow_tail = true; // user came back to bottom
                    return true;
                }

                if (e == Event::PageDown) {
                    int maxTopRow = std::max(0, totalLines - min_top);
                    currentTopRow = std::min(maxTopRow, currentTopRow + min_top);
                    if (currentTopRow >= maxTopRow) follow_tail = true;
                    return true;
                }
                if (e == Event::g) {
                    int maxTopRow = std::max(0, totalLines - min_top);
                    currentTopRow = maxTopRow;
                    follow_tail = true;
                    return true;
                }

                // Hover-to-focus
                if (e.is_mouse()) {
                    const auto& m = e.mouse();
                    const bool inRenderedArea = renderedArea.Contain(m.x, m.y);
                    const bool inDisasmPaneBySplit =
                        state_ ? (m.x >= state_->disasmSplitSize) : true;

                    if (!(inRenderedArea && inDisasmPaneBySplit)) {
                        return false;  // Don't steal mouse events from other panes.
                    }

                    // Only handle explicit checkbox clicks; otherwise let other panes react.
                    if (m.button == Mouse::Left &&
                        (m.motion == Mouse::Pressed || m.motion == Mouse::Released)) {
                        for (int i = 0; i < instructionCount &&
                                        i < static_cast<int>(checkboxBoxes.size()); ++i) {
                            if (!checkboxBoxes[i].Contain(m.x, m.y)) continue;
                            if (i >= static_cast<int>(rowAddresses.size())) return true;
                            const auto address = rowAddresses[static_cast<size_t>(i)];
                            const bool enabled = !breakpoints.contains(address);
                            setBreakpoint(address, enabled);
                            return true;
                        }
                    }

                    if (Focused() && m.button == ftxui::Mouse::WheelUp) {
                        if (currentTopRow > 0) currentTopRow--;
                        follow_tail = false;
                        return true;
                    }
                    if (Focused() && m.button == ftxui::Mouse::WheelDown) {
                        int maxTopRow = std::max(0, totalLines - min_top);
                        if (currentTopRow < maxTopRow) currentTopRow++;
                        if (currentTopRow >= maxTopRow) follow_tail = true; // user came back to bottom
                        return true;
                    }

                    return false;
                }

                return ComponentBase::OnEvent(e); // forward anything else

            }

            Element OnRender() override {

                std::vector<Element> lines;
                static bool hasUpdated = 0;
                
            
                const std::vector<InstructionInfo>* assemblyInstructions = Emulator::getRunInstructions(currentTopRow, min_top, &hasUpdated, &totalLines);

                instructionCount = assemblyInstructions->size();
                maxTopRow = std::max(0, totalLines - min_top);
                rowBoxes.assign(static_cast<size_t>(instructionCount), {});
                checkboxBoxes.assign(static_cast<size_t>(instructionCount), {});
                rowAddresses.assign(static_cast<size_t>(instructionCount), 0);

                auto at_bottom = [&]{
                    int slack = 0;
                    return currentTopRow >= std::max(0, maxTopRow - slack);
                };

                if (hasUpdated) {
                    // If the user was at bottom, keep them at bottom.
                    // Also: if this is first load, follow tail.
                    if (follow_tail || at_bottom()) {
                        currentTopRow = maxTopRow;
                        follow_tail = true;
                    }
                }
                lastTotalLines = totalLines;
                
                auto header = hbox({text("  Disassembly View")}) | underlined | dim | bold | color(Color::CornflowerBlue);
                lines.push_back(header);

                for (int r = 0; r < instructionCount; r++) {
                    const auto& info = assemblyInstructions->at(r);
                    rowAddresses[static_cast<size_t>(r)] = info.address;
                    const bool hasBreakpoint = breakpoints.contains(info.address);
                    const bool checked = hasBreakpoint;

                    Element checkbox = text(checked ? "[x] " : "[ ] ")
                        | reflect(checkboxBoxes[r]);

                    if (checked) {
                        checkbox | color(Color::GrayDark);
                    }
                    else {
                        checkbox | color(Color::White);
                    }

                    auto disasmColor = color(Color::Magenta);

                    if (hasBreakpoint) 
                        disasmColor = color(Color::White);
                    else if (info.instructionType == "other") 
                        disasmColor = color(Color::Magenta);
                    else if (info.instructionType == "jmp") 
                        disasmColor = color(Color::Red1);
                    else if (info.instructionType == "call") 
                        disasmColor = color(Color::Yellow1);
                    else if (info.instructionType == "cond") 
                        disasmColor = color(Color::Orange1);
                    else if (info.instructionType == "ret") 
                        disasmColor = color(Color::MediumPurple1);
                    
                    Element left = hbox({text(hex8ByteStr(info.address)) | disasmColor, text(" - " + info.instruction + "\n") | color(Color::CornflowerBlue)});
                    

                    Element mid = text("   ");//separator();

                    // Print the symbol
                    Element right = hbox({filler(), text(" " +  info.symbol) | color(Color::Magenta)});

                    Element row = hbox({checkbox, left, mid, right}) | reflect(rowBoxes[r]);
                    if (hasBreakpoint) {
                        row = row | color(Color::White);
                    }
                    lines.emplace_back(row);
                    //lines.emplace_back(hbox({left}));
                
                    }

                    auto display = vbox(lines) | border | focus | reflect(renderedArea);

                    if (Focused())
                        return display | color(Color::Magenta);

                    return display;
                }

        
        public:

            explicit Impl(AppStatePtr state) : state_(std::move(state)) {}

            

        };

        return Make<Impl>(std::move(state));
    }
}
