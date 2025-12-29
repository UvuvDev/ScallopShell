#include "disasmdisplay.hpp"
#include "emulatorAPI.hpp"

using namespace ftxui;

namespace ScallopUI {


    Component DisasmDisplay() {
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



                
                
                return ComponentBase::OnEvent(e); // forward anything else

            }

            Element OnRender() override {

                std::vector<Element> lines;
                static bool hasUpdated = 0;
                
            
                const std::vector<InstructionInfo>* assemblyInstructions = Emulator::getRunInstructions(currentTopRow, min_top, &hasUpdated, &totalLines);

                instructionCount = assemblyInstructions->size();
                maxTopRow = std::max(0, totalLines - min_top);

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
                    Element left = text(hex8ByteStr(assemblyInstructions->at(r).address)) | color(Color::Magenta);

                    if (assemblyInstructions->at(r).instructionType == "other") 
                        left = hbox({left, text(" - " + assemblyInstructions->at(r).instruction + "\n") | color(Color::CornflowerBlue)});
                    else if (assemblyInstructions->at(r).instructionType == "jmp") 
                        left = hbox({left, text(" - " + assemblyInstructions->at(r).instruction + "\n") | color(Color::Red1)});
                    else if (assemblyInstructions->at(r).instructionType == "call") 
                        left = hbox({left, text(" - " + assemblyInstructions->at(r).instruction + "\n") | color(Color::Yellow1)});
                    else if (assemblyInstructions->at(r).instructionType == "cond") 
                        left = hbox({left, text(" - " + assemblyInstructions->at(r).instruction + "\n") | color(Color::Orange1)});
                    else if (assemblyInstructions->at(r).instructionType == "ret") 
                        left = hbox({left, text(" - " + assemblyInstructions->at(r).instruction + "\n") | color(Color::MediumPurple1)});
                
                    //Element mid = separator();

                    // Print the symbol
                    //Element right = hbox({filler(), text(" " +  assemblyInstructions->at(r).symbol) | color(Color::Magenta)}) |
                                        size(WIDTH, EQUAL, 100);
                    //lines.emplace_back(hbox({left, mid, right}));
                    lines.emplace_back(hbox({left}));
                
                }

                auto display = vbox(lines) | border | focus | reflect(renderedArea);

                if (Focused())
                    return display | color(Color::Magenta);

                return display;
            }


        public:

            Impl() {
                
            }

            

        };

        return Make<Impl>();
    }
}