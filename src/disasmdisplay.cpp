#include "disasmdisplay.hpp"
#include "emulatorAPI.hpp"

using namespace ftxui;

namespace ScallopUI {


    Component DisasmDisplay() {
        class Impl : public ComponentBase {
        private:
            int rows;
            int bottomRow = 0;
            int min_top = 37;
            int instructionCount = 0;
            Box renderedArea;
            

            

            bool Focusable() const override { return true; }

            bool OnEvent(Event e) override {
                
                if (e == Event::ArrowUp)
                {
                    if (bottomRow > 0)
                        bottomRow--;
                    
                    return true;
                }
                if (e == Event::ArrowDown)
                {
                    if (bottomRow < instructionCount)
                        bottomRow++;
                    return true;
                }
                
                
                return ComponentBase::OnEvent(e); // forward anything else

            }

            Element OnRender() override {

                std::vector<Element> lines;
                static int hasUpdated = false;
                

                //if (hasUpdated > 0) { bottomRow = hasUpdated; }

                const std::vector<InstructionInfo>* assemblyInstructions = Emulator::getRunInstructions(bottomRow, min_top, &hasUpdated);

                instructionCount = assemblyInstructions->size();
                
                auto header = hbox({text("  Disassembly View")}) | underlined | dim | bold | color(Color::CornflowerBlue);
                lines.push_back(header);

                for (int r = 0; r < instructionCount; r++) {
                    auto e = text(hex8ByteStr(assemblyInstructions->at(r).address)) | color(Color::Magenta);

                    if (assemblyInstructions->at(r).instructionType == "other") 
                        e = hbox({e, text(" - " + assemblyInstructions->at(r).instruction + "\n") | color(Color::CornflowerBlue)});
                    else if (assemblyInstructions->at(r).instructionType == "jmp") 
                        e = hbox({e, text(" - " + assemblyInstructions->at(r).instruction + "\n") | color(Color::Red1)});
                    else if (assemblyInstructions->at(r).instructionType == "call") 
                        e = hbox({e, text(" - " + assemblyInstructions->at(r).instruction + "\n") | color(Color::Yellow1)});
                    else if (assemblyInstructions->at(r).instructionType == "cond") 
                        e = hbox({e, text(" - " + assemblyInstructions->at(r).instruction + "\n") | color(Color::Orange1)});
                    else if (assemblyInstructions->at(r).instructionType == "ret") 
                        e = hbox({e, text(" - " + assemblyInstructions->at(r).instruction + "\n") | color(Color::MediumPurple1)});
                        //e = hbox({e, text("     took branch -> " +  hex8ByteStr(assemblyInstructions->at(r).addrTaken)) | color(Color::Red1)});
                    lines.emplace_back(e);
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