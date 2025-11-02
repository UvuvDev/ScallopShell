#include "registerdisplay.hpp"
#include "emulatorAPI.hpp"

using namespace ftxui;

namespace ScallopUI {


    Component RegisterDisplay() {
        class Impl : public ComponentBase {
        private:

            bool Focusable() const override { return false; }

            Element OnRender() override {

                std::vector<Element> lines;
                
                const std::vector<std::string>* registers = Emulator::getRegisters();

                static int lastInstructionCount = 0;
                
                auto header = hbox({text("  Register View")}) | underlined | dim | bold | color(Color::SeaGreen1);
                lines.push_back(header);

                for (uint r = 0; r < registers->size(); r++) {
                    auto e = text(registers->at(r)) | color(Color::MediumPurple1);

                    lines.emplace_back(e);
                }

                //lines.emplace_back(text("skibidi!!!!") | color(Color::Purple3));
                auto display = vbox(lines) | border ;

                return display;
            }


        public:

            Impl() {
                
            }

            

        };

        return Make<Impl>();
    }
}