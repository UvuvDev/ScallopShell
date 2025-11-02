#include "registerdisplay.hpp"
#include "emulatorAPI.hpp"

using namespace ftxui;

namespace ScallopUI {


    Component RegisterDisplay() {
        class Impl : public ComponentBase {
        private:


            Box renderBox;

            bool Focusable() const override { return false; }

            Element OnRender() override {

                std::vector<Element> lines;
                
                const std::vector<std::string>* registers = Emulator::getRegisters();

                auto header = hbox({text("  Register View")}) | underlined | dim | bold | color(Color::SeaGreen1);
                lines.push_back(header);

                for (uint r = 0; r < registers->size(); r++) {
                    if (r + 1 < registers->size()) {
                        Element left = text(registers->at(r))
                                    | color(Color::MediumPurple1)
                                    | size(WIDTH, EQUAL, 50);

                        Element mid = separator();

                        // Right column: filler eats remaining space on the left → text ends up at the right edge
                        Element right = hbox({
                                        filler(),  // expands
                                        text(registers->at(r + 1)) | color(Color::Orange1),
                                        }) | size(WIDTH, EQUAL, 50);

                        lines.emplace_back(hbox({ left, mid, right }));
                        r++;
                    } else {
                        lines.emplace_back(text(registers->at(r)) | color(Color::MediumPurple1));
                    }
                    }

                //lines.emplace_back(text("skibidi!!!!") | color(Color::Purple3));
                auto display = vbox(lines) | border | reflect(renderBox) ;

                
                return display;
            }


        public:

            Impl() {
                
            }

            

        };

        return Make<Impl>();
    }
}