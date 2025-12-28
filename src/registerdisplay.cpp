#include "registerdisplay.hpp"
#include "emulatorAPI.hpp"

using namespace ftxui;

namespace ScallopUI
{

    Component RegisterDisplay()
    {
        class Impl : public ComponentBase
        {
        private:
            Box renderBox;

            bool Focusable() const override { return false; }

            Element OnRender() override
            {

                const std::vector<std::string> *registers = Emulator::getRegisters();
                
                // Lines and color definitions
                std::vector<Element> lines;
                auto headerColor = Color::CornflowerBlue;
                auto leftSideColor = Color::Magenta;
                auto rightSideColor = Color::CornflowerBlue;
                

                // Set the header 
                auto header = hbox({text("  Register View")}) | underlined | dim | bold | color(headerColor);
                lines.push_back(header);

                // For every register that we get back:
                for (uint r = 0; r < registers->size(); r++)
                {
                    // If it's not at either the last or the second to last register:
                    if (r + 1 < registers->size())
                    {
                        Element left = text(registers->at(r)) | color(leftSideColor) | size(WIDTH, EQUAL, 50);

                        Element mid = separator();

                        // Right column: filler eats remaining space on the left, text ends up at the right edge
                        Element right = hbox({
                                            filler(), // expands
                                            text(registers->at(r + 1)) | color(rightSideColor),
                                        }) |
                                        size(WIDTH, EQUAL, 50);

                        lines.emplace_back(hbox({left, mid, right}));
                        r++;
                    }
                    else
                    {
                        // If there's one more register left, put it on the left side
                        lines.emplace_back(text(registers->at(r)) | color(leftSideColor));
                    }
                }

                auto display = vbox(lines) | border | reflect(renderBox);
                return display;
            }

        public:
            Impl()
            {
            }
        };

        return Make<Impl>();
    }
}