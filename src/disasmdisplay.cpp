#include "disasmdisplay.hpp"

using namespace ftxui;

namespace ScallopUI {


    Component DisasmDisplay() {
        class Impl : public ComponentBase {
        private:
            int rows;
            int bottomRow = 0;
            int min_top = 30;
            Box renderedArea;
            std::vector<std::string> assemblyInstructions;


            void initStrings() {
                for (int i = 1; i <= 100; ++i) {
                    assemblyInstructions.emplace_back("mov " + std::to_string(i) + ", rax");
                }
            }

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
                    if (bottomRow < assemblyInstructions.size())
                        bottomRow++;
                    return true;
                }
                /*if (e.is_mouse()) {
                    if (e.mouse().button == ftxui::Mouse::Left && 
                        e.mouse().motion == ftxui::Mouse::Pressed && renderedArea.Contain(e.mouse().x, e.mouse().y)) {

                        TakeFocus();
                        return true;   // consumed
                    }
                    return false;      // let others handle
                }*/
                
                
                return ComponentBase::OnEvent(e); // forward anything else

            }

            Element OnRender() override {

                std::vector<Element> lines;

                auto header = hbox({text("  Disassembly View")}) | underlined | dim | bold | color(Color::Yellow1);
                lines.push_back(header);

                for (int r = bottomRow; r < assemblyInstructions.size(); r++) {
                    auto e = text(" - " + assemblyInstructions.at(r) + "\n") | color(Color::Blue);

                    lines.emplace_back(hbox(e));
                }

                auto display = vbox(lines) | border | focus | reflect(renderedArea);

                return display;
            }


        public:

            Impl() {
                initStrings();
            }

            

        };

        return Make<Impl>();
    }
}