#include "notes.hpp"
#include "emulatorAPI.hpp"

using namespace ftxui;

std::string notes;

void saveNotes() {

    std::fstream file;

    std::filesystem::path notesPath = Emulator::getBreakpointConfigPath(Emulator::getSelectedVCPU()).parent_path() / "notes.txt";
    file.open(notesPath, std::ios_base::out);

    file<<notes;

    file.close();

}

void openNotes() {

    std::ifstream file;
    std::string line;

    std::filesystem::path notesPath = Emulator::getBreakpointConfigPath(Emulator::getSelectedVCPU()).parent_path() / "notes.txt";
    file.open(notesPath, std::ios_base::in);

    int linesRead = 0;
    while (std::getline(file, line)) {
        linesRead++;
        notes += line + "\n";
    }
    if (linesRead > 0 && !notes.empty()) notes.pop_back(); // If a line was read, remove the trailing newline.

    file.close();

}

namespace ScallopUI
{

    Component Notepad()
    {
        struct Impl : ComponentBase
        {
            Component input_;
            Box renderBox_;

            Impl()
            {
                openNotes();

                InputOption opt = InputOption::Default();
                opt.password = false;
                opt.placeholder = "notepad";

                opt.transform = [](InputState s)
                {
                    Element e = std::move(s.element);
                    if (s.is_placeholder)
                        e |= dim;
                    if (s.focused)
                        e |= border;
                    else if (s.hovered)
                        e |= borderRounded;
                    else
                        e |= borderEmpty;
                    return e;
                };

                input_ = Input(&notes, opt);
                Add(input_);
            }

            bool Focusable() const override { return true; }

            bool OnEvent(Event e) override
            {
                // Hover-to-focus
                if (e.is_mouse()) {
                    const auto& m = e.mouse();
                    if (renderBox_.Contain(m.x, m.y) && !Focused()) {
                        TakeFocus();
                    }
                }

                // Ctrl+S to save
                if (e == Event::CtrlS) {
                    saveNotes();
                    return true;
                }

                return input_->OnEvent(e);
            }

            Element OnRender() override
            {
                auto display = input_->Render() | reflect(renderBox_);

                if (Focused())
                    return display | color(Color::Magenta);

                return display;
            }
        };

        return Make<Impl>();
    }
}