#include "notes.hpp"

using namespace ftxui;

std::string notes;

void saveNotes() {

    std::fstream file;

    file.open("notes.txt", std::ios_base::out);

    file<<notes;

    file.close();

}

void openNotes() {

    std::ifstream file;
    std::string line;

    file.open("notes.txt");

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
                    return e; // no bgcolor/inverted => transparent
                };

                auto input = Input(&notes, opt);

                Add(ftxui::CatchEvent(input, [this](ftxui::Event e)
                                      {
                                        
                    if (e == ftxui::Event::CtrlS) {
                        saveNotes();
                        return true; 
                    }
                    return false; }));
            }

            
        };

        return Make<Impl>();
    }
}