#include "cligui.hpp"
#include <memory>
#include <stdlib.h>

using namespace ftxui;

void skibidi()
{
    FILE *skib = fopen("skibidi.txt", "w+");
    fwrite("pleaseeeeeeeeeeeee", 1, 10, skib);
    fclose(skib);
}

void skibidi2()
{
    FILE *skib = fopen("skibidi2.txt", "w+");
    fwrite("pleaseeeeeeeeeeeee", 1, 10, skib);
    fclose(skib);
}

void skibidi3()
{
    
    //ScreenInteractive::Exit();
}

namespace ScallopUI
{

    std::vector<std::string> history;
    uint historyMaxLen = 10;
    CLI::App app("Scallop Shell");
    ftxui::Box mouseBox;

    Component InputCli()
    {
        struct Impl : ComponentBase
        {
        
            std::shared_ptr<std::string> content = std::make_shared<std::string>();
            std::shared_ptr<std::string> placeholder = std::make_shared<std::string>(" > ");

            Impl()
            {
                InputOption opt = InputOption::Default();
                opt.password = false;
                opt.placeholder = placeholder.get(); // safe: Impl owns it

                opt.transform = [](InputState s)
                {
                    Element e = std::move(s.element);
                    if (s.is_placeholder)
                        e |= dim;

                    e |= border;
                    /*if (s.focused)
                        e |= border;
                    else if (s.hovered)
                        e |= borderRounded;
                    else
                        e |= borderEmpty;*/
                    return e; // no bgcolor/inverted => transparent
                };

                auto input = Input(content.get(), opt);

                Add(ftxui::CatchEvent(input, [this](ftxui::Event e)
                                      {
                                        
                    if (e == ftxui::Event::Return) {
                        std::string line = *content;
                        history.emplace_back(*content);
                        content->clear();

                        try {
                            app.parse(line);
                        } catch (const CLI::ParseError &pe) {
                            (void)app.exit(pe);   // returns an int status
                        }
                        app.clear(); // Reset Cli

                        return true; 
                    }
                    if (e == Event::Tab || e == Event::TabReverse) {
                        return false; // let container handle focus change
                    }
                    if (e.is_mouse()) {
                        if (e.mouse().button == ftxui::Mouse::Left && 
                            e.mouse().motion == ftxui::Mouse::Pressed && mouseBox.Contain(e.mouse().x, e.mouse().y)) {

                            //TakeFocus();
                            return true;   // consumed
                        }
                        return false;      // let others handle
                    }
                    
                    return false; }));
            }
        };

        return Make<Impl>();
    }

    /**
     * History of past user commands.
     */
    Component CliHistory()
    {

        return Renderer([] {
            Elements lines;
            
            if (history.size() > historyMaxLen) 
                history.erase(history.begin()); // Keep lines shown to max length

            for (int i = history.size() - 1; i >= 0; i--) 
                lines.push_back(text(history.at(i)));
            
            return vbox(std::move(lines)) | border | vscroll_indicator | frame | reflect(mouseBox);
        });

    }

    void initCliCommands()
    {
        auto help = app.add_subcommand("help", "Parameter");
        help->callback(skibidi);

        auto help2 = app.add_subcommand("print", "Parameter");
        help2->callback(skibidi2);

        auto help3 = app.add_subcommand("quit", "Parameter");
        help3->callback(skibidi3);
    }

} // namespace ScallopUI
