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

            Component input;

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

                input = Input(content.get(), opt);

                Add(input);
                
            }

             bool OnEvent(Event e) override {
                // Mouse: click to focus (don’t change tabs!)
                if (e.is_mouse() &&
                    e.mouse().button == Mouse::Left &&
                    e.mouse().motion == Mouse::Pressed &&
                    mouseBox.Contain(e.mouse().x, e.mouse().y)) {
                    TakeFocus();
                    return true;  // consume the click
                }

                // Let the container handle focus traversal
                if (e == Event::Tab || e == Event::TabReverse /* alias of TabReverse in some builds */)
                    return false;

                // If not focused, don't eat keys
                if (!ComponentBase::Focused())
                    return false;

                // Enter => submit command
                if (e == Event::Return) {
                    const std::string line = *content;
                    history.emplace_back(line);
                    content->clear();

                    try {
                    app.parse(line);
                    } catch (const CLI::ParseError &pe) {
                    (void)app.exit(pe);  // consume status
                    }
                    app.clear();           // reset CLI parser state
                    return true;
                }

                // Otherwise, let the inner Input handle typing, arrows, backspace, etc.
                if (input->OnEvent(e)) return true;

                // Fallback so other decorators/containers still get a chance
                return ComponentBase::OnEvent(e);
            }

            bool Focusable() const override { return true; }

            Element OnRender() override {
                // Render the child input and reflect its box for click-to-focus
                auto inner = input->Render() | reflect(mouseBox);

                // Always draw a border; highlight when focused
                return inner
                    | border
                    | color(ComponentBase::Focused() ? Color::Magenta : Color::GrayDark);
            }
            
        };

        return Make<Impl>();
    }

    /**
     * History of past user commands.
     */
    Component CliHistory()
    {

        struct Impl : ComponentBase {

            Element OnRender() override {
                Elements lines;
                
                if (history.size() > historyMaxLen) 
                    history.erase(history.begin()); // Keep lines shown to max length

                for (int i = history.size() - 1; i >= 0; i--) 
                    lines.push_back(text(history.at(i)));
                
                
                auto display = vbox(std::move(lines)) | border | vscroll_indicator | frame | reflect(mouseBox);

                if (Focused()) 
                    return display | color(Color::Magenta);
                
                return display;
            };

        };

        return Make<Impl>();
        

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
