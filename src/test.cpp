#include <cstdint>
#include <vector>
#include <string>
#include <sstream>
#include <iomanip>
#include <algorithm>

#include <ftxui/component/component.hpp>
#include <ftxui/component/screen_interactive.hpp>
#include <ftxui/dom/elements.hpp>

#include "memorydisplay.hpp"
#include "cligui.hpp"
#include "notes.hpp"

using namespace ftxui;

std::string Code(Event event)
{
  std::string codes;
  for (auto &it : event.input())
  {
    codes += " " + std::to_string((unsigned int)it);
  }
  return codes;
}

Component DummyWindowContent(std::vector<uint8_t> &memory_)
{
  class Impl : public ComponentBase
  {
  private:
    bool checked[3] = {false, false, false};
    float slider = 50;

  public:
    Impl(std::vector<uint8_t> &memory_)
    {
      Add({ScallopUI::MemoryDisplay(memory_.data(), memory_.size(), 0, 16)});
    }
  };
  return Make<Impl>(memory_);
}

int main()
{


  ScallopUI::initCliCommands();

  auto screen = ScreenInteractive::Fullscreen();

  std::vector<uint8_t> memory(1024);
  for (size_t i = 0; i < memory.size(); ++i)
    memory[i] = (i * 17) & 0xFF;

  std::vector<uint8_t> codeMem(1024);
  for (size_t i = 0; i < codeMem.size(); ++i)
    codeMem[i] = (i * 1) & 0xFF;

  // auto mem = ScallopUI::MemoryDisplay(memory.data(), memory.size(), 0x7ffff560000, 16, 16);
  auto mem = DummyWindowContent(memory);
  auto code = DummyWindowContent(codeMem);
  auto notes = ScallopUI::Notepad();


  /*=================*/

  /*================*/


  std::vector<std::string> tab_values{
      "memory",
      "code",
      "notepad",
  };
  
  int tab_selected = 0;
  auto tab_toggle = Toggle(&tab_values, &tab_selected);

  auto tab_container = Container::Tab(
      {
          mem, 
          code,
          notes,
      },
      &tab_selected);

  auto container = Container::Vertical({
      tab_toggle,
      tab_container,
  });

  auto renderer = Renderer(container, [&] {
    return vbox({
               tab_toggle->Render(),
               separator(),
               tab_container->Render(),
           }) |
           border;
  });

  /*===============*/




  auto history = ScallopUI::CliHistory();
  int splitCliMem = 10;
  int splitCliHistory = 90;

  auto input = ScallopUI::InputCli();

  auto componentA = ResizableSplitLeft(input, history, &splitCliHistory);

  auto componentB = ResizableSplitBottom(componentA, renderer, &splitCliMem);

  //auto FullScreen = ftxui::

  // Show it full-screen
  screen.Loop(componentB);
  return 0;
}
