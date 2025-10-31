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
#include "disasmdisplay.hpp"
#include "emulatorAPI.hpp"

using namespace ftxui;




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
  auto mem  = ScallopUI::MemoryDisplay(memory.data(), memory.size(), 0, 8);
  auto code = ScallopUI::MemoryDisplay(codeMem.data(), codeMem.size(), 0, 8);
  auto notes = ScallopUI::Notepad();


  /*=================*/

  /*================*/


  std::vector<std::string> tab_names{
      "memory",
      "code",
      "notepad",
  };
  
  int tab_selected = 0;
  auto tab_toggle = Toggle(&tab_names, &tab_selected);

  tab_toggle = CatchEvent(tab_toggle, [&](Event e){
    if (!tab_toggle->Focused())
      return false; // don't consume events if not focused
    return false;
  });

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

  auto left_stack = Container::Vertical({
    tab_toggle,
    tab_container,
  });

  auto left_render = Renderer(left_stack, [&] {
    return vbox({
            tab_toggle->Render(),
            separator(),
            tab_container->Render(),
          }) | border;
  });
  
  /*===============*/

  auto disasm = ScallopUI::DisasmDisplay();
  int disasmSize = 100;

  auto right_stack = Container::Vertical({
    disasm,        // ensure DisasmDisplay() is focusable
  });
  auto right_render = Renderer(right_stack, [&] {
    return disasm->Render();
  });
  auto centerTop = ResizableSplitLeft(left_render, right_render, &disasmSize);

  /*===============*/

  auto cli_pane = Container::Horizontal({
    ScallopUI::InputCli(),
    ScallopUI::CliHistory(),
  });

  int splitCliHistory = 90;
  auto cli_split = ResizableSplitLeft(cli_pane->ChildAt(0), cli_pane->ChildAt(1), &splitCliHistory);

  // Final vertical split: CLI (bottom) vs center (top)
  int splitCliMem = 10;
  auto root = ResizableSplitBottom(cli_split, centerTop, &splitCliMem);

  Emulator emu;
  int pid = emu.startEmulation("/home/bradley/Downloads/a.out");
  if (pid < 0) {
      std::cerr << "Failed to start QEMU\n";
  } else {
    FILE* rizz = fopen("WEGOTIT.TXT", "w+");
    fwrite("LETS GOOOO", 11, 1, rizz);
    fclose(rizz);
  }

  // Show it full-screen
  screen.Loop(root);
  return 0;
}
