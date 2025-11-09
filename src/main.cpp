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
#include "registerdisplay.hpp"
#include "debug.hpp"

using namespace ftxui;




int main()
{


  ScallopUI::initCliCommands();

  std::atomic<bool> running = true;

  auto screen = ScreenInteractive::Fullscreen();
  ftxui::ScreenInteractive* g_screen = &screen;

  // auto mem = ScallopUI::MemoryDisplay(memory.data(), memory.size(), 0x7ffff560000, 16, 16);
  const int memoryRange = 0;
  auto mem  = ScallopUI::MemoryDisplay(nullptr, memoryRange, 0, 8);
  auto code  = ScallopUI::MemoryDisplay(nullptr, memoryRange, 0, 8);
  auto notes = ScallopUI::Notepad();
  auto regs = ScallopUI::RegisterDisplay();

  Emulator emu;
  int pid = emu.startEmulation("/home/bradley/Downloads/a.out");
  if (pid < 0) {
      std::cerr << "Failed to start QEMU\n";
  }

  std::this_thread::sleep_for(std::chrono::milliseconds(1000));

  /*=================*/

  /*================*/


  std::vector<std::string> tab_names{
      "memory",
      "code",
      "notepad",
      "regs",
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
          regs,
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

  auto cli_input = ScallopUI::InputCli();
  auto cli_pane = Container::Horizontal({
    cli_input,
    ScallopUI::CliHistory(),
  });

  int splitCliHistory = 90;
  auto cli_split = ResizableSplitLeft(cli_pane->ChildAt(0), cli_pane->ChildAt(1), &splitCliHistory);

  // Final vertical split: CLI (bottom) vs center (top)
  int splitCliMem = 10;
  auto root = ResizableSplitBottom(cli_split, centerTop, &splitCliMem);


  std::thread([&]{
    while (running) {
        std::this_thread::sleep_for(std::chrono::milliseconds(25));
        if (g_screen) g_screen->PostEvent(ftxui::Event::Custom);
    }
  }).detach();


  root = CatchEvent(root, [&](const Event& e) {
    // Example: focus CLI on Ctrl key press
    if (e == Event::CtrlS) {
        cli_input->TakeFocus();
        return true;  // consume
    }
    else if (e == Event::CtrlD) {
      disasm->TakeFocus();
      return true;
    }
    else if (e == Event::CtrlM) {
      mem->TakeFocus();
      return true;
    }
    else if (e == Event::CtrlA) {
      code->TakeFocus();
      return true;
    }
    return false;     // let others handle it
  });

  // Show it full-screen
  screen.Loop(root);

  running = false;
  return 0;
}