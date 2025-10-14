#include "gui.hpp"
#include "loop.hpp"

#include <deque>
#include <mutex>
#include <thread>
#include <atomic>
#include <vector>
#include <string>
#include <sstream>
#include <cstdio>
#include <cstdint>
#include <inttypes.h>
#include <cstring>
#include <cerrno>
#include <cstdlib>

// FTXUI
#include <ftxui/component/component.hpp>
#include <ftxui/component/screen_interactive.hpp>
#include <ftxui/dom/elements.hpp>
#include <ftxui/component/scroller.hpp>   

// Single global ScreenInteractive
static ftxui::ScreenInteractive screen = ftxui::ScreenInteractive::Fullscreen();
static std::condition_variable cmd_cv;
// gui.cpp
std::atomic<bool> g_continue_mode{false}; // start paused (step mode)
std::atomic<bool> g_quit{false};

namespace
{
  struct Model
  {
    std::deque<std::string> log;
    std::deque<std::string> cmdq; // commands typed in FTXUI input line
    std::string input;
    std::string status;
    size_t max_lines = 5000;
    std::mutex mtx;
  };

  std::atomic<bool> running{false};
  Model model;
  static std::string g_last_cmd = "ni";

  ftxui::Element RenderLog()
  {
    std::vector<ftxui::Element> lines;
    std::lock_guard<std::mutex> lk(model.mtx);
    lines.reserve(model.log.size());
    for (auto &s : model.log)
      lines.push_back(ftxui::text(s));
    return ftxui::vbox(std::move(lines));
  }

  ftxui::Component BuildRoot()
  {
    // --- input line
    ftxui::Component input = ftxui::Input(&model.input, "enter command…");

    // --- log view (Element -> Component -> Scroller)
    auto log_renderer = ftxui::Renderer([&]
                                        { return RenderLog() | ftxui::vscroll_indicator | ftxui::yframe // clip to viewport
                                                 | ftxui::size(ftxui::HEIGHT, ftxui::GREATER_THAN, 20) | ftxui::borderRounded; });
    auto log_scroller = ftxui::Scroller(log_renderer); // <-- makes it scrollable

    // Keep both components in a container so the scroller can receive events.
    auto container = ftxui::Container::Vertical({
        log_scroller,
        input,
    });
    container->SetActiveChild(input); // focus starts on input

    auto push_cmd = [&]
    {
      std::string cmd;
      bool did_push = false;
      {
        std::lock_guard<std::mutex> lk(model.mtx);
        cmd.swap(model.input);

        // trim
        while (!cmd.empty() && (cmd.back() == '\n' || cmd.back() == '\r' || isspace((unsigned char)cmd.back())))
          cmd.pop_back();
        while (!cmd.empty() && isspace((unsigned char)cmd.front()))
          cmd.erase(cmd.begin());

        if (!cmd.empty())
        {
          g_last_cmd = cmd;
          model.cmdq.push_back(cmd);
          did_push = true;
        }
        else if (!g_last_cmd.empty())
        {
          model.cmdq.push_back(g_last_cmd); // repeat last command on empty Enter
          did_push = true;
        }
      }
      if (did_push)
        cmd_cv.notify_one();
    };

    auto renderer = ftxui::Renderer(container, [&]
                                    {
    ftxui::Element status_el;
    {
      std::lock_guard<std::mutex> lk(model.mtx);
      status_el = ftxui::text(model.status);
    }

    return ftxui::vbox({
      ftxui::text(" Scallop Shell — Instruction Panel ")
        | ftxui::bold | ftxui::center | ftxui::border,
      log_scroller->Render(),                                   // <-- component
      ftxui::separator(),
      ftxui::hbox({ ftxui::text("> "), input->Render() }) | ftxui::border,
      status_el | ftxui::dim,
    }); });

    // Let Enter/Esc work as before. Also forward scroll keys to the scroller
    // even when the input has focus.
    return ftxui::CatchEvent(renderer, [&](ftxui::Event e)
                             {
    if (e == ftxui::Event::Return) { push_cmd(); return true; }
    if (e == ftxui::Event::Escape) {
      std::lock_guard<std::mutex> lk(model.mtx);
      model.input.clear();
      return true;
    }
    if (e == ftxui::Event::PageDown || e == ftxui::Event::PageUp ||
        e == ftxui::Event::ArrowDown || e == ftxui::Event::ArrowUp ||
        e == ftxui::Event::End || e == ftxui::Event::Home) {
      log_scroller->OnEvent(e);   // let the scroller handle these
      return true;
    }
    return false; });
  }

  void LogUnsafe_nolock(const std::string &s)
  {
    model.log.push_back(s);
    if (model.log.size() > model.max_lines)
      model.log.pop_front();
  }
}

bool UiPopCommandBlocking(std::string &out)
{
  std::unique_lock<std::mutex> lk(model.mtx);
  cmd_cv.wait(lk, []
              { return !model.cmdq.empty(); });
  out = std::move(model.cmdq.front());
  model.cmdq.pop_front();
  return true;
}

// ------------- Public UI API -------------
void UiStart()
{
  static std::thread t([]
                       {
    auto root = BuildRoot();
    running = true;
    screen.Loop(root);
    running = false; });
  t.detach(); // <<< prevent std::terminate() on shutdown
}

void UiStop()
{
  screen.Exit();
}

void UiLog(const std::string &s)
{
  {
    std::lock_guard<std::mutex> lk(model.mtx);
    LogUnsafe_nolock(s);
  }
  screen.PostEvent(ftxui::Event::Custom);
}

void UiLogRaw(const std::string &s) { UiLog(s); }

void UiClear()
{
  {
    std::lock_guard<std::mutex> lk(model.mtx);
    model.log.clear();
  }
  screen.PostEvent(ftxui::Event::Custom);
}

bool UiPopCommand(std::string &out)
{
  std::lock_guard<std::mutex> lk(model.mtx);
  if (model.cmdq.empty())
    return false;
  out = std::move(model.cmdq.front());
  model.cmdq.pop_front();
  return true;
}

void UiSetStatus(const std::string &line)
{
  {
    std::lock_guard<std::mutex> lk(model.mtx);
    model.status = line;
  }
  screen.PostEvent(ftxui::Event::Custom);
}

// ----------------- CLI + printers -----------------

ExamineFlags xFlags;
int bytesToExamine = 0;
bool printGLIBC = true;

// parsed args stash (for x/b)
static std::optional<uint64_t> g_examine_addr;
static std::optional<uint64_t> g_break_addr;
static std::string g_break_desc;
static bool g_break_save = false;

static void parse_x_command(const std::string &cmd)
{
  // syntax: x/[N][g|w|h|b] <addr>
  xFlags = ExamineFlags::g;
  int tmpN = bytesToExamine;
  // parse /Nf if present
  auto slash = cmd.find('/');
  if (slash != std::string::npos)
  {
    const char *p = cmd.c_str() + slash + 1;
    int n = 0;
    char c = 0;
    if (sscanf(p, "%d%c", &n, &c) >= 1)
    {
      if (n > 0)
        tmpN = n;
      switch (c)
      {
      case 'g':
        xFlags = ExamineFlags::g;
        break;
      case 'w':
        xFlags = ExamineFlags::w;
        break;
      case 'h':
        xFlags = ExamineFlags::h;
        break;
      case 'b':
        xFlags = ExamineFlags::b;
        break;
      default:
        break;
      }
    }
  }
  bytesToExamine = tmpN;

  // parse address (last token)
  std::istringstream iss(cmd);
  std::string tok, last;
  while (iss >> tok)
    last = tok;
  if (!last.empty())
  {
    try
    {
      g_examine_addr = std::stoull(last, nullptr, 0);
    }
    catch (...)
    {
      g_examine_addr.reset();
    }
  }
}

static void parse_b_command(const std::string &cmd)
{
  // syntax: b <hex_addr> <desc> [save]
  g_break_addr.reset();
  g_break_desc.clear();
  g_break_save = false;

  std::istringstream iss(cmd);
  std::string bcmd, addr_s, desc_s, save_s;
  iss >> bcmd >> addr_s >> desc_s >> save_s;
  if (!addr_s.empty())
  {
    try
    {
      g_break_addr = std::stoull(addr_s, nullptr, 0);
    }
    catch (...)
    {
      g_break_addr.reset();
    }
  }
  if (!desc_s.empty())
    g_break_desc = desc_s;
  if (!save_s.empty())
    g_break_save = (save_s[0] == 'y' || save_s[0] == 'Y' || save_s[0] == 's' || save_s[0] == 'S');
}

int Cli(CliFlags *out_flags)
{
  // Non-blocking: read one command if user typed anything in the FTXUI input.
  std::string cmd;
  if (!UiPopCommandBlocking(cmd))
    return 2; // nothing this frame

  if (cmd.empty())
    return 2;

  // Primary matches
  if (!strncmp(cmd.c_str(), "back", 4))
  {
    *out_flags = CliFlags::printBack;
    return 1;
  }
  if (!strncmp(cmd.c_str(), "ni", 2))
  {
    *out_flags = CliFlags::ni;
    return 1;
  }
  if (!strncmp(cmd.c_str(), "reg", 3))
  {
    *out_flags = CliFlags::regV;
    return 1;
  }
  if (!strncmp(cmd.c_str(), "flag", 4))
  {
    *out_flags = CliFlags::pFlags;
    return 1;
  }
  if (!strncmp(cmd.c_str(), "libc on", 7))
  {
    *out_flags = CliFlags::startGLIBCprints;
    return 1;
  }
  if (!strncmp(cmd.c_str(), "libc off", 8))
  {
    *out_flags = CliFlags::stopGLIBCprints;
    return 1;
  }
  if (!strncmp(cmd.c_str(), "clear", 5))
  {
    *out_flags = CliFlags::clear;
    return 1;
  }
  if (!strncmp(cmd.c_str(), "c", 1))
  {
    *out_flags = CliFlags::contin;
    return 1;
  }
  if (!strncmp(cmd.c_str(), "info", 4))
  {
    *out_flags = CliFlags::info;
    return 1;
  }
  if (!strncmp(cmd.c_str(), "lay", 3))
  {
    *out_flags = CliFlags::lay;
    return 1;
  }
  if (!strncmp(cmd.c_str(), "starti", 6))
  {
    *out_flags = CliFlags::starti;
    return 1;
  }
  if (!strncmp(cmd.c_str(), "q", 1))
  {
    UiLog("Exiting Scallop Shell....");
    exit(0);
  }

  if (!strncmp(cmd.c_str(), "x", 1))
  {
    parse_x_command(cmd);
    *out_flags = CliFlags::examine;
    return 1;
  }

  if (!strncmp(cmd.c_str(), "b", 1))
  {
    parse_b_command(cmd);
    *out_flags = CliFlags::breakpoint;
    return 1;
  }

  // Unrecognized command: ignore for now
  UiLog(std::string("Unknown command: ") + cmd);
  return 0;
}

void spinner()
{
  // optional: keep existing behavior (stdout), or convert to UiLog-based animation
}

void clearLine()
{
  // No-op under FTXUI to avoid cursor escape codes fighting with the UI.
}

void printMemMap(int index)
{
  if (!memMaps.at(index)->canRun())
    return;

  for (auto addr : memMaps.at(index)->addressSpaces)
  {
    if (addr.first <= regs.rip && addr.second >= regs.rip)
    {
      if (insn[0].address == addr.first)
      {
        UiLog("  #-------- " + memMaps.at(index)->desc + " --------#");
      }
      char buf[256];
      std::snprintf(buf, sizeof(buf),
                    "\t0x%" PRIx64 ":\t%s\t\t%s",
                    insn[0].address, insn[0].mnemonic, insn[0].op_str);
      UiLog(buf);

      if (insn[0].address == addr.second)
      {
        memMaps.at(index)->run++;
        UiLog("  #-------- end of " + memMaps.at(index)->desc + " --------#");
      }
    }
  }
}

void printBreak(int symbolI)
{
  if (symbolI != -1)
  {
    char buf[256];
    auto raw_addr_ptr = symbolTable.at(symbolI).getAddr();
    unsigned long long addr_val =
        static_cast<unsigned long long>(reinterpret_cast<uintptr_t>(raw_addr_ptr));
    std::snprintf(buf, sizeof(buf), "  0x%016llx:    %s     %s |\t<- %s",
                  addr_val,
                  insn[0].mnemonic, insn[0].op_str,
                  symbolTable.at(symbolI).getDesc().c_str());
    UiLog(std::string("[BRK] ") + buf);
    flags = CliFlags::ni;
    return;
  }
  if (hasInstrucBreak(insn[0].mnemonic) == 1)
  {
    char buf[256];
    std::snprintf(buf, sizeof(buf), "  0x%" PRIx64 ":    %s     %s",
                  (uint64_t)insn[0].address, insn[0].mnemonic, insn[0].op_str);
    UiLog(std::string("[BRK] ") + buf);
    flags = CliFlags::ni;
  }
}

void printSymbol(int symbolI)
{
  char buf[256];
  auto raw_addr_ptr = symbolTable.at(symbolI).getAddr();
  unsigned long long addr_val =
      static_cast<unsigned long long>(reinterpret_cast<uintptr_t>(raw_addr_ptr));
  std::snprintf(buf, sizeof(buf), "  0x%016llx:    %s     %s |\t<- %s",
                addr_val,
                insn[0].mnemonic, insn[0].op_str,
                symbolTable.at(symbolI).getDesc().c_str());
  UiLog(std::string("[SYM] ") + buf);
}

void printBasic()
{
  char buf[256];
  std::snprintf(buf, sizeof(buf), "0x%" PRIx64 ":    %s     %s",
                (uint64_t)insn[0].address, insn[0].mnemonic, insn[0].op_str);
  UiLog(buf);
}

void printEFlags(uint64_t eflags)
{
  std::string s = "SET FLAGS -";
  if (eflags & (1ULL << 0))
    s += " CF";
  if (eflags & (1ULL << 2))
    s += " PF";
  if (eflags & (1ULL << 4))
    s += " AF";
  if (eflags & (1ULL << 6))
    s += " ZF";
  if (eflags & (1ULL << 7))
    s += " SF";
  if (eflags & (1ULL << 8))
    s += " TF";
  if (eflags & (1ULL << 9))
    s += " IF";
  if (eflags & (1ULL << 10))
    s += " DF";
  if (eflags & (1ULL << 11))
    s += " OF";
  UiLog(s);
}

void printRegVerbose()
{
  char buf[256];
  UiLog("#----------------------------- REGISTERS -----------------------------#");
  std::snprintf(buf, sizeof(buf), "RAX=0x%016llx  RBX=0x%016llx  RCX=0x%016llx  RDX=0x%016llx", regs.rax, regs.rbx, regs.rcx, regs.rdx);
  UiLog(buf);
  std::snprintf(buf, sizeof(buf), "RDI=0x%016llx  RSI=0x%016llx  RBP=0x%016llx  RSP=0x%016llx", regs.rdi, regs.rsi, regs.rbp, regs.rsp);
  UiLog(buf);
  std::snprintf(buf, sizeof(buf), "RIP=0x%016llx   R8=0x%016llx   R9=0x%016llx   R10=0x%016llx", regs.rip, regs.r8, regs.r9, regs.r10);
  UiLog(buf);
  std::snprintf(buf, sizeof(buf), "R11=0x%016llx  R12=0x%016llx  R13=0x%016llx  R14=0x%016llx", regs.r11, regs.r12, regs.r13, regs.r14);
  UiLog(buf);
  std::snprintf(buf, sizeof(buf), "R15=0x%016llx  EFLAGS=0x%016llx", regs.r15, regs.eflags);
  UiLog(buf);
  printEFlags(regs.eflags);
  UiLog("#---------------------------------------------------------------------#");
}

void printInstructions()
{
  int symbolI = hasSymbol(insn[0].address);
  int mapI = hasLoopSymbol(insn[0].address);

  if (mapI != -1)
  {
    printMemMap(mapI);
    return;
  }

  if (symbolI != -1)
  {
    if (symbolTable.at(symbolI).getType() == 'b')
      printBreak(symbolI);
    else if (symbolTable.at(symbolI).getType() == 's')
      printSymbol(symbolI);
    return;
  }

  printBreak(symbolI);
  printBasic();
}

void handleBacktrace()
{
  if (!strncmp(insn[0].mnemonic, "ret", 3))
  {
    backtrace.pop();
  }
  if (!strncmp(insn[0].mnemonic, "call", 4))
  {
    backtrace.push(insn[0].address);
  }
}

bool moveOn() { return (flags == CliFlags::contin); }

int runFlags(int childPID)
{
  switch (flags)
  {
  case CliFlags::ni:
    if (!runCliThisTick)
    {
      Cli(&flags);
      if (moveOn() || flags == CliFlags::ni)
        return -1;
      return 0;
    }
    break;

  case CliFlags::contin:
    return -1;

  case CliFlags::printBack:
    backtrace.printStack();
    Cli(&flags);
    break;

  case CliFlags::breakpoint:
  {
    if (!g_break_addr.has_value())
    {
      UiLog("usage: b <hex_addr> <desc> [save]");
      Cli(&flags);
      break;
    }
    uint64_t addr = *g_break_addr;
    const char *desc = g_break_desc.empty() ? "bkpt" : g_break_desc.c_str();

    symbolTable.emplace_back(Symbol(addr, desc, 'b'));
    if (g_break_save)
    {
      if (FILE *f = fopen("info.txt", "a"))
      {
        fprintf(f, "0x%lx %s b\n", addr, desc);
        fclose(f);
      }
    }
    char buf[128];
    std::snprintf(buf, sizeof(buf), "breakpoint set at 0x%lx (%s)%s", addr, desc, g_break_save ? " [saved]" : "");
    UiLog(buf);
    Cli(&flags);
    break;
  }

  case CliFlags::starti:
    UiLog("starti not implemented");
    Cli(&flags);
    break;

  case CliFlags::clear:
    UiClear();
    Cli(&flags);
    break;

  case CliFlags::info:
    UiLog("Process ID = " + std::to_string(childPID));
    Cli(&flags);
    break;

  case CliFlags::regV:
    printRegVerbose();
    Cli(&flags);
    break;

  case CliFlags::pFlags:
    printEFlags(regs.eflags);
    Cli(&flags);
    break;

  case CliFlags::startGLIBCprints:
    printGLIBC = true;
    UiLog("GLIBC prints: ON");
    Cli(&flags);
    break;

  case CliFlags::stopGLIBCprints:
    printGLIBC = false;
    UiLog("GLIBC prints: OFF");
    Cli(&flags);
    break;

  case CliFlags::examine:
  {
    if (!g_examine_addr.has_value())
    {
      UiLog("usage: x/[N][g|w|h|b] <hex_addr>");
      Cli(&flags);
      break;
    }
    uint64_t address = *g_examine_addr;

    int unit = 8;
    switch (xFlags)
    {
    case ExamineFlags::g:
      unit = 8;
      break;
    case ExamineFlags::w:
      unit = 4;
      break;
    case ExamineFlags::h:
      unit = 2;
      break;
    case ExamineFlags::b:
      unit = 1;
      break;
    default:
      break;
    }
    int bytesToRead = unit * (bytesToExamine > 0 ? bytesToExamine : 1);
    int offset = 0;

    {
      char hdr[128];
      std::snprintf(hdr, sizeof(hdr), "Data at 0x%lx:", address);
      UiLog(hdr);
    }

    while (offset < bytesToRead)
    {
      errno = 0;
      long data = ptrace(PTRACE_PEEKDATA, childPID, (void *)(address + offset), 0);
      if (data == -1 && errno != 0)
      {
        UiLog("ptrace(PTRACE_PEEKDATA) failed");
        break;
      }

      char line[256];
      line[0] = 0;
      std::string s;
      int bytesThisWord = (int)sizeof(long);
      if (offset + bytesThisWord > bytesToRead)
        bytesThisWord = bytesToRead - offset;
      for (int j = 0; j < bytesThisWord; j++)
      {
        uint8_t byte = (data >> (8 * j)) & 0xFF;
        std::snprintf(line, sizeof(line), "%02x ", byte);
        s += line;
      }
      UiLog(s);
      offset += (int)sizeof(long);
    }

    Cli(&flags);
    break;
  }

  default:
    break;
  }

  return 0;
}
