#include "memorydisplay.hpp"
#include "emulatorAPI.hpp"
#include <ftxui/component/component.hpp>
#include <utility>

using namespace ftxui;



uint64_t getRegisterValue(const std::string& registerArg) {
    std::vector<std::string>* regs = Emulator::getRegisters(false);
    if (!regs || regs->empty()) {
        regs = Emulator::getRegisters(true);
        if (!regs)
            return 0;
    }

    const std::string prefix = registerArg + "=";
    for (const std::string& line : *regs) {
        if (line.rfind(prefix, 0) != 0)
            continue;
        const char* valStr = line.c_str() + prefix.size();
        return strtoull(valStr, nullptr, 16);
    }

    return 0; // not found
}



namespace ScallopUI
{

    struct HexEditHistory {
        int row;
        int col;
        uint8_t data;

        HexEditHistory(int row_, int col_, uint8_t data_) {
            row = row_;
            col = col_;
            data = data_;
        }

    };

    /*===================================================*/
    /*=                                                 =*/
    /*=                                                 =*/
    /*=                                                 =*/
    /*=                                                 =*/
    /*=                                                 =*/
    /*=                                                 =*/    
    /*=                                                 =*/    
    /*===================================================*/

    Component MemoryDisplay(std::vector<uint8_t>* data, std::string followedReg, size_t size,
                            uint64_t base_addr, int bytesPerRow, int visibleRows)
    {
        class Impl : public ComponentBase
        {
        private:

        /**
         * Commit the nibble, so basically this is what is supposed to set the data equal to what it needs to be.
         * NOTE FOR LATER - Data seems to be being edited where this is called as well, check this out.
         */
        void commit_nibble(int v) {
            if (selectedRow < 0 || selectedColumn < 0) return;
            
            const size_t idx = (size_t)selectedRow * bpr_ + selectedColumn;
            if (idx >= size_) return;

            // Always snapshot before we mutate
            hexEditHistory.emplace_back(selectedRow, selectedColumn, data_->at(idx));

            editTrail.emplace_back(selectedRow, selectedColumn);

            if (pending_nibble_ < 0) {
                // --- First nibble (high) ---
                uint8_t old = data_->at(idx);
                data_->at(idx) = (uint8_t)((v << 4) | (old & 0x0F));
                pending_nibble_ = v; // waiting for low nibble
            } else {
                // --- Second nibble (low) ---
                data_->at(idx) = (uint8_t)((pending_nibble_ << 4) | v);
                pending_nibble_ = -1;

                // advance selection to next cell
                if (++selectedColumn >= bpr_) {
                    selectedColumn = 0;
                    ++selectedRow;
                }
                // if we walked off the end, exit edit mode
                if ((size_t)selectedRow * bpr_ + selectedColumn >= size_) {
                    editing_ = false;
                }
            }
        }


        bool handleMouseTakeover(ftxui::Mouse m) {

               // Local (x,y) inside the rendered element:
                int lx = m.x - mouseBox.x_min - leftmostX;
                int ly = m.y - mouseBox.y_min - highestY;
                // Map local coords to your data model:
                int cell_w = 3; // Each byte is 2 characters + a space
                int cell_h = 1; // one line per row

                int col = lx / cell_w;
                int row = (ly / cell_h) + top_row_;

                selectedRow = row;
                selectedColumn = col;
                    
                editing_ = true;

                return true; 

        }
        public:
            Impl(std::vector<uint8_t>* data, std::string followedReg, size_t size,
                 uint64_t base_addr, int bpr, int rows)
                : data_(data),
                  size_(size ? size
                             : static_cast<size_t>(rows) * static_cast<size_t>(bpr)),
                  base_addr_(base_addr),
                  bpr_(bpr),
                  rows_(rows),
                  followedReg_(std::move(followedReg)),
                  cache_key_(followedReg_.empty() ? "default" : followedReg_),
                  need_refresh_(true) {
                  }

        private:
            std::vector<uint8_t >* data_;
            size_t size_;
            uint64_t base_addr_;
            int bpr_;
            int rows_;
            int top_row_ = 0;
            ftxui::Box mouseBox; // Box where mouse can be
            int selectedRow = -1; // Where the mouse is selecting - row
            int selectedColumn = -1; // Where the mouse is selecting - column
            int leftmostX = 0x15; // Offset that accounts for the displayed memory addresses pixels
            int highestY = 2; // Offset that accounts for window border
            bool editing_ = false;           // Is editing? false = no
            int pending_nibble_ = -1;        // -1 = none, otherwise 0..15
            bool pushed_snapshot_ = false; 
            std::vector<HexEditHistory> hexEditHistory;
            std::vector<std::pair<int,int>> editTrail;  // Highlights for edited bits
            std::string followedReg_;
            std::string cache_key_;
            bool need_refresh_ = true;

            bool Focusable() const override { return true; }

            /*====================================*/
            /*====================================*/

            // All event handling
            bool OnEvent(Event e) override
            {
                const int max_rows = static_cast<int>((size_ + bpr_ - 1) / bpr_);
                const int max_top = std::max(0, max_rows - rows_);
                
                // Editing keystrokes
                if (editing_) {
                    // ESC cancels current nibble (but keeps any committed change)
                    if (e == Event::Return) {
                        pending_nibble_ = -1;
                        editing_ = false;
                        pushed_snapshot_ = false;
                        editTrail.clear();
                        return true;
                    }
                    // Backspace "un-types" the high nibble edit (restores original if needed)
                    if (e == Event::Backspace) {
                        if (!hexEditHistory.empty()) {
                            HexEditHistory lastEdit = hexEditHistory.back();

                            data_->at(lastEdit.row*bpr_ + lastEdit.col) = lastEdit.data;
                            selectedRow = lastEdit.row;
                            selectedColumn = lastEdit.col;
                            hexEditHistory.pop_back();
                            
                        }
                        if (!editTrail.empty()) {
                            editTrail.pop_back();
                        }
                        return true;
                    }

                    // Hex characters
                    if (e.is_character()) {
                    char c = e.character()[0];
                    int v = hexval(c);
                    if (v >= 0) {
                        commit_nibble(v);
                        return true;
                    }
                    }
                    // Ignore other keys while editing
                    const auto& m = e.mouse();     
                    if (m.button == ftxui::Mouse::Left && m.motion == ftxui::Mouse::Pressed) {   
                        return handleMouseTakeover(m);
                    }
                    return false;
                }
                if (e == Event::Character('r') || e == Event::Character('R'))
                {
                    need_refresh_ = true;
                    return true;
                }
                if (e == Event::ArrowUp)
                {
                    top_row_ = std::max(0, top_row_ - 1);
                    return true;
                }
                if (e == Event::ArrowDown)
                {
                    top_row_ = std::min(max_top, top_row_ + 1);
                    return true;
                }
                if (e == Event::PageUp)
                {
                    top_row_ = std::max(0, top_row_ - rows_);
                    return true;
                }
                if (e == Event::PageDown)
                {
                    top_row_ = std::min(max_top, top_row_ + rows_);
                    return true;
                }
                if (e == Event::Home)
                {
                    top_row_ = 0;
                    return true;
                }
                if (e == Event::End)
                {
                    top_row_ = max_top;
                    return true;
                }
                if (e == Event::Backspace) {
                    if (!hexEditHistory.empty()) {
                        HexEditHistory lastEdit = hexEditHistory.back();

                        data_->at(lastEdit.row*bpr_ + lastEdit.col) = lastEdit.data;
                        selectedRow = lastEdit.row;
                        selectedColumn = lastEdit.col;
                        hexEditHistory.pop_back();
                    }
                    return true;
                }

                // If event is not a mouse, just return false
                if (!e.is_mouse()) return false;
                

                const auto& m = e.mouse();
                if (m.button == ftxui::Mouse::Left && m.motion == ftxui::Mouse::Pressed)              
                    return handleMouseTakeover(m);

                return false;
            }

            /*====================================*/
            /*====================================*/

            Element OnRender() override
            {

                if (!followedReg_.empty())
                {
                    uint64_t regValue = getRegisterValue(followedReg_);
                    if (regValue != base_addr_)
                    {
                        base_addr_ = regValue;
                        top_row_ = 0;
                        need_refresh_ = true;
                    }
                }

                bool request_update = need_refresh_ || data_ == nullptr || data_->empty();
                data_ = Emulator::getMemory(base_addr_, size_, request_update, -1, cache_key_);
                if (request_update)
                {
                    need_refresh_ = false;
                }

                std::vector<Element> lines;
                lines.reserve(rows_ + 2);

                auto header = hbox({text(" Address             "), text("Bytes") | bold}) | underlined | dim;
                lines.push_back(header);

                const int max_rows = static_cast<int>((size_ + bpr_ - 1) / bpr_);
                const int end_row = std::min(top_row_ + rows_, max_rows);

                for (int r = top_row_; r < end_row && data_ != nullptr && !data_->empty(); ++r)
                {

                    //printf("%p RELEASE MEEEEE\n", data_);
                    
                    size_t start = static_cast<size_t>(r) * bpr_;

                    // Write the address for currently selected address space
                    auto addr_el = text(hex8ByteStr(base_addr_ + start)) | color(Color::CornflowerBlue);

                    std::vector<Element> byte_els;
                    byte_els.reserve(bpr_ * 2 - 1);
                    for (int i = 0; i < bpr_; ++i)
                    {
                        size_t idx = start + i;
                        if (idx < size_)
                        {
                            // Show the data bytes
                            uint8_t b = data_->at(idx);
                            Element e = text(hex1ByteStr(b)) | color(Color::Magenta); // This is the actual text being displayed
                            
                            // Dim NULL bytes for readability
                            if (b == 0x00)
                                e = e | dim;

                            // Handle highlighting
                            bool isHighlighted = std::find(editTrail.begin(), editTrail.end(),
                               std::make_pair(r,i)) != editTrail.end();
                            if (isHighlighted) {
                                e = e | bgcolor(Color::Black) | bold;
                            }

                            byte_els.push_back(e); // Add the byte to the list of things to display
                        }
                        else
                        {
                            byte_els.push_back(text("  ") | dim);
                        }
                        if (i + 1 != bpr_)
                            byte_els.push_back(text(" "));

                        // Meant to add spaces in betweeen the bytes. May come back to later
                        //if ((i+1) % 8 == 0) byte_els.push_back(text(" | "));
                    }

                    // Add the lines to the box that will be displayed.
                    lines.push_back(hbox({addr_el, text(": "), hbox(std::move(byte_els))}));
                }

                // Final display - add border and focus
                auto display =  vbox(std::move(lines)) | border | focus;

                if (Focused())
                    return display | color(Color::Magenta) | reflect(mouseBox);

                return display | reflect(mouseBox);


            }
        };

        // IMPORTANT: pass the args to Impl here
        return Make<Impl>(data, std::move(followedReg), size, base_addr, bytesPerRow, visibleRows);
    }

}
