#include "memorydisplay.hpp"
#include <ftxui/component/component.hpp>

using namespace ftxui;

namespace ScallopUI
{

    /*===================================================*/
    /*=                                                 =*/
    /*=                                                 =*/
    /*=                                                 =*/
    /*=                                                 =*/
    /*=                                                 =*/
    /*=                                                 =*/    
    /*=                                                 =*/    
    /*===================================================*/


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

    Component MemoryDisplay(uint8_t *data, size_t size,
                            uint64_t base_addr, int bytesPerRow, int visibleRows)
    {
        class Impl : public ComponentBase
        {
        private:

        void begin_edit_if_needed() {
            if (selectedRow < 0 || selectedColumn < 0) return;
            editing_ = true;
            pending_nibble_ = -1;
            pushed_snapshot_ = false;
        }

        void commit_nibble(int v) {
            if (selectedRow < 0 || selectedColumn < 0) return;
            
            const size_t idx = (size_t)selectedRow * bpr_ + selectedColumn;
            if (idx >= size_) return;

            // Always snapshot before we mutate
            hexEditHistory.emplace_back(selectedRow, selectedColumn, data_[idx]);

            editTrail.emplace_back(selectedRow, selectedColumn);

            if (pending_nibble_ < 0) {
                // --- First nibble (high) ---
                uint8_t old = data_[idx];
                data_[idx] = (uint8_t)((v << 4) | (old & 0x0F));
                pending_nibble_ = v; // waiting for low nibble
            } else {
                // --- Second nibble (low) ---
                data_[idx] = (uint8_t)((pending_nibble_ << 4) | v);
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


        public:
            Impl(uint8_t *data, size_t size,
                 uint64_t base_addr, int bpr, int rows)
                : data_(data), size_(size),
                  base_addr_(base_addr), bpr_(bpr), rows_(rows) {
                    //hex_edit = HexEdit(&hexEditorOpen);
                    //Add(hex_edit);
                  }

        private:
            uint8_t *data_;
            size_t size_;
            uint64_t base_addr_;
            int bpr_;
            int rows_;
            int top_row_ = 0;
            ftxui::Box mouseBox;
            int selectedRow = -1;
            int selectedColumn = -1;
            int leftmostX = 0x15;
            int highestY = 2;
            bool editing_ = false;           // replaces hexEditorOpen
            int pending_nibble_ = -1;        // -1 = none, otherwise 0..15
            bool pushed_snapshot_ = false; 
            std::vector<HexEditHistory> hexEditHistory;
            std::vector<std::pair<int,int>> editTrail;  // Highlights for edited bits


            bool Focusable() const override { return true; }

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

                            data_[lastEdit.row*bpr_ + lastEdit.col] = lastEdit.data;
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
                    return false;
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

                        data_[lastEdit.row*bpr_ + lastEdit.col] = lastEdit.data;
                        selectedRow = lastEdit.row;
                        selectedColumn = lastEdit.col;
                        hexEditHistory.pop_back();
                    }
                    return true;
                }

                // If event is not a mouse, just return false
                if (!e.is_mouse()) return false;
                

                const auto& m = e.mouse();
                if (m.button != ftxui::Mouse::Left || m.motion != ftxui::Mouse::Pressed)
                    return false;
                
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

                    // Zeros byte at selected box
                    /*if (row >= 0 && row < rows_ && col >= 0 && col < bpr_) {
                        
                        hexEditHistory.emplace_back(HexEditHistory{row, col, data_[row*bpr_ + col]});

                        data_[row*bpr_ + col] = 0;
                    }*/ 
                    TakeFocus();
                    return true; 

                return false;
            }

            Element OnRender() override
            {
                std::vector<Element> lines;
                lines.reserve(rows_ + 2);

                auto header = hbox({text(" Address             "), text("Bytes") | bold}) | underlined | dim;
                lines.push_back(header);

                const int max_rows = static_cast<int>((size_ + bpr_ - 1) / bpr_);
                const int end_row = std::min(top_row_ + rows_, max_rows);

                for (int r = top_row_; r < end_row; ++r)
                {
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
                            uint8_t b = data_[idx];
                            Element e = text(hex1ByteStr(b)) | color(Color::Magenta); // This is the actual text being displayed
                            
                            // Dim NULL bytes
                            if (b == 0x00)
                                e = e | dim;

                            // Handle highlighting
                            bool isHighlighted = std::find(editTrail.begin(), editTrail.end(),
                               std::make_pair(r,i)) != editTrail.end();
                            if (isHighlighted) {
                                e = e | bgcolor(Color::Black) | bold;
                            }

                            byte_els.push_back(e);
                        }
                        else
                        {
                            byte_els.push_back(text("  ") | dim);
                        }
                        if (i + 1 != bpr_)
                            byte_els.push_back(text(" "));

                        //if ((i+1) % 8 == 0) byte_els.push_back(text(" | "));
                    }

                    lines.push_back(hbox({addr_el, text(": "), hbox(std::move(byte_els))}));
                }

                auto display =  vbox(std::move(lines)) | border | focus;
                return display | reflect(mouseBox);
            }
        };

        // IMPORTANT: pass the args to Impl here
        return Make<Impl>(data, size, base_addr, bytesPerRow, visibleRows);
    }

}