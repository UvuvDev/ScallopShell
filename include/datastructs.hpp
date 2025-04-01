#pragma once

#include <iostream>
#include <vector>

class AddressStack {
    public:
        // Push a memory address onto the stack.
        uint64_t push(uint64_t address) {
            stack.push_back(address);
            return 1;
        }
    
        // Remove and return the top memory address from the stack.
        uint64_t pop() {
            if (empty()) {
                return 0;
            }
            uint64_t topAddress = stack.back();
            stack.pop_back();
            return topAddress;
        }
    
        // Return the top memory address without removing it.
        uint64_t top() const {
            if (empty()) {
                throw std::runtime_error("Stack is empty");
            }
            return stack.back();
        }
    
        // Check if the stack is empty.
        bool empty() const {
            return stack.empty();
        }
    
        // Return the number of addresses on the stack.
        size_t size() const {
            return stack.size();
        }

        void printStack() {

            std::cout << BOLD_YELLOW << "###------BACKTRACE------###" << RESET << "\n";
            for (int i = 0; i < stack.size(); i++) {
                std::cout << BOLD_YELLOW << "   #" << i << ":\t\t" << (uint64_t*)stack.at(i) << "\n" << RESET;
            }
        }
    
    private:
        std::vector<uint64_t> stack;
    };