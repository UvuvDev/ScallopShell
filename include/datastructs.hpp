#pragma once

#include <iostream>
#include <vector>

class AddressStack
{
public:
    // Push a memory address onto the stack.
    uint64_t push(uint64_t address)
    {
        stack.push_back(address);
        return 1;
    }

    // Remove and return the top memory address from the stack.
    uint64_t pop()
    {
        if (empty())
        {
            return 0;
        }
        uint64_t topAddress = stack.back();
        stack.pop_back();
        return topAddress;
    }

    // Return the top memory address without removing it.
    uint64_t top() const
    {
        if (empty())
        {
            return 0;
        }
        return stack.back();
    }

    // Check if the stack is empty.
    bool empty() const
    {
        return stack.empty();
    }

    // Return the number of addresses on the stack.
    size_t size() const
    {
        return stack.size();
    }

    void printStack()
    {

        std::cout << BOLD_YELLOW << "###------BACKTRACE------###" << RESET << "\n";
        for (int i = 0; i < stack.size(); i++)
        {
            std::cout << BOLD_YELLOW << "   #" << i << ":\t\t" << (uint64_t *)stack.at(i) << "\n"
                      << RESET;
        }
    }

private:
    std::vector<uint64_t> stack;
};

class LinkedList
{
public:

    std::shared_ptr<LinkedList> next;
    uint64_t jmpAddr;
    uint64_t stayAddr;

    LinkedList(std::shared_ptr<LinkedList> next, uint64_t jmpAddr, uint64_t stayAddr) {
        this->next = next;
        this->jmpAddr = jmpAddr;
        this->stayAddr = stayAddr;
    }

    void printList() {

        std::cout << YELLOW << "\t#---------- JUMP TABLE ---------#" << "\n";
        recursivePrint(this);
        std::cout << YELLOW << "\t#-------------------------------#" << "\n" << RESET;
        
    }

private:

    void recursivePrint(LinkedList* nextNode) {
        if (nextNode == NULL) return;
        if (nextNode->next != NULL)
            recursivePrint(nextNode->next.get());
        std::cout << YELLOW << "\t# " << (uint64_t*)nextNode->jmpAddr << " " << (uint64_t*)nextNode->stayAddr << " #" << "\n";
    }
    
};
