#include "jump.hpp"
#include "loop.hpp"

#define PAGE_SIZE 4096
#define MMAP_DATA_PAGES 8
#define MMAP_TOTAL_PAGES (1 + MMAP_DATA_PAGES)

struct perf_event_mmap_page *meta;
int perfEv;
size_t data_buf_size;
uint8_t *LBR;

bool checkPerfEventParanoid()
{
    FILE *f = fopen("/proc/sys/kernel/perf_event_paranoid", "r");
    if (!f)
    {
        perror("Cannot open /proc/sys/kernel/perf_event_paranoid");
        return false;
    }

    int level;
    if (fscanf(f, "%d", &level) != 1)
    {
        fprintf(stderr, "Failed to parse perf_event_paranoid\n");
        fclose(f);
        return false;
    }
    fclose(f);

    if (level > 1)
    {
        printf("ERROR - kernel.perf_event_paranoid = %d\n", level);
        printf("THIS PREVENTS JUMP TABLE FUNCTIONALITY.\n");
        printf("To fix temporarily (until reboot), run:\n");
        printf("    sudo sysctl -w kernel.perf_event_paranoid=0\n\n");
        printf("To fix permanently, add this line to /etc/sysctl.conf or /etc/sysctl.d/*.conf:\n");
        printf("    kernel.perf_event_paranoid=0\n");
        printf("Then run: sudo sysctl --system\n\n");

        return false;
    }
}

int initializeLBRTracking()
{
    struct perf_event_attr pe;
    memset(&pe, 0, sizeof(pe));
    pe.size = sizeof(pe);

    pe.type = PERF_TYPE_HARDWARE;
    pe.config = PERF_COUNT_HW_BRANCH_INSTRUCTIONS;

    pe.sample_period = 1; // Trigger every branch
    pe.sample_type = PERF_SAMPLE_BRANCH_STACK;
    pe.branch_sample_type = PERF_SAMPLE_BRANCH_USER | PERF_SAMPLE_BRANCH_ANY;

    pe.exclude_kernel = 1;
    pe.exclude_hv = 1;
    pe.disabled = 0;

    perfEv = perf_event_open(&pe, 0, -1, -1, 0);
    if (perfEv < 0)
    {
        perror("perf_event_open");
        return 1;
    }

    size_t mmap_size = PAGE_SIZE * MMAP_TOTAL_PAGES;
    void *memMap = mmap(NULL, mmap_size, PROT_READ | PROT_WRITE, MAP_SHARED, perfEv, 0);
    if (memMap == MAP_FAILED)
    {
        perror("mmap");
        return 1;
    }

    printf("perf_event_open and mmap succeeded.\n");

    meta = (struct perf_event_mmap_page *)memMap;
    LBR = (uint8_t *)memMap + PAGE_SIZE;
    data_buf_size = PAGE_SIZE * MMAP_DATA_PAGES;

    printf("finished initializing.\n");

    return 0;
}

long perf_event_open(struct perf_event_attr *hw_event, pid_t pid,
                     int cpu, int group_fd, unsigned long flags)
{
    return syscall(__NR_perf_event_open, hw_event, pid, cpu,
                   group_fd, flags);
}

bool jumpOccurred(uint64_t *jmpAddrArg,
                  uint64_t *stayAddrArg,
                  pid_t child)
{

    static perf_branch_entry lastEntry = {0};

    // Load the head
    uint64_t head = __atomic_load_n(&meta->data_head, __ATOMIC_ACQUIRE);
    uint64_t tail = meta->data_tail;

    //printf("[DEBUG] perf tail=%lu head=%lu\n", tail, head);

    if (tail >= head)
        return false;

    size_t offset = tail % data_buf_size;
    struct perf_event_header *hdr = (struct perf_event_header *)(LBR + offset);

    if (hdr->type == PERF_RECORD_SAMPLE)
    {

        struct perf_branch_entry *branches = (struct perf_branch_entry *)(hdr + 1);

        for (int i = 0; i < 16; i++)
        {
            if (branches[i].from == 0 && branches[i].to == 0)
                break;
            //printf("[LBR %2d] From: 0x%llx → To: 0x%llx | Flags: 0x%llx\n", i,
            //       branches[i].from, branches[i].to);
        }

        if (branches[0].from == regs.rip)
        {
            *jmpAddrArg = branches[0].to;
            *stayAddrArg = branches[0].from;
            return true;
        }

        // If last entry wasn't initialized, set it = to the first page
        if (lastEntry.from == 0 && lastEntry.to == 0)
        {
            lastEntry.abort = branches[0].abort;
            lastEntry.cycles = branches[0].cycles;
            lastEntry.from = branches[0].from;
            lastEntry.in_tx = branches[0].in_tx;
            lastEntry.mispred = branches[0].mispred;
            lastEntry.predicted = branches[0].predicted;
            lastEntry.reserved = branches[0].reserved;
            lastEntry.to = branches[0].to;
            lastEntry.type = branches[0].type;
        }

        // If the entries are identical, return false
        if (lastEntry.from == branches[0].from && lastEntry.to == branches[0].to)
            return false;

        *jmpAddrArg = branches[0].to;
        *stayAddrArg = branches[0].from;

        // Debug LBR TOS
        //printf("LBR TOS (most recent branch):\n");
        //printf("    From: 0x%llx → To: 0x%llx\n", branches[0].from, branches[0].to);
        //printf("----\n");

        lastEntry = branches[0];
    }

    // Check if any of the jump addresses match
    LinkedList *curJmp = jumpTable.get();
    while (curJmp != NULL)
    {
        if (*jmpAddrArg == curJmp->jmpAddr)
        {
            curJmp->next = NULL;
        }
        curJmp = curJmp->next.get();
    }

    tail += hdr->size;

    meta->data_tail = tail;
    __atomic_store_n(&meta->data_tail, tail, __ATOMIC_RELEASE);
    return true;
}

bool handleJumps(int cnt)
{

    uint64_t jmpAddr = 0xdeadbeef;
    uint64_t stayAddr = 0xdeadbeef;

    static bool initialized = false;

    if (!initialized)
    {
        checkPerfEventParanoid();
        initializeLBRTracking();
    }
    initialized = true;

    bool jumped = jumpOccurred(&jmpAddr, &stayAddr, child);

    // If theres a jump instruction
    if (jumped)
    {

        std::shared_ptr<LinkedList> lastNode = jumpTable;
        int length = 0;

        bool duplicateFound = false;

        while (lastNode != NULL && lastNode->next != NULL)
        {
            if (lastNode->jmpAddr == jmpAddr)
            {
                lastNode->next = NULL;
                duplicateFound = true;
                break;
            }
            else if (lastNode->stayAddr == stayAddr)
            {
                lastNode->next = NULL;
                duplicateFound = true;
                break;
            }
            // printf(" 0x%lx -> ", lastNode->jmpAddr);
            length++;
            lastNode = lastNode->next;
        }

        if (!duplicateFound)
        {
            std::shared_ptr<LinkedList> newNode = std::make_shared<LinkedList>(nullptr, jmpAddr, stayAddr);
            // printf("new addr = %lx", jmpAddr);
            if (jumpTable == NULL)
            {
                jumpTable = newNode;
            }
            else
            {
                lastNode->next = newNode;
            }

            jumpTable->printList();
        }

        // printf("\n\n");

        // printInstructions();
        // handleBacktrace();
    }
}