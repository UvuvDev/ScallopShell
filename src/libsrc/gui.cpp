#include "gui.hpp"

int Cli(CliFlags* flags)
{

    char cmd[20];
    printf(" > ");
    scanf("%s", cmd);

    if (!strncmp(cmd, "back", 4))
    {
        *flags = CliFlags::printBack;
        return 1;
    }
    if (!strncmp(cmd, "ni", 2))
    {
        *flags = CliFlags::ni;
        return 1;
    }
    if (!strncmp(cmd, "b", 1))
    {
        *flags = CliFlags::breakpoint;
        return 1;
    }
    if (!strncmp(cmd, "c", 1))
    {
        *flags = CliFlags::contin;
        return 1;
    }
    if (!strncmp(cmd, "lay", 3))
    {
        *flags = CliFlags::lay;
        return 1;
    }
    if (!strncmp(cmd, "q", 1))
    {
        printf("Exiting Scallop Shell....\n");
        exit(1);
    }
    
    
    return 0;
}

void spinner()
{

    static int x = 0;

    static constexpr int delay = 10000;

    switch (x % (4*delay))
    {
    case 0:
        printf("\b|");
        fflush(stdout);
        break;
    case 1*delay:
        printf("\b/");
        fflush(stdout);
        break;
    case 2*delay:
        printf("\b-");
        fflush(stdout);
        break;
    case 3*delay:
        printf("\b\\");
        fflush(stdout);
        break;
    default:
        break;
    }
    x++;
}