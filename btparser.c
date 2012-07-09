#include "lib/core-backtrace.h"
#include "lib/utils.h"

int main(int argc, char *argv[])
{
    btp_debug_parser = 1;
    //print_mapping_data("coredump-t", "maps-t");
    print_mapping_data("coredump", "maps");
    return 0;
}
