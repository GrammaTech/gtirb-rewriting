// gcc constraints.c -o constraints && ddisasm constraints --ir constraints.gtirb -j1

#include <stdio.h>

int leaf_function() {
    return 'A';
}

int nonleaf_function() {
    return leaf_function() + 1;
}

int main() {
    int leaf_ret = leaf_function();
    printf("leaf_function: %i\n", leaf_ret);

    int nonleaf_ret = nonleaf_function();
    printf("nonleaf_function: %i\n", leaf_ret);
}
