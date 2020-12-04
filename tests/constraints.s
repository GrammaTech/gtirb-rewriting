# gcc constraints.s -o constraints && ddisasm constraints --ir constraints.gtirb

        .text

        .globl  leaf_function
        .type   leaf_function,@function
leaf_function:
        pushq   %rbp
        movq    %rsp, %rbp
        movl    $65, %eax
        popq    %rbp
        retq

        .globl  nonleaf_function
        .type   nonleaf_function,@function
nonleaf_function:
        pushq   %rbp
        movq    %rsp, %rbp
        callq   leaf_function
        addl    $1, %eax
        popq    %rbp
        retq

        .globl  main
        .type   main,@function
main:
        pushq   %rbp
        movq    %rsp, %rbp
        callq   leaf_function
        movl    %eax, %esi
        movabsq $.L.str, %rdi
        callq   printf
        callq   nonleaf_function
        movl    %eax, %esi
        movabsq $.L.str.1, %rdi
        callq   printf
        xorl    %eax, %eax
        popq    %rbp
        retq

        .type   .L.str,@object
        .section        .rodata.str1.1,"aMS",@progbits,1
.L.str:
        .asciz  "leaf_function: %i\n"

        .type   .L.str.1,@object
.L.str.1:
        .asciz  "nonleaf_function: %i\n"
