/*
 * Compatibility defines for BPF atomic opcodes (kernel March 2025).
 * Force-included so they are defined before host kernel headers (e.g. from
 * -v /usr/src:/usr/src) that reference BPF_LOAD_ACQ/BPF_STORE_REL but may
 * not define them (e.g. AWS Graviton kernel 6.17.0-1007-aws).
 */
#ifndef BPF_LOAD_ACQ
#define BPF_LOAD_ACQ  0x100
#endif
#ifndef BPF_STORE_REL
#define BPF_STORE_REL 0x110
#endif
