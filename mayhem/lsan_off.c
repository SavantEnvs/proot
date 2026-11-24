/* Leaks are not the bug class fuzzed here: disable LeakSanitizer at build time (ASan stays on). */
int __lsan_is_turned_off(void) { return 1; }
