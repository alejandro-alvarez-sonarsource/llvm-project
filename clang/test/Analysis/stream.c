// RUN: %clang_analyze_cc1 -analyzer-checker=core,unix,alpha.unix.Stream,debug.ExprInspection -verify %s

#include "Inputs/system-header-simulator.h"
#include "Inputs/system-header-simulator-for-malloc.h"
#include "Inputs/system-header-simulator-for-valist.h"

void clang_analyzer_eval(int);
void clang_analyzer_dump_char(char);
void clang_analyzer_dump_int(int);
extern void clang_analyzer_dump_ptr(void*);
extern void clang_analyzer_warnIfReached();

void check_fread(void) {
  FILE *fp = tmpfile();
  fread(0, 0, 0, fp); // expected-warning {{Stream pointer might be NULL}}
  fclose(fp);
}

void check_fwrite(void) {
  FILE *fp = tmpfile();
  fwrite(0, 0, 0, fp); // expected-warning {{Stream pointer might be NULL}}
  fclose(fp);
}

void check_fgetc(void) {
  FILE *fp = tmpfile();
  fgetc(fp); // expected-warning {{Stream pointer might be NULL}}
  fclose(fp);
}

void check_fgets(void) {
  FILE *fp = tmpfile();
  char buf[256];
  fgets(buf, sizeof(buf), fp); // expected-warning {{Stream pointer might be NULL}}
  fclose(fp);
}

void check_fputc(void) {
  FILE *fp = tmpfile();
  fputc('A', fp); // expected-warning {{Stream pointer might be NULL}}
  fclose(fp);
}

void check_fputs(void) {
  FILE *fp = tmpfile();
  fputs("ABC", fp); // expected-warning {{Stream pointer might be NULL}}
  fclose(fp);
}

void check_fprintf(void) {
  FILE *fp = tmpfile();
  fprintf(fp, "ABC"); // expected-warning {{Stream pointer might be NULL}}
  fclose(fp);
}

void check_fscanf(void) {
  FILE *fp = tmpfile();
  fscanf(fp, "ABC"); // expected-warning {{Stream pointer might be NULL}}
  fclose(fp);
}

void check_ungetc(void) {
  FILE *fp = tmpfile();
  ungetc('A', fp); // expected-warning {{Stream pointer might be NULL}}
  fclose(fp);
}

void check_fseek(void) {
  FILE *fp = tmpfile();
  fseek(fp, 0, 0); // expected-warning {{Stream pointer might be NULL}}
  fclose(fp);
}

void check_fseeko(void) {
  FILE *fp = tmpfile();
  fseeko(fp, 0, 0); // expected-warning {{Stream pointer might be NULL}}
  fclose(fp);
}

void check_ftell(void) {
  FILE *fp = tmpfile();
  ftell(fp); // expected-warning {{Stream pointer might be NULL}}
  fclose(fp);
}

void check_ftello(void) {
  FILE *fp = tmpfile();
  ftello(fp); // expected-warning {{Stream pointer might be NULL}}
  fclose(fp);
}

void check_rewind(void) {
  FILE *fp = tmpfile();
  rewind(fp); // expected-warning {{Stream pointer might be NULL}}
  fclose(fp);
}

void check_fgetpos(void) {
  FILE *fp = tmpfile();
  fpos_t pos;
  fgetpos(fp, &pos); // expected-warning {{Stream pointer might be NULL}}
  fclose(fp);
}

void check_fsetpos(void) {
  FILE *fp = tmpfile();
  fpos_t pos;
  fsetpos(fp, &pos); // expected-warning {{Stream pointer might be NULL}}
  fclose(fp);
}

void check_clearerr(void) {
  FILE *fp = tmpfile();
  clearerr(fp); // expected-warning {{Stream pointer might be NULL}}
  fclose(fp);
}

void check_feof(void) {
  FILE *fp = tmpfile();
  feof(fp); // expected-warning {{Stream pointer might be NULL}}
  fclose(fp);
}

void check_ferror(void) {
  FILE *fp = tmpfile();
  ferror(fp); // expected-warning {{Stream pointer might be NULL}}
  fclose(fp);
}

void check_fileno(void) {
  FILE *fp = tmpfile();
  fileno(fp); // expected-warning {{Stream pointer might be NULL}}
  fclose(fp);
}

void f_open(void) {
  FILE *p = fopen("foo", "r");
  char buf[1024];
  fread(buf, 1, 1, p); // expected-warning {{Stream pointer might be NULL}}
  fclose(p);
}

void f_dopen(int fd) {
  FILE *F = fdopen(fd, "r");
  char buf[1024];
  fread(buf, 1, 1, F); // expected-warning {{Stream pointer might be NULL}}
  fclose(F);
}

void f_seek(void) {
  FILE *p = fopen("foo", "r");
  if (!p)
    return;
  fseek(p, 1, SEEK_SET); // no-warning
  fseek(p, 1, 3); // expected-warning {{The whence argument to fseek() should be SEEK_SET, SEEK_END, or SEEK_CUR}}
  fclose(p);
}

void f_seeko(void) {
  FILE *p = fopen("foo", "r");
  if (!p)
    return;
  fseeko(p, 1, SEEK_SET); // no-warning
  fseeko(p, 1, 3); // expected-warning {{The whence argument to fseek() should be SEEK_SET, SEEK_END, or SEEK_CUR}}
  fclose(p);
}

void f_double_close(void) {
  FILE *p = fopen("foo", "r");
  if (!p)
    return;
  fclose(p);
  fclose(p); // expected-warning {{Stream might be already closed}}
}

void f_double_close_alias(void) {
  FILE *p1 = fopen("foo", "r");
  if (!p1)
    return;
  FILE *p2 = p1;
  fclose(p1);
  fclose(p2); // expected-warning {{Stream might be already closed}}
}

void f_use_after_close(void) {
  FILE *p = fopen("foo", "r");
  if (!p)
    return;
  fclose(p);
  clearerr(p); // expected-warning {{Stream might be already closed}}
}

void f_open_after_close(void) {
  FILE *p = fopen("foo", "r");
  if (!p)
    return;
  fclose(p);
  p = fopen("foo", "r");
  if (!p)
    return;
  fclose(p);
}

void f_reopen_after_close(void) {
  FILE *p = fopen("foo", "r");
  if (!p)
    return;
  fclose(p);
  // Allow reopen after close.
  p = freopen("foo", "w", p);
  if (!p)
    return;
  fclose(p);
}

void f_leak(int c) {
  FILE *p = fopen("foo.c", "r");
  if (!p)
    return;
  if(c)
    return; // expected-warning {{Opened stream never closed. Potential resource leak}}
  fclose(p);
}

FILE *f_null_checked(void) {
  FILE *p = fopen("foo.c", "r");
  if (p)
    return p; // no-warning
  else
    return 0;
}

void pr7831(FILE *fp) {
  fclose(fp); // no-warning
}

// PR 8081 - null pointer crash when 'whence' is not an integer constant
void pr8081(FILE *stream, long offset, int whence) {
  fseek(stream, offset, whence);
}

void check_freopen_1(void) {
  FILE *f1 = freopen("foo.c", "r", (FILE *)0); // expected-warning {{Stream pointer might be NULL}}
  f1 = freopen(0, "w", (FILE *)0x123456);      // Do not report this as error.
}

void check_freopen_2(void) {
  FILE *f1 = fopen("foo.c", "r");
  if (f1) {
    FILE *f2 = freopen(0, "w", f1);
    if (f2) {
      // Check if f1 and f2 point to the same stream.
      fclose(f1);
      fclose(f2); // expected-warning {{Stream might be already closed.}}
    } else {
      // Reopen failed.
      // f1 is non-NULL but points to a possibly invalid stream.
      rewind(f1); // expected-warning {{Stream might be invalid}}
      // f2 is NULL but the previous error stops the checker.
      rewind(f2);
    }
  }
}

void check_freopen_3(void) {
  FILE *f1 = fopen("foo.c", "r");
  if (f1) {
    // Unchecked result of freopen.
    // The f1 may be invalid after this call.
    freopen(0, "w", f1);
    rewind(f1); // expected-warning {{Stream might be invalid}}
    fclose(f1);
  }
}

extern FILE *GlobalF;
extern void takeFile(FILE *);

void check_escape1(void) {
  FILE *F = tmpfile();
  if (!F)
    return;
  fwrite("1", 1, 1, F); // may fail
  GlobalF = F;
  fwrite("1", 1, 1, F); // no warning
}

void check_escape2(void) {
  FILE *F = tmpfile();
  if (!F)
    return;
  fwrite("1", 1, 1, F); // may fail
  takeFile(F);
  fwrite("1", 1, 1, F); // no warning
}

void check_escape3(void) {
  FILE *F = tmpfile();
  if (!F)
    return;
  takeFile(F);
  F = freopen(0, "w", F);
  if (!F)
    return;
  fwrite("1", 1, 1, F); // may fail
  fwrite("1", 1, 1, F); // no warning
}

void check_escape4(void) {
  FILE *F = tmpfile();
  if (!F)
    return;
  fwrite("1", 1, 1, F); // may fail

  // no escape at a non-StreamChecker-handled system call
  setbuf(F, "0");

  fwrite("1", 1, 1, F); // expected-warning {{might be 'indeterminate'}}
  fclose(F);
}

int Test;
_Noreturn void handle_error(void);

void check_leak_noreturn_1(void) {
  FILE *F1 = tmpfile();
  if (!F1)
    return;
  if (Test == 1) {
    handle_error(); // no warning
  }
  rewind(F1);
} // expected-warning {{Opened stream never closed. Potential resource leak}}

// Check that "location uniqueing" works.
// This results in reporting only one occurence of resource leak for a stream.
void check_leak_noreturn_2(void) {
  FILE *F1 = tmpfile();
  if (!F1)
    return;
  if (Test == 1) {
    return; // no warning
  }
  rewind(F1);
} // expected-warning {{Opened stream never closed. Potential resource leak}}
// FIXME: This warning should be placed at the `return` above.
// See https://reviews.llvm.org/D83120 about details.

void fflush_after_fclose(void) {
  FILE *F = tmpfile();
  int Ret;
  fflush(NULL);                      // no-warning
  if (!F)
    return;
  if ((Ret = fflush(F)) != 0)
    clang_analyzer_eval(Ret == EOF); // expected-warning {{TRUE}}
  fclose(F);
  fflush(F);                         // expected-warning {{Stream might be already closed}}
}

void fflush_on_open_failed_stream(void) {
  FILE *F = tmpfile();
  if (!F) {
    fflush(F); // no-warning
    return;
  }
  fclose(F);
}

void test_fscanf_eof() {
  FILE *F1 = tmpfile();
  if (!F1)
    return;

  int a;
  unsigned b;
  int ret = fscanf(F1, "%d %u", &a, &b);
  char c = fgetc(F1); // expected-warning {{Read function called when stream is in EOF state. Function has no effect}}
  // expected-warning@-1 {{File position of the stream might be 'indeterminate' after a failed operation. Can cause undefined behavior}}
  fclose(F1);
}

void test_fscanf_escape() {
  FILE *F1 = tmpfile();
  if (!F1)
    return;

  int a = 48;
  unsigned b = 127;
  char buffer[] = "FSCANF"; // 70 83 67 65 78 70

  clang_analyzer_dump_int(a); // expected-warning {{48 S32b}}
  clang_analyzer_dump_int(b); // expected-warning {{127 S32b}}
  clang_analyzer_dump_char(buffer[2]); // expected-warning {{67 S8b}}

  int ret = fscanf(F1, "%d %u %s", &a, &b, buffer);
  clang_analyzer_dump_int(a); // expected-warning {{conj_$}}
  clang_analyzer_dump_int(b); // expected-warning {{conj_$}}
  clang_analyzer_dump_char(buffer[2]); // expected-warning {{derived_$}}

  if (ret != EOF) {
    char c = fgetc(F1); // ok
  }

  fclose(F1);
}

void test_fputc() {
  FILE *F1 = tmpfile();
  if (!F1)
    return;

  char a = 'y'; // 'y' = 121 ASCII
  char r = fputc(a, F1);
  if (r != EOF) {
    clang_analyzer_dump_char(r); // expected-warning {{121 S8b}}
    char z = fgetc(F1);
  } else {
    clang_analyzer_dump_char(r);  // expected-warning {{-1 S8b}}
  }

  fclose(F1);
}

void test_fputs() {
  FILE *F1 = tmpfile();
  if (!F1)
    return;

  char buffer[] = "HELLO";
  int r = fputs(buffer, F1);
  if (r >= 0) {
    // fputs does not invalidate the input buffer (72 is ascii for 'H')
    clang_analyzer_dump_char(buffer[0]); // expected-warning {{72 S8b}}
  } else if (r == EOF) {
    // fputs does not invalidate the input buffer, *and* this branch
    // can happen
    clang_analyzer_dump_char(buffer[0]); // expected-warning {{72 S8b}}
  } else {
    // This branch can not happen
    int *p = NULL;
    *p = 0;
  }

  fclose(F1);
}

void test_fprintf() {
  FILE *F1 = tmpfile();
  if (!F1)
    return;

  unsigned a = 42;
  char *output = "HELLO";
  int r = fprintf(F1, "%s\t%u\n", output, a);
  // fprintf does not invalidate any of its input
  // 69 is ascii for 'E'
  clang_analyzer_dump_int(a); // expected-warning {{42 S32b}}
  clang_analyzer_dump_char(output[1]); // expected-warning {{69 S8b}}
  if (r < 0) {
    // Failure
    fprintf(F1, "%s\t%u\n", output, a); // expected-warning {{File position of the stream might be 'indeterminate' after a failed operation. Can cause undefined behavior}}
  } else {
    char buffer[10];
    fscanf(F1, "%s", buffer);
    if (fseek(F1, 0, SEEK_SET) == 0) {
      fprintf(F1, "%s\t%u\n", buffer, a); // ok
    }
  }

  fclose(F1);
}

void test_getline_null_file() {
  char *buffer = NULL;
  size_t n = 0;
  getline(&buffer, &n, NULL); // expected-warning {{Stream pointer might be NULL}}
}

void test_getline_null_lineptr() {
  FILE *F1 = tmpfile();
  if (!F1)
    return;

  char **buffer = NULL;
  size_t n = 0;
  getline(buffer, &n, F1); // expected-warning {{Line pointer might be NULL}}
  fclose(F1);
}

void test_getline_null_size() {
  FILE *F1 = tmpfile();
  if (!F1)
    return;
  char *buffer = NULL;
  getline(&buffer, NULL, F1); // expected-warning {{Size pointer might be NULL}}
  fclose(F1);
}

void test_getline_null_buffer_bad_size() {
  FILE *F1 = tmpfile();
  if (!F1)
    return;
  char *buffer = NULL;
  size_t n = 8;
  getline(&buffer, &n, F1); // expected-warning {{Line pointer might be null while n value is not zero}}
  fclose(F1);
}

void test_getline_null_buffer_bad_size_2(size_t n) {
  FILE *F1 = tmpfile();
  if (!F1)
    return;
  char *buffer = NULL;
  if (n > 0) {
    getline(&buffer, &n, F1);  // expected-warning {{Line pointer might be null while n value is not zero}}
  }
  fclose(F1);
}

void test_getline_null_buffer_unknown_size(size_t n) {
  FILE *F1 = tmpfile();
  if (!F1)
    return;
  char *buffer = NULL;


  getline(&buffer, &n, F1);  // ok
  fclose(F1);
  free(buffer);
}

void test_getline_null_buffer() {
  FILE *F1 = tmpfile();
  if (!F1)
    return;
  char *buffer = NULL;
  size_t n = 0;
  ssize_t r = getline(&buffer, &n, F1);
  // getline returns -1 on failure, number of char reads on success (>= 0)
  if (r < -1) {
    clang_analyzer_warnIfReached(); // must not happen
  } else {
    // The buffer could be allocated both on failure and success
    clang_analyzer_dump_int(n);      // expected-warning {{conj_$}}
    clang_analyzer_dump_ptr(buffer); // expected-warning {{conj_$}}
  }
  free(buffer);
  fclose(F1);
}

void test_getline_malloc_buffer() {
  FILE *F1 = tmpfile();
  if (!F1)
    return;
  size_t n = 10;
  char *buffer = malloc(n);
  buffer[0] = 'a'; // 'a' = 97 ASCII

  clang_analyzer_dump_char(buffer[0]); // expected-warning {{97 S8b}}
  ssize_t r = getdelim(&buffer, &n, '\r', F1);
  clang_analyzer_dump_int(r); // expected-warning {{-1 S32b}} \
                                 expected-warning {{conj_$}}
  if (r == -1) {
    char x = buffer[0]; // expected-warning {{Assigned value is garbage or undefined}}
  } else {
    clang_analyzer_dump_int(n);      // expected-warning {{conj_$}}
    clang_analyzer_dump_char(buffer[0]); // expected-warning {{conj_$}}
  }

  fclose(F1); // expected-warning {{Potential memory leak}}
}

void test_getline_alloca() {
  FILE *F1 = tmpfile();
  if (!F1)
    return;
  size_t n = 10;
  char *buffer = alloca(n);

  getline(&buffer, &n, F1); // expected-warning {{Memory allocated by alloca() should not be deallocated}}
  fclose(F1);
}

void test_getline_ptr() {
  FILE *F1 = tmpfile();
  if (!F1)
    return;
  size_t n = 10;
  char *buffer = (char*)test_getline_ptr;

  getline(&buffer, &n, F1); // expected-warning {{Argument to getline() is the address of the function 'test_getline_ptr', which is not memory allocated by malloc()}}
  fclose(F1);
}

void test_getdelim_null_file() {
  char *buffer = NULL;
  size_t n = 0;
  getdelim(&buffer, &n, '\n', NULL); // expected-warning {{Stream pointer might be NULL}}
}

void test_getdelim_null_size() {
  FILE *F1 = tmpfile();
  if (!F1)
    return;
  char *buffer = NULL;
  getdelim(&buffer, NULL, ',', F1); // expected-warning {{Size pointer might be NULL}}
  fclose(F1);
}

void test_getdelim_null_buffer_bad_size() {
  FILE *F1 = tmpfile();
  if (!F1)
    return;
  char *buffer = NULL;
  size_t n = 8;
  getdelim(&buffer, &n, ';', F1); // expected-warning {{Line pointer might be null while n value is not zero}}
  fclose(F1);
}

void test_getdelim_null_buffer_bad_size_2(size_t n) {
  FILE *F1 = tmpfile();
  if (!F1)
    return;
  char *buffer = NULL;
  if (n > 0) {
    getdelim(&buffer, &n, ' ', F1);  // expected-warning {{Line pointer might be null while n value is not zero}}
  }
  fclose(F1);
}

void test_getdelim_null_buffer_unknown_size(size_t n) {
  FILE *F1 = tmpfile();
  if (!F1)
    return;
  char *buffer = NULL;
  getdelim(&buffer, &n, '-', F1);  // ok
  fclose(F1);
  free(buffer);
}

void test_getdelim_null_buffer() {
  FILE *F1 = tmpfile();
  if (!F1)
    return;
  char *buffer = NULL;
  size_t n = 0;
  ssize_t r = getdelim(&buffer, &n, '\r', F1);
  // getdelim returns -1 on failure, number of char reads on success (>= 0)
  if (r < -1) {
    clang_analyzer_warnIfReached(); // must not happen
  }
  else {
    // The buffer could be allocated both on failure and success
    clang_analyzer_dump_int(n);      // expected-warning {{conj_$}}
    clang_analyzer_dump_ptr(buffer); // expected-warning {{conj_$}}
  }
  free(buffer);
  fclose(F1);
}

void test_getdelim_malloc_buffer() {
  FILE *F1 = tmpfile();
  if (!F1)
    return;
  size_t n = 10;
  char *buffer = malloc(n);
  buffer[0] = 'a'; // 'a' = 97 ASCII

  clang_analyzer_dump_char(buffer[0]); // expected-warning {{97 S8b}}

  ssize_t r = getdelim(&buffer, &n, '\r', F1);
  clang_analyzer_dump_int(r); // expected-warning {{-1 S32b}} \
                                 expected-warning {{conj_$}}
  if (r == -1) {
    char x = buffer[0]; // expected-warning {{Assigned value is garbage or undefined}}
  } else {
    clang_analyzer_dump_int(n);      // expected-warning {{conj_$}}
    clang_analyzer_dump_char(buffer[0]); // expected-warning {{conj_$}}
  }

  fclose(F1); // expected-warning {{Potential memory leak}}
}

void test_getdelim_alloca() {
  FILE *F1 = tmpfile();
  if (!F1)
    return;
  size_t n = 10;
  char *buffer = alloca(n);

  getdelim(&buffer, &n, '&', F1); // expected-warning {{Memory allocated by alloca() should not be deallocated}}
  fclose(F1);
}

void test_getdelim_ptr() {
  FILE *F1 = tmpfile();
  if (!F1)
    return;
  size_t n = 10;
  char *buffer = (char*)test_getdelim_ptr;

  getdelim(&buffer, &n, '/', F1); // expected-warning {{Argument to getdelim() is the address of the function 'test_getdelim_ptr', which is not memory allocated by malloc()}}
  fclose(F1);
}

void test_getline_while() {
  FILE *file = fopen("file.txt", "r");
  if (file == NULL) {
    return;
  }

  char *line = NULL;
  size_t len = 0;
  ssize_t read;

  while ((read = getline(&line, &len, file)) != -1) {
    printf("%s\n", line);
  }

  free(line);
  fclose(file);
}

void test_getline_leak() {
  FILE *file = fopen("file.txt", "r");
  if (file == NULL) {
    return;
  }

  char *line = NULL;
  size_t len = 0;
  ssize_t read;

  while ((read = getline(&line, &len, file)) != -1) {
    printf("%s\n", line);
  }

  fclose(file); // expected-warning {{Potential memory leak}}
}

void test_getline_no_return_check() {
  FILE *file = fopen("file.txt", "r");
  if (file == NULL) {
    return;
  }

  char *line = NULL;
  size_t len = 0;
  getline(&line, &len, file);

  if (line[0] == '\0') {} // expected-warning {{The left operand of '==' is a garbage value}}

  free(line);
  fclose(file);
}

void test_getline_return_check() {
  FILE *file = fopen("file.txt", "r");
  if (file == NULL) {
    return;
  }

  char *line = NULL;
  size_t len = 0;
  ssize_t r = getline(&line, &len, file);

  if (r != -1) {
    if (line[0] == '\0') {} // ok
  }
  free(line);
  fclose(file);
}

void test_getline_feof_check() {
  FILE *file = fopen("file.txt", "r");
  if (file == NULL) {
    return;
  }

  char *line = NULL;
  size_t len = 0;
  ssize_t r = getline(&line, &len, file);

  if (r != -1) {
    // success, end-of-file is not possible
    int f = feof(file);
    clang_analyzer_dump_int(f); // expected-warning {{0 S32b}}
  } else {
    // failure, end-of-file is possible, but not the only reason to fail
    int f = feof(file);
    clang_analyzer_dump_int(f); // expected-warning {{conj_$}} \\
                                   expected-warning {{0 S32b}}
  }
  free(line);
  fclose(file);
}

void test_getline_after_eof() {
  FILE *file = fopen("file.txt", "r");
  if (file == NULL) {
    return;
  }

  size_t n = 10;
  char *buffer = malloc(n);
  ssize_t read = fread(buffer, n, 1, file);
  if (!feof(file)) {
    getline(&buffer, &n, file); // expected-warning {{File position of the stream might be 'indeterminate' after a failed operation. Can cause undefined behavior}}
  }
  fclose(file);
  free(buffer);
}

void test_getline_feof() {
  FILE *file = fopen("file.txt", "r");
  if (file == NULL) {
    return;
  }

  size_t n = 10;
  char *buffer = malloc(n);
  ssize_t read = fread(buffer, n, 1, file);
  getline(&buffer, &n, file); // expected-warning {{File position of the stream might be 'indeterminate' after a failed operation. Can cause undefined behavior}} \\
                                 expected-warning {{Read function called when stream is in EOF state. Function has no effect}}
  fclose(file);
  free(buffer);
}

void test_getline_clear_eof() {
  FILE *file = fopen("file.txt", "r");
  if (file == NULL) {
    return;
  }

  size_t n = 10;
  char *buffer = malloc(n);
  ssize_t read = fread(buffer, n, 1, file);
  if (feof(file)) {
    clearerr(file);
    getline(&buffer, &n, file); // ok
  }
  fclose(file);
  free(buffer);
}

void test_getline_not_null(char **buffer, size_t *size) {
  FILE *file = fopen("file.txt", "r");
  if (file == NULL) {
    return;
  }

  getline(buffer, size, file);
  fclose(file);

  if (size == NULL || buffer == NULL) {
    clang_analyzer_warnIfReached(); // must not happen
  }
}

void test_getline_size_0(size_t size) {
  FILE *file = fopen("file.txt", "r");
  if (file == NULL) {
    return;
  }

  size_t old_size = size;
  char *buffer = NULL;
  ssize_t r = getline(&buffer, &size, file);
  if (r >= 0) {
    // Since buffer is NULL, old_size should be 0. Otherwise, there would be UB.
    clang_analyzer_eval(old_size == 0); // expected-warning{{TRUE}}
  }
  fclose(file);
  free(buffer);
}
