/* Bounded diagnostics for the fixed C API smoke fixture, not SDK code.
 * No URLs, arguments, environment values, images or memory dumps are recorded.
 */
#ifndef CEF_STATIC_SMOKE_PROGRESS_V1_H_
#define CEF_STATIC_SMOKE_PROGRESS_V1_H_

enum smoke_stage {
  SMOKE_START = 1, SMOKE_EXECUTE = 2, SMOKE_EXECUTE_RETURN = 3,
  SMOKE_INITIALIZED = 4, SMOKE_CONTEXT = 5, SMOKE_CREATE = 6,
  SMOKE_AFTER_CREATED = 7, SMOKE_RENDERER_CONTEXT = 8,
  SMOKE_PROOF_SENT = 9, SMOKE_PROOF_RECEIVED = 10,
  SMOKE_TITLE = 11, SMOKE_PAINT = 12, SMOKE_LOAD_ERROR = 13,
  SMOKE_AUDIT_REJECTED = 14, SMOKE_FINAL_AUDIT = 15,
  SMOKE_BEFORE_CLOSE = 16, SMOKE_LOOP = 17, SMOKE_LOOP_RETURN = 18,
  SMOKE_SHUTDOWN = 19, SMOKE_SHUTDOWN_RETURN = 20
};
static int smoke_role, smoke_initialized, smoke_context, smoke_created;
static int smoke_create_accepted, smoke_renderer_context, smoke_proof_sent;
static int smoke_proof_received, smoke_title_calls, smoke_paint_calls;
static int smoke_width, smoke_height, smoke_pixel[4], smoke_load_code;
static int smoke_browser_modules = -1, smoke_browser_third_party = -1;
static unsigned smoke_sequence;

static void smoke_set_role(int argc, char** argv) {
  static const char* roles[] = {"renderer", "gpu-process", "utility", "zygote"};
  smoke_role = 0;
  for (int i = 1; i < argc; ++i) {
    const char* type = NULL;
    if (strncmp(argv[i], "--type=", 7) == 0) type = argv[i] + 7;
    else if (strcmp(argv[i], "--type") == 0 && i + 1 < argc) type = argv[++i];
    if (!type) continue;
    smoke_role = 5;
    for (int j = 0; j < 4; ++j) {
      if (strcmp(type, roles[j]) == 0) smoke_role = j + 1;
    }
  }
}

static int smoke_path(char* path, size_t length, const char* kind,
                      const char* suffix) {
  const char* directory = getenv("CEF_STATIC_SMOKE_PROGRESS_DIR");
  if (!directory || directory[0] != '/') return 0;
  int n = snprintf(path, length, "%s/smoke-%s-%d.%s", directory,
                   kind, process_id(), suffix);
  return n > 0 && (size_t)n < length;
}

static void smoke_trace(int stage) {
  char path[8192], temporary[8192];
  if (smoke_sequence >= 512 || !smoke_path(path, sizeof(path), "progress", "json") ||
      !smoke_path(temporary, sizeof(temporary), "progress", "json.new")) return;
  ++smoke_sequence;
  FILE* f = fopen(temporary, "w");
  if (!f) return; /* Diagnostics cannot manufacture a successful proof. */
  int n = fprintf(f,
    "{\"schema\":1,\"pid\":%d,\"role\":%d,\"stage\":%d,\"sequence\":%u,"
    "\"initialized\":%d,\"context\":%d,\"created\":%d,\"create_accepted\":%d,"
    "\"renderer_context\":%d,\"proof_sent\":%d,\"proof_received\":%d,"
    "\"title_calls\":%d,\"javascript\":%d,\"paint_calls\":%d,\"paint\":%d,"
    "\"width\":%d,\"height\":%d,\"pixel_b\":%d,\"pixel_g\":%d,"
    "\"pixel_r\":%d,\"pixel_a\":%d,\"load_code\":%d,\"renderer_pid\":%d,"
    "\"renderer_modules\":%d,\"renderer_third_party\":%d,"
    "\"browser_modules\":%d,\"browser_third_party\":%d,\"closing\":%d,\"passed\":%d}\n",
    process_id(), smoke_role, stage, smoke_sequence,
    smoke_initialized, smoke_context, smoke_created, smoke_create_accepted,
    smoke_renderer_context, smoke_proof_sent, smoke_proof_received,
    smoke_title_calls, javascript_ok, smoke_paint_calls, paint_ok,
    smoke_width, smoke_height, smoke_pixel[0], smoke_pixel[1], smoke_pixel[2], smoke_pixel[3],
    smoke_load_code, renderer_pid, renderer_modules_ok, renderer_third_party_modules_ok,
    smoke_browser_modules, smoke_browser_third_party, closing, passed);
  int code = fclose(f);
  if (n > 0 && code == 0) (void)rename(temporary, path);
  else (void)remove(temporary);
}

static void smoke_modules(void) {
#if defined(__linux__)
  char path[8192], temporary[8192], line[8192];
  if (!smoke_path(path, sizeof(path), "modules", "txt") ||
      !smoke_path(temporary, sizeof(temporary), "modules", "txt.new")) return;
  FILE* maps = fopen("/proc/self/maps", "r");
  if (!maps) return;
  FILE* output = fopen(temporary, "w");
  if (!output) { fclose(maps); return; }
  unsigned count = 0;
  while (count < 512 && fgets(line, sizeof(line), maps)) {
    char* name = strrchr(line, '/');
    if (!name || !strstr(++name, ".so")) continue;
    size_t length = strcspn(name, "\r\n");
    if (!length || length > 192) continue;
    int safe = 1;
    for (size_t i = 0; i < length; ++i) {
      char c = name[i];
      if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
            (c >= '0' && c <= '9') || c == '.' || c == '_' || c == '-' || c == '+')) safe = 0;
    }
    if (safe) { name[length] = 0; fprintf(output, "%s\n", name); }
    else fputs("NONCANONICAL_MODULE_NAME\n", output);
    ++count;
  }
  fclose(maps);
  int ok = !ferror(output);
  int code = fclose(output);
  if (ok && code == 0) (void)rename(temporary, path);
  else (void)remove(temporary);
#endif
}
#endif
