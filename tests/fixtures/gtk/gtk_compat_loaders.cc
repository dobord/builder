// Copyright 2021 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.
// Loader excerpt from chromium 79460ebecaa5625e57a5fb679a735659e73dc687,
// ui/gtk/gtk_compat.cc, with builder's CEF_STATIC_DIRECT_GTK3_V1 edits.
// This fixture is not a CEF runtime verification.

// CEF_STATIC_DIRECT_GTK3_V1
#if !defined(CEF_STATIC_GTK3)
#include "ui/gtk/gtk_stubs.h"
#endif

void* DlOpen(const char* library_name, bool check = true) {
#if defined(CEF_STATIC_GTK3)
  (void)library_name;
  (void)check;
  CHECK(false) << "Static GTK3 profile forbids loading a system GTK module";
  return nullptr;
#else
  void* library = dlopen(library_name, RTLD_LAZY | RTLD_GLOBAL);
  CHECK(!check || library);
  return library;
#endif
}

template <typename T>
struct DlSymWrapper {
  // An exclusion is necessary because not using a raw_ptr results in an error:
  // "Use raw_ptr<T> instead of a raw pointer.", but using raw_ptr results in a
  // different error: "raw_ptr<T> doesn't work with this kind of pointee type
  // T".
  RAW_PTR_EXCLUSION T* fn = nullptr;

  template <typename... Args>
  DISABLE_CFI_DLSYM auto operator()(Args&&... args) {
    CHECK(fn);
    return fn(std::forward<Args>(args)...);
  }
};

template <typename T>
auto DlSym(void* library, const char* name) {
  void* symbol = dlsym(library, name);
  return DlSymWrapper<T>{reinterpret_cast<T*>(symbol)};
}

void* GetLibGio() {
  static void* libgio = DlOpen("libgio-2.0.so.0");
  return libgio;
}

void* GetLibGdkPixbuf() {
  static void* libgdk_pixbuf = DlOpen("libgdk_pixbuf-2.0.so.0");
  return libgdk_pixbuf;
}

void* GetLibGdk3() {
  static void* libgdk3 = DlOpen("libgdk-3.so.0");
  return libgdk3;
}

void* GetLibGtk3(bool check = true) {
  static void* libgtk3 = DlOpen("libgtk-3.so.0", check);
  return libgtk3;
}

void* GetLibGtk4(bool check = true) {
  static void* libgtk4 = DlOpen("libgtk-4.so.1", check);
  return libgtk4;
}

void* GetLibGtk() {
#if defined(CEF_STATIC_GTK3)
  return RTLD_DEFAULT;
#else
  if (GtkCheckVersion(4)) {
    return GetLibGtk4();
  }
  return GetLibGtk3();
#endif
}

bool LoadGtk3() {
  if (!GetLibGtk3(false)) {
    return false;
  }
  ui_gtk::InitializeGdk_pixbuf(GetLibGdkPixbuf());
  ui_gtk::InitializeGdk(GetLibGdk3());
  ui_gtk::InitializeGtk(GetLibGtk3());
  return true;
}

bool LoadGtk4() {
  if (!GetLibGtk4(false)) {
    return false;
  }
  // In GTK4 mode, we require some newer gio symbols that aren't available
  // in Ubuntu Xenial or Debian Stretch.  Fortunately, GTK4 itself depends
  // on a newer version of glib (which provides gio), so if we're using
  // GTK4, we can safely assume the system has the required gio symbols.
  ui_gtk::InitializeGio(GetLibGio());
  // In GTK4, libgtk provides all gdk_*, gsk_*, and gtk_* symbols.
  ui_gtk::InitializeGdk(GetLibGtk4());
  ui_gtk::InitializeGsk(GetLibGtk4());
  ui_gtk::InitializeGtk(GetLibGtk4());
  return true;
}

bool LoadGtkImpl(ui::LinuxUiBackend backend) {
  // If GTK3 or GTK4 is somehow already loaded, then the preloaded library must
  // be used, because GTK3 and GTK4 have conflicting symbols and cannot be
  // loaded simultaneously.
  if (dlopen("libgtk-3.so.0", RTLD_LAZY | RTLD_GLOBAL | RTLD_NOLOAD)) {
    return LoadGtk3();
  }
  if (dlopen("libgtk-4.so.1", RTLD_LAZY | RTLD_GLOBAL | RTLD_NOLOAD)) {
    return LoadGtk4();
  }

  auto* cmd = base::CommandLine::ForCurrentProcess();
  unsigned int gtk_version;
  if (!base::StringToUint(cmd->GetSwitchValueASCII(switches::kGtkVersionFlag),
                          &gtk_version)) {
    gtk_version = 0;
  }
  auto env = base::Environment::Create();
  const auto desktop = base::nix::GetDesktopEnvironment(env.get());
  if (!gtk_version && desktop == base::nix::DESKTOP_ENVIRONMENT_GNOME) {
    // GNOME is currently the only desktop to support GTK4 starting with version
    // 42+. Try to match the loaded GTK version with the GNOME GTK version.
    // Checking the GNOME version is not necessary since GTK4 is available iff
    // GNOME is version 42+. This is the case for Debian, Ubuntu, and the
    // RPM-based distributions that are supported.
    gtk_version = 4;
  }
  // Default to GTK4 on GNOME except on X11 where GTK IMEs are still immature.
  // This may be enabled unconditionally when support for Ubuntu 22.04 ends,
  // since IME issues have been addressed in later releases. Allow the command
  // line switch to override this.
  return gtk_version == 4 && (cmd->HasSwitch(switches::kGtkVersionFlag) ||
                              backend == ui::LinuxUiBackend::kWayland)
             ? LoadGtk4() || LoadGtk3()
             : LoadGtk3() || LoadGtk4();
}

gfx::Insets InsetsFromGtkBorder(const GtkBorder& border) {
  return gfx::Insets::TLBR(border.top, border.left, border.bottom,
                           border.right);
}

bool LoadGtk(ui::LinuxUiBackend backend) {
#if defined(CEF_STATIC_GTK3)
  (void)backend;
  return true;
#else
  static bool loaded = LoadGtkImpl(backend);
  return loaded;
#endif
}
