"""Verbatim public PDFium copy methods under strict CTAD warning policy."""
from __future__ import annotations
import hashlib
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest import mock

from secure_release import cef_windows_source_repair as repair
from tests.cef_windows_pdfium_inputs import SPAN, PDFIUM
from tests.test_cef_windows_watermark_string_repair import populate_v21


def methods(raw):
    prefixes = (
        b'  constexpr void copy_from(span<const element_type, extent> other)\n',
        b'  constexpr void copy_from_nonoverlapping(\n      span<const element_type, extent> other)\n',
        b'  constexpr void copy_from(span<const element_type> other)\n',
        b'  constexpr void copy_from_nonoverlapping(span<const element_type> other)\n',
    )
    result = []
    for prefix in prefixes:
        if raw.count(prefix) != 1:
            raise ValueError('Unexpected exact PDFium span method boundary')
        start = raw.index(prefix)
        end = raw.index(b'\n  }\n', start) + len(b'\n  }\n')
        result.append(raw[start:end].decode())
    return result


def native_probe(raw):
    fixed_copy, fixed_nonoverlap, dynamic_copy, dynamic_nonoverlap = methods(raw)
    prefix = r'''
#include <algorithm>
#include <array>
#include <cstdlib>
#include <functional>
#include <span>
#include <type_traits>
#include <vector>
#define CHECK(x) ((x) ? (void)0 : std::abort())
#define DCHECK(x) CHECK(x)
namespace pdfium_probe {
inline constexpr size_t dynamic_extent=std::dynamic_extent;
template<class T,size_t E=dynamic_extent> class span {
  T* data_;
 public:
  using element_type=T;
  static constexpr size_t extent=E;
  constexpr span(T* data,size_t n) : data_(data) { CHECK(n==E); }
  constexpr T* begin() const { return data_; }
  constexpr T* end() const { return data_+E; }
  constexpr size_t size() const { return E; }
'''
    prefix += fixed_copy + fixed_nonoverlap + '};\n'
    prefix += r'''
template<class T> class span<T,dynamic_extent> {
  T* data_;
  size_t size_;
 public:
  using element_type=T;
  constexpr span(T* data,size_t n) : data_(data),size_(n) {}
  constexpr T* begin() const { return data_; }
  constexpr T* end() const { return data_+size_; }
  constexpr size_t size() const { return size_; }
'''
    prefix += dynamic_copy + dynamic_nonoverlap + '};\n}\n'
    return prefix + r'''
using pdfium_probe::span;
using pdfium_probe::dynamic_extent;
template<size_t E> constexpr bool constexpr_overlap() {
  std::array<int,6> values{1,2,3,4,5,6};
  span<int,E>(values.data()+1,4).copy_from(span<const int,E>(values.data(),4));
  return values==std::array<int,6>{1,1,2,3,4,6};
}
static_assert(constexpr_overlap<4>());
static_assert(constexpr_overlap<dynamic_extent>());
template<size_t E> void exercise() {
  int left[]{1,2,3,4,5,6};
  span<int,E>(left,4).copy_from(span<const int,E>(left+1,4));
  CHECK(left[0]==2 && left[1]==3 && left[2]==4 && left[3]==5);
  int right[]{1,2,3,4,5,6};
  span<int,E>(right+1,4).copy_from(span<const int,E>(right,4));
  CHECK(right[0]==1 && right[1]==1 && right[2]==2 && right[3]==3 && right[4]==4);
  int source[]{7,8,9,10}, target[]{0,0,0,0};
  span<int,E>(target,4).copy_from_nonoverlapping(span<const int,E>(source,4));
  CHECK(std::equal(source,source+4,target));
  span<int,E>(target,4).copy_from(span<const int,E>(target,4));
  CHECK(std::equal(source,source+4,target));
}
int main(int argc,char** argv) {
  if(argc>1) {
    int values[]{1,2,3,4,5,6};
    if(argv[1][0]=='o') span<int,4>(values,4).copy_from_nonoverlapping(span<const int,4>(values+1,4));
    else span<int>(values,2).copy_from(span<const int>(values+2,4));
    return 7; // Guards must terminate before this return.
  }
  exercise<4>();exercise<dynamic_extent>();
}
'''


class PdfiumSpanRepairTests(unittest.TestCase):
    def test_exact_dependency_pin_and_only_six_comparator_argument_lists_change(self):
        fixed = repair.transform(SPAN, repair.PDFIUM_SPAN_HEADER)
        self.assertEqual(repair.PDFIUM, PDFIUM)
        self.assertEqual(repair.profile()['pdfium_commit'], PDFIUM)
        self.assertEqual(hashlib.sha256(fixed).hexdigest(), repair.PDFIUM_SPAN_AFTER)
        self.assertEqual(fixed.replace(b'std::less_equal<>{}', b'std::less_equal{}')
                              .replace(b'std::greater_equal<>{}', b'std::greater_equal{}'), SPAN)
        self.assertEqual(SPAN.count(b'std::less_equal{}'), 4)
        self.assertEqual(SPAN.count(b'std::greater_equal{}'), 2)
        self.assertEqual(tuple(x.encode() for x in methods(SPAN)), repair.PDFIUM_SPAN_METHODS)
        self.assertEqual(repair.source_limit(repair.PDFIUM_SPAN_HEADER), 131072)
        self.assertEqual(repair.source_limit('unreviewed/span.h'), 65536)

    def test_native_strict_warning_overlap_constexpr_and_safety_guards(self):
        from tests.test_cef_windows_frame_tree_iterator_repair import FrameTreeRepairTests
        helper = FrameTreeRepairTests()
        fixed = repair.transform(SPAN, repair.PDFIUM_SPAN_HEADER)
        with tempfile.TemporaryDirectory(prefix='pdfium-span-v23-') as folder:
            root = Path(folder).resolve()
            failed_original = None
            for label, raw in (('original', SPAN), ('fixed', fixed)):
                source = root / (label + '.cc')
                exe = root / (label + ('.exe' if os.name == 'nt' else ''))
                source.write_text(native_probe(raw), encoding='utf-8')
                command = helper.command(source, exe)
                if os.name == 'nt':
                    env = dict(os.environ, CL='/clang:-Wctad-maybe-unsupported')
                else:
                    command.insert(1, '-Wctad-maybe-unsupported'); env = None
                result = subprocess.run(command, cwd=root, env=env,
                    capture_output=True, text=True, errors='replace', timeout=90)
                if label == 'original':
                    failed_original = result.returncode != 0
                    if os.name == 'nt':
                        self.assertNotIn(result.returncode, (0, 90))
                    if failed_original:
                        self.assertIn('ctad-maybe-unsupported', result.stdout + result.stderr)
                    else:
                        subprocess.run([str(exe)], check=True, capture_output=True, timeout=20)
                else:
                    self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                    subprocess.run([str(exe)], check=True, capture_output=True, timeout=20)
                    for mode in ('overlap', 'size-mismatch'):
                        guard = subprocess.run([str(exe), mode], capture_output=True, timeout=20)
                        self.assertNotIn(guard.returncode, (0, 7))
        print('CEF_PDFIUM_SPAN_V23_NATIVE original_failed=' + str(failed_original).lower()
              + ' windows_ctad_failed=' + str(os.name == 'nt').lower()
              + ' fixed_runs=true strict_ctad=true fixed_extent=true dynamic_extent=true overlap_both_directions=true'
                ' constexpr=true nonoverlap=true guards=true public_blob=true edits=6'
                ' pdfium_commit=' + PDFIUM + ' after_sha256=' + repair.PDFIUM_SPAN_AFTER)

    def test_newlines_idempotence_and_partial_inputs_rejected(self):
        for newline in (b'\n', b'\r\n'):
            fixed = repair.transform(SPAN.replace(b'\n', newline), repair.PDFIUM_SPAN_HEADER)
            self.assertEqual(repair.transform(fixed, repair.PDFIUM_SPAN_HEADER), fixed)
        for invalid in (b'', SPAN + b'\n', SPAN.replace(b'\n', b'\r\n', 1),
                        SPAN.replace(b'std::less_equal{}', b'std::less_equal<>{}', 1)):
            with self.assertRaises(ValueError): repair.transform(invalid, repair.PDFIUM_SPAN_HEADER)

    def test_invalid_pdfium_source_is_checked_before_watermark_write(self):
        with tempfile.TemporaryDirectory(prefix='pdfium-transition-v23-') as folder:
            work = Path(folder).resolve() / 'work'
            populate_v21(work)
            marker = work / repair.MARKER
            previous = marker.read_bytes()
            (work / repair.PDFIUM_SPAN_HEADER).write_bytes(SPAN + b'\n')
            with mock.patch.object(repair.os, 'replace') as replace:
                with self.assertRaises(ValueError): repair.apply(work, repair.build_key(repair.BASE_KEY), 'upgrade-v21')
                replace.assert_not_called()
            self.assertEqual(marker.read_bytes(), previous)


if __name__ == '__main__':
    unittest.main()
