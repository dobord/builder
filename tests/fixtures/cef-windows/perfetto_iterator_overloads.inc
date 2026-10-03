/*
 * Copyright (C) 2021 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

// Unchanged overload excerpts from google/perfetto
// 9c7ce42050379be8c24a270f395e00c7347965cb/include/perfetto/tracing/traced_value.h
// Full original SHA-256: 6c1e16a9580f3dc88a446832a87aeea1b73210ec9297e35120ae4648f1f89966

template <typename T>
decltype(std::declval<T>().WriteIntoTrace(std::declval<TracedValue>()), void())
WriteImpl(base::priority_tag<4>, TracedValue context, T&& value) {
  value.WriteIntoTrace(std::move(context));
}

template <typename T>
typename check_traced_value_support<
    decltype(*std::begin(std::declval<T&>()))>::type
WriteImpl(base::priority_tag<1>, TracedValue context, T&& value) {
  auto array = std::move(context).WriteArray();
  for (auto&& item : value) {
    array.Append(item);
  }
}
