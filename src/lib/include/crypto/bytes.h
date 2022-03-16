/*
* Copyright 2019 Virtru Corporation
*
* SPDX - License Identifier: BSD-3-Clause-Clear
*
*/
//
//  TDF SDK
//
//  Created by Sujan Reddy on 2019/04/07.
//

#ifndef VIRTRU_BYTES_H
#define VIRTRU_BYTES_H

#include <gsl/span>
#include <array>

/// This provides a simple wrapper around gsl to work with bytes.
namespace virtru::crypto {

    /// Constants
    constexpr auto kKeyLength = 32;
    constexpr auto kIVLength = 16;

   ///
   /// Define the bytes(Read only).
   ///
   template <std::ptrdiff_t Extent = gsl :: dynamic_extent>
   using BytesT = gsl::span <const gsl::byte, Extent>;
   using Bytes = BytesT<>;

   ///
   /// Wrapper around std::array
   ///
   template <std::size_t N>
   using ByteArray = std::array <gsl :: byte, N>;
   using WrappedKey = ByteArray<kKeyLength>;
   using IV = ByteArray<kIVLength>;

    ///
    /// Define writeable bytes
    ///
    template <std::ptrdiff_t Extent = gsl::dynamic_extent>
    using WriteableBytesT = gsl::span <gsl::byte, Extent>;
    using WriteableBytes = WriteableBytesT<>;

    template <std :: ptrdiff_t Extent >
    constexpr auto toBytes(BytesT < Extent > data) noexcept {
        return data;
    }
    
    template <std::ptrdiff_t Extent>
    constexpr auto toWriteableBytes(WriteableBytesT <Extent> data) noexcept {
        return data;
    }

    /// Adding constness
    template <std::ptrdiff_t Extent>
    constexpr auto toBytes (gsl::span <gsl::byte, Extent> data) noexcept {
        return BytesT <Extent> {data};
    }

    /// Any containers inherited from basic_string<ElementType> to bytes(Read only).
    template <typename ElementType,
              std::ptrdiff_t Extent,
              typename = std::enable_if_t <std::has_unique_object_representations_v <ElementType>> >
    auto toBytes (gsl::span <ElementType, Extent> data) noexcept {
        return as_bytes(data);
    }

    /// Any containers inherited from basic_string<ElementType> to writable bytes.
    template <typename ElementType,
              std::ptrdiff_t Extent,
              typename = std::enable_if_t <std::has_unique_object_representations_v <ElementType>> >
    auto toWriteableBytes(gsl::span <ElementType, Extent> data) noexcept {
        return as_writeable_bytes(data);
    }

    /// Form std::array to bytes(Read only).
    template <typename ElementType,
              std::size_t N,
              typename = std::enable_if_t <std::has_unique_object_representations_v <ElementType>> >
    constexpr auto toBytes(const std::array <ElementType, N> & data) noexcept {
        return toBytes(gsl::span <const ElementType, N > { data });
    }

    /// Form std::array to writable bytes.
    template <typename ElementType,
              std::size_t N,
              typename = std::enable_if_t <std::has_unique_object_representations_v <ElementType>> >
    constexpr auto toWriteableBytes(std::array <ElementType, N> & data) noexcept {
        return toWriteableBytes(gsl::span <ElementType, N> { data });
    }

    // Form Plain old C array to bytes(Read only).
    template <typename ElementType, 
              std::size_t N,
              typename = std::enable_if_t <std::has_unique_object_representations_v <ElementType>> >
    constexpr auto toBytes(ElementType (& arr)[N]) noexcept {
        return toBytes(gsl::make_span(arr));
    }

    // Form Plain old C array to writable bytes.
    template <typename ElementType,
              std::size_t N,
              typename = std::enable_if_t <std::has_unique_object_representations_v <ElementType>> >
    constexpr auto toWriteableBytes(ElementType(&arr)[N]) noexcept {
        return toWriteableBytes(gsl::make_span(arr));
    }

    // From container(std::string/std::vector<char>) to bytes(Read only).
    template <class Cont,
              typename = std::enable_if_t <std::has_unique_object_representations_v <std::remove_reference_t <
                                           decltype(* std::declval <const Cont&> ().data ())>> > >
    constexpr auto toBytes(const Cont & cont) noexcept {
        return toBytes(gsl::make_span(cont));
    }

    // From container(std::string/std::vector<char>) to to writable bytes.
    template <class Cont,
              typename = std::enable_if_t <std::has_unique_object_representations_v <std::remove_reference_t <
                                           decltype(* std::declval <Cont &> ().data ())>> > >
    constexpr auto toWriteableBytes(Cont & cont) noexcept {
        return toWriteableBytes(gsl::make_span(cont));
    }

    ///
    /// Simple conversions.
    ///
    template <typename T>
    using ConvertibleToBytes = decltype(toBytes(std::declval <const T&> ()));

    template <typename T, std::ptrdiff_t Extent = gsl::dynamic_extent>
    inline constexpr bool isBytes = std::is_convertible_v <const T&, BytesT <Extent>>;

    template <typename T>
    using ExplicitlyConvertibleToBytes = std::enable_if_t <! isBytes <T>, ConvertibleToBytes <T>>;

    template <typename T, typename = ConvertibleToBytes <T>>
    auto toDynamicBytes (const T& t) {
        return Bytes { toBytes(t) };
    }

    template <typename T, typename = ExplicitlyConvertibleToBytes <T>>
    auto toDynamicBytesExplicitly (const T& t) {
        return toDynamicBytes(t);
    }

    inline unsigned char* toUchar(gsl::byte* p) {
        return reinterpret_cast <unsigned char *> (p);
    }

    inline const unsigned char *toUchar (const gsl::byte *p) {
        return reinterpret_cast <const unsigned char *> (p);
    }

    template <std::ptrdiff_t Extent>
    auto toUchar(BytesT<Extent> src) {
        return gsl::span <const unsigned char, Extent> {reinterpret_cast <const unsigned char *> (src.data ()), src.size()};
    }

    inline char* toChar(gsl::byte *p) {
        return reinterpret_cast <char*> (p);
    }

    inline const char* toChar(const gsl::byte* p) {
        return reinterpret_cast <const char *> (p);
    }

    template <std::ptrdiff_t Extent>
    auto toChar(BytesT <Extent> src) {
        return gsl :: span <const char, Extent> { reinterpret_cast <const char*> (src.data()), src.size ()};
    }

    template <std::ptrdiff_t Extent>
    auto toChar(WriteableBytesT <Extent> src) {
        return gsl::span <const char, Extent> { reinterpret_cast <const char *> (src.data()), src.size ()};
    }

    inline auto finalizeSize(WriteableBytes& buffer, const int& size) {
        return gsl::finally( [&buffer, &size ] { buffer = buffer.first(size); });
    }
} // namespace virtru::crypto

#endif //VIRTRU_BYTES_H

