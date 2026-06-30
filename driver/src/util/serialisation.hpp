#pragma once
#include "flatbuffers/flatbuffers.h"
#include <vector.hpp>
#include <span.hpp>
#include <utility.hpp>

namespace serialisation
{
    [[nodiscard]] inline cstd::vector<uint8_t> builder_to_vector(const flatbuffers::FlatBufferBuilder& builder)
    {
        return cstd::vector<uint8_t>(builder.GetBufferPointer(), builder.GetSize());
    }

    template <class CreateFn, class... Args>
    [[nodiscard]] cstd::vector<uint8_t> serialise(flatbuffers::FlatBufferBuilder& builder, const CreateFn& create_fn, Args&&... args)
    {
        const auto root = create_fn(builder, cstd::forward<Args>(args)...);
        builder.Finish(root);
        return builder_to_vector(builder);
    }

    template <class CreateFn, class... Args>
    [[nodiscard]] cstd::vector<uint8_t> serialise(const CreateFn& create_fn, Args&&... args)
    {
        flatbuffers::FlatBufferBuilder builder;
        return serialise(builder, create_fn, cstd::forward<Args>(args)...);
    }

    template <auto CreateFn>
    [[nodiscard]] constexpr auto lift()
    {
        return []<class... Args>(flatbuffers::FlatBufferBuilder& builder, Args&&... args)
        {
            return CreateFn(builder, cstd::forward<Args>(args)...);
        };
    }

    template <class T, class Range, class Fn>
    [[nodiscard]] auto collect(flatbuffers::FlatBufferBuilder& builder, const Range& range, Fn&& fn)
    {
        cstd::vector<flatbuffers::Offset<T>> offsets;

        for (const auto& item : range)
        {
            offsets.push_back(fn(builder, item));
        }

        return builder.CreateVector(offsets.data(), offsets.size());
    }

    template <class T>
    [[nodiscard]] const T* deserialise(const uint8_t* data) noexcept
    {
        return flatbuffers::GetRoot<T>(data);
    }

    template <class T>
    [[nodiscard]] const T* deserialise(cstd::span<const uint8_t> buffer) noexcept
    {
        return flatbuffers::GetRoot<T>(buffer.data());
    }
}
