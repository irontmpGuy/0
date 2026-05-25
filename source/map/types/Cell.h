#pragma once
#include <cstdint>

struct Cell {
    static inline constexpr uint32_t MAX_ITEMS = 8;

    void* items[MAX_ITEMS];
    uint8_t count;

    Cell()
        : items{ nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr },
          count(0)
    {}

    void clear() {
        for (uint32_t i = 0; i < MAX_ITEMS; ++i)
            items[i] = nullptr;
        count = 0;
    }

    bool add(void* obj) {
        if (!obj) return false;
        if (count >= MAX_ITEMS) return false;

        items[count++] = obj;
        return true;
    }
};