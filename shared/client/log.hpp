#pragma once
#include <spdlog/spdlog.h>

#define LOG_INFO(fmt, ...) spdlog::info(fmt __VA_OPT__(,) __VA_ARGS__)
#define LOG_WARN(fmt, ...) spdlog::warn(fmt __VA_OPT__(,) __VA_ARGS__)
#define LOG_ERR(fmt, ...) spdlog::error(fmt __VA_OPT__(,) __VA_ARGS__)
