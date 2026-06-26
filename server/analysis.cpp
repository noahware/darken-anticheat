#include "analysis.hpp"
#include "log.hpp"

namespace analysis
{
    void process_example_check(const Anticheat::ExampleCheckResult* result)
    {
        if (!result)
        {
            LOG_ERR("null ExampleCheckResult");
            return;
        }

        LOG_INFO("example check result: value=0x{:x}, status={}",
            result->value(), result->status());

        if (result->value() != 0x123)
        {
            LOG_WARN("unexpected example check value: 0x{:x} (expected 0x123)",
                result->value());
        }

        if (result->status() != 0)
        {
            LOG_WARN("example check status non-zero: {}", result->status());
        }
    }

    void process_client_timestamp(const Anticheat::ClientTimestampResult* result)
    {
        if (!result)
        {
            LOG_ERR("null ClientTimestampResult");
            return;
        }

        LOG_INFO("client timestamp: {}ms", result->timestamp());
    }
}
