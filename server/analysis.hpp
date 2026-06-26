#pragma once
#include <schema/example_check_generated.h>
#include <schema/client_timestamp_generated.h>

namespace analysis
{
    void process_example_check(const Anticheat::ExampleCheckResult* result);
    void process_client_timestamp(const Anticheat::ClientTimestampResult* result);
}
