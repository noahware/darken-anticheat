#include "example_check.hpp"

#include "flatbuffers/flatbuffers.h"
#include "example_check_generated.h"

cstd::vector<uint8_t> checks::example_check()
{
	flatbuffers::FlatBufferBuilder fbb(128);

	auto result = Anticheat::CreateExampleCheckResult(fbb, 0x123, 0);

	fbb.Finish(result);

	const auto* buf = fbb.GetBufferPointer();
	const auto size = fbb.GetSize();

	return cstd::vector<uint8_t>(buf, size);
}
