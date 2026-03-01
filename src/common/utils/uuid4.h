/*=============================================================================
Copyright (c) 2024-2026 Stas Skokov

Distributed under the MIT License (https://opensource.org/licenses/MIT)
=============================================================================*/

#pragma once

#include <string>

#include <boost/uuid/uuid.hpp>
#include <boost/uuid/uuid_generators.hpp>
#include <boost/uuid/uuid_io.hpp>

namespace fptn::common::utils {

inline std::string GenerateUUID4() {
  boost::uuids::random_generator generator;
  const boost::uuids::uuid uuid = generator();
  return boost::uuids::to_string(uuid);
}

}  // namespace fptn::common::utils
