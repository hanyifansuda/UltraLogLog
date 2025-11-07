#pragma once

namespace dynatrace {
namespace hash4j {
namespace distinctcount {

class StateChangeObserver {
public:
  virtual ~StateChangeObserver() = default;

  virtual void stateChanged(double probabilityDecrement) = 0;
};

} // namespace distinctcount
} // namespace hash4j
} // namespace dynatrace