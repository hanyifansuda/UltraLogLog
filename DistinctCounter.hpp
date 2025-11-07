#pragma once

#include "StateChangeObserver.hpp"
#include <cstdint>
#include <vector>

namespace dynatrace {
namespace hash4j {
namespace distinctcount {

template <typename SketchType> class BaseEstimator {
public:
  virtual ~BaseEstimator() = default;
  virtual double estimate(const SketchType &sketch) const = 0;
};

template <typename SketchImpl, typename EstimatorType> class DistinctCounter {
public:
  virtual ~DistinctCounter() = default;

  virtual SketchImpl copy() const = 0;
  virtual SketchImpl downsize(int p) const = 0;
  virtual SketchImpl &add(int64_t hashValue) = 0;
  virtual SketchImpl &addToken(int32_t token) = 0;
  virtual SketchImpl &add(int64_t hashValue,
                          StateChangeObserver *stateChangeObserver) = 0;
  virtual SketchImpl &addToken(int32_t token,
                               StateChangeObserver *stateChangeObserver) = 0;
  virtual SketchImpl &add(const SketchImpl &other) = 0;

  virtual const std::vector<uint8_t> &getState() const = 0;
  virtual std::vector<uint8_t> &getState() = 0;

  virtual int getP() const = 0;
  virtual double getDistinctCountEstimate() const = 0;
  virtual double getDistinctCountEstimate(const EstimatorType &estimator) const = 0;
  virtual double getStateChangeProbability() const = 0;
  virtual SketchImpl &reset() = 0;
};

} // namespace distinctcount
} // namespace hash4j
} // namespace dynatrace