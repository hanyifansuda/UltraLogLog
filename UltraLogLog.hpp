/*
 * Copyright 2022-2024 Dynatrace LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#pragma once

#include "DistinctCountUtil.hpp"
#include "DistinctCounter.hpp"
#include "StateChangeObserver.hpp"
#include <algorithm> // for std::fill
#include <cmath>     // for std::pow, std::sqrt
#include <cstdint>
#include <limits> // for std::numeric_limits
#include <memory>
#include <stdexcept>
#include <vector>

using dynatrace::hash4j::distinctcount::internal::countl_zero_32;
using dynatrace::hash4j::distinctcount::internal::countl_zero_64;

namespace dynatrace {
namespace hash4j {
namespace distinctcount {

class UltraLogLog;

class UltraLogLogEstimator : public BaseEstimator<UltraLogLog> {
public:
  ~UltraLogLogEstimator() override = default;
  double estimate(const UltraLogLog &sketch) const override = 0;
};

class UltraLogLog final
    : public DistinctCounter<UltraLogLog, UltraLogLogEstimator> {

public:
  
  class MaximumLikelihoodEstimator;
  class OptimalFGRAEstimator;

  static const MaximumLikelihoodEstimator &getMaximumLikelihoodEstimator();
  static const OptimalFGRAEstimator &getOptimalFGRAEstimator();
  static const UltraLogLogEstimator &getDefaultEstimator();

  static constexpr int32_t MIN_P = 3;
  static constexpr int32_t MAX_P = 32 - 6; // Integer.SIZE - 6

private:
  static constexpr int32_t MIN_STATE_SIZE = 1 << MIN_P;
  static constexpr int32_t MAX_STATE_SIZE = 1 << MAX_P;

  std::vector<uint8_t> state;

  explicit UltraLogLog(int p);
  explicit UltraLogLog(std::vector<uint8_t> state);

public:
  
  static UltraLogLog create(int p);
  static UltraLogLog wrap(std::vector<uint8_t> state);

  UltraLogLog() = default;
  UltraLogLog(const UltraLogLog &) = default;
  UltraLogLog(UltraLogLog &&) = default;
  UltraLogLog &operator=(const UltraLogLog &) = default;
  UltraLogLog &operator=(UltraLogLog &&) = default;

  UltraLogLog copy() const override;
  UltraLogLog downsize(int p) const override;

  static UltraLogLog merge(const UltraLogLog &sketch1,
                           const UltraLogLog &sketch2);

  const std::vector<uint8_t> &getState() const override;
  std::vector<uint8_t> &getState() override;

  int getP() const override;

  UltraLogLog &add(int64_t hashValue) override;
  UltraLogLog &addToken(int32_t token) override;

  static int32_t computeToken(int64_t hashValue);

  UltraLogLog &add(int64_t hashValue,
                   StateChangeObserver *stateChangeObserver) override;
  UltraLogLog &addToken(int32_t token,
                        StateChangeObserver *stateChangeObserver) override;

  UltraLogLog &add(const UltraLogLog &other) override;

  static int64_t unpack(uint8_t reg);
  static uint8_t pack(int64_t hashPrefix);

  double getDistinctCountEstimate() const override;
  double getDistinctCountEstimate(
      const UltraLogLogEstimator &estimator) const override;

  static int64_t getScaledRegisterChangeProbability(uint8_t reg, int p);

  double getStateChangeProbability() const override;
  UltraLogLog &reset() override;
};

class UltraLogLog::MaximumLikelihoodEstimator final
    : public UltraLogLogEstimator {
private:
  static const double INV_SQRT_FISHER_INFORMATION;
  static const double ML_EQUATION_SOLVER_EPS;
  static const double ML_BIAS_CORRECTION_CONSTANT;

  static int64_t contribute(int r, std::vector<int> &b, int p);

public:
  double estimate(const UltraLogLog &ultraLogLog) const override;

  friend const UltraLogLog::MaximumLikelihoodEstimator &
  UltraLogLog::getMaximumLikelihoodEstimator();

private:
  
  MaximumLikelihoodEstimator() = default;
  MaximumLikelihoodEstimator(const MaximumLikelihoodEstimator &) = delete;
  MaximumLikelihoodEstimator &
  operator=(const MaximumLikelihoodEstimator &) = delete;
};

class UltraLogLog::OptimalFGRAEstimator final : public UltraLogLogEstimator {
public:
  
  static const double ETA_0;
  static const double ETA_1;
  static const double ETA_2;
  static const double ETA_3;
  static const double TAU;
  static const double V;

  static const double POW_2_TAU;
  static const double POW_2_MINUS_TAU;
  static const double POW_4_MINUS_TAU;

private:
  static const double MINUS_INV_TAU;

public:
  static const double ETA_X;

private:
  static const double ETA23X;
  static const double ETA13X;
  static const double ETA3012XX;
  static const double POW_4_MINUS_TAU_ETA_23;
  static const double POW_4_MINUS_TAU_ETA_01;
  static const double POW_4_MINUS_TAU_ETA_3;
  static const double POW_4_MINUS_TAU_ETA_1;
  static const double POW_2_MINUS_TAU_ETA_X;
  static const double PHI_1;
  static const double P_INITIAL;
  static const double POW_2_MINUS_TAU_ETA_02;
  static const double POW_2_MINUS_TAU_ETA_13;
  static const double POW_2_MINUS_TAU_ETA_2;
  static const double POW_2_MINUS_TAU_ETA_3;

public:
  static double calculateTheoreticalRelativeStandardError(int p);

  static const std::vector<double> ESTIMATION_FACTORS;
  static const std::vector<double> REGISTER_CONTRIBUTIONS;

  static double smallRangeEstimate(int64_t c0, int64_t c4, int64_t c8,
                                   int64_t c10, int64_t m);
  static double largeRangeEstimate(int64_t c4w0, int64_t c4w1, int64_t c4w2,
                                   int64_t c4w3, int64_t m);
  static double psiPrime(double z, double zSquare);
  static double sigma(double z);

private:
  static double calculateContribution0(int c0, double z);
  static double calculateContribution4(int c4, double z);
  static double calculateContribution8(int c8, double z);
  static double calculateContribution10(int c10, double z);

public:
  static double phi(double z, double zSquare);

private:
  static double calculateLargeRangeContribution(int c4w0, int c4w1, int c4w2,
                                                int c4w3, int m, int w);

public:
  double estimate(const UltraLogLog &ultraLogLog) const override;

  friend const UltraLogLog::OptimalFGRAEstimator &
  UltraLogLog::getOptimalFGRAEstimator();

private:
  
  OptimalFGRAEstimator() = default;
  OptimalFGRAEstimator(const OptimalFGRAEstimator &) = delete;
  OptimalFGRAEstimator &operator=(const OptimalFGRAEstimator &) = delete;
};

} // namespace distinctcount
} // namespace hash4j
} // namespace dynatrace