/*
 * Copyright 2022-2024 Dynatrace LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 */

#pragma once

#include <algorithm>
#include <cmath>
#include <cstdint>
#include <cstring>
#include <limits>
#include <memory>
#include <stdexcept>
#include <type_traits>
#include <vector>

#if __cplusplus < 202002L
// C++17 fallback for std::bit_cast
namespace std {
template <class To, class From>
typename std::enable_if<(sizeof(To) == sizeof(From)) &&
                            std::is_trivially_copyable<From>::value &&
                            std::is_trivial<To>::value,
                        To>::type
bit_cast(const From &src) noexcept {
  To dst;
  ::memcpy(&dst, &src, sizeof(To));
  return dst;
}
} // namespace std
#endif

namespace dynatrace {
namespace hash4j {
namespace distinctcount {

namespace internal {

inline int32_t countl_zero_32(uint32_t x) {
#if defined(_MSC_VER)
  if (x == 0) return 32;
  unsigned long index;
  _BitScanReverse(&index, x);
  return 31 - index;
#else
  return x == 0 ? 32 : __builtin_clz(x);
#endif
}

inline int32_t countl_zero_64(uint64_t x) {
#if defined(_MSC_VER)
#ifdef _WIN64
  if (x == 0) return 64;
  unsigned long index;
  _BitScanReverse64(&index, x);
  return 63 - index;
#else
  if (x == 0) return 64;
  unsigned long index;
  if (_BitScanReverse(&index, (uint32_t)(x >> 32))) return 31 - index;
  if (_BitScanReverse(&index, (uint32_t)x)) return 63 - index;
  return 64;
#endif
#else
  return x == 0 ? 64 : __builtin_clzll(x);
#endif
}

} // namespace internal


class DistinctCountUtil {
private:
  DistinctCountUtil() = delete;

  static constexpr double C0 = -1.0 / 3.0;
  static constexpr double C1 = 1.0 / 45.0;
  static constexpr double C2 = 1.0 / 472.5;

  static constexpr int MAX_NLZ_IN_TOKEN = 38;
  static constexpr double RELATIVE_ERROR_LIMIT = 1e-6;
  static constexpr uint32_t INVALID_TOKEN_INDEX = 0xFFFFFFFFu;

public:
  // -----------------------
  // Utilities
  // -----------------------
  static std::invalid_argument getUnexpectedStateLengthException() {
    return std::invalid_argument("unexpected state length!");
  }

  static bool isUnsignedPowerOfTwo(int x) { return (x & (x - 1)) == 0; }

  static void checkPrecisionParameter(int p, int minP, int maxP) {
    if (p < minP || p > maxP) {
      throw std::invalid_argument("illegal precision parameter");
    }
  }

  // -------------------------------------------------------------------
  // Solve maximum likelihood equation
  // -------------------------------------------------------------------
  static double solveMaximumLikelihoodEquation(double a,
                                               const std::vector<int> &b,
                                               int n,
                                               double relativeErrorLimit) {
    if (a == 0.0) return std::numeric_limits<double>::infinity();

    int kMax = n;
    while (kMax >= 0 && b[kMax] == 0) --kMax;
    if (kMax < 0) return 0.0;

    int kMin = kMax;
    int t = b[kMax];
    long long s1 = t;
    double s2 = std::bit_cast<double>(static_cast<uint64_t>(t) +
                                      (static_cast<uint64_t>(kMax) << 52));

    for (int k = kMax - 1; k >= 0; --k) {
      t = b[k];
      if (t > 0) {
        s1 += t;
        s2 += std::bit_cast<double>(static_cast<uint64_t>(t) +
                                    (static_cast<uint64_t>(k) << 52));
        kMin = k;
      }
    }

    double x;
    if (s2 <= 1.5 * a) {
      x = static_cast<double>(s1) / (0.5 * s2 + a);
    } else {
      x = std::log1p(s2 / a) * (static_cast<double>(s1) / s2);
    }

    double deltaX = x;
    double gPrevious = 0.0;
    while (deltaX > x * relativeErrorLimit) {
      uint64_t rawX = std::bit_cast<uint64_t>(x);
      int kappa = static_cast<int>(((rawX & 0x7FF0000000000000ULL) >> 52) - 1021ULL);

      uint64_t shiftCnt = (static_cast<uint64_t>(std::max(kMax, kappa)) + 1ULL) << 52;
      double xPrime = std::bit_cast<double>(rawX - shiftCnt);

      double xPrime2 = xPrime * xPrime;
      double h = xPrime + xPrime2 * (C0 + xPrime2 * (C1 - xPrime2 * C2));

      for (int k = kappa - 1; k >= kMax; --k) {
        double hPrime = 1.0 - h;
        h = (xPrime + h * hPrime) / (xPrime + hPrime);
        xPrime += xPrime;
      }

      double g = static_cast<double>(b[kMax]) * h;
      for (int k = kMax - 1; k >= kMin; --k) {
        double hPrime = 1.0 - h;
        h = (xPrime + h * hPrime) / (xPrime + hPrime);
        xPrime += xPrime;
        g += static_cast<double>(b[k]) * h;
      }
      g += x * a;

      if (gPrevious < g && g <= static_cast<double>(s1)) {
        deltaX *= (g - static_cast<double>(s1)) / (gPrevious - g);
      } else {
        deltaX = 0.0;
      }
      x += deltaX;
      gPrevious = g;
    }

    return x;
  }

  // -------------------------------------------------------------------
  // Token functions
  // -------------------------------------------------------------------
  static int32_t computeToken1(int64_t hashValue) {
    uint32_t idx = static_cast<uint32_t>(static_cast<uint64_t>(hashValue) >> 38);
    int32_t nlz = countLeadingZeros64(~(~hashValue << 26)) & 0x3F;
    return (static_cast<int32_t>(idx) << 6) | nlz;
  }

  static int64_t reconstructHash1(int32_t token) {
    int64_t idx = static_cast<int64_t>(static_cast<uint32_t>(token) & 0xFFFFFFC0u);
    uint64_t mask38 = 0x3FFFFFFFFFULL;
    uint64_t right = mask38 >> (token & 0x3F);
    return static_cast<int64_t>(right | (static_cast<uint64_t>(idx) << 32));
  }

  struct TokenIterator {
    virtual ~TokenIterator() = default;
    virtual bool hasNext() = 0;
    virtual int32_t nextToken() = 0;
  };

  struct TokenIterable {
    virtual ~TokenIterable() = default;
    virtual std::unique_ptr<TokenIterator> iterator() = 0;
  };

  static bool isValidToken(int32_t token) {
    int nlz = token & 0x3F;
    return nlz <= MAX_NLZ_IN_TOKEN;
  }

  static double estimateDistinctCountFromTokens(TokenIterable &tokenIterable) {
    std::unique_ptr<TokenIterator> it = tokenIterable.iterator();
    if (!it) throw std::invalid_argument("TokenIterable returned null iterator");

    std::vector<int> b(MAX_NLZ_IN_TOKEN, 0);
    uint32_t currentIdx = INVALID_TOKEN_INDEX;
    uint64_t currentFlags = 0ULL;

    while (it->hasNext()) {
      int32_t token = it->nextToken();
      if (!isValidToken(token)) continue;

      uint32_t idx = static_cast<uint32_t>(token) >> 6;
      if (currentIdx != idx) {
        currentFlags = 0ULL;
        currentIdx = idx;
      }

      uint64_t mask = 1ULL << (token & 0x3F);
      if ((currentFlags & mask) == 0ULL) {
        currentFlags |= mask;
        int nlz = token & 0x3F;
        if (nlz < MAX_NLZ_IN_TOKEN) b[nlz] += 1;
        else b[MAX_NLZ_IN_TOKEN - 1] += 1;
      }
    }

    double a = std::ldexp(1.0, 27); // 2^27
    int maxNonZeroIndex = 0;

    for (int i = 0; i < MAX_NLZ_IN_TOKEN; ++i) {
      if (b[i] != 0) {
        uint64_t bits = (static_cast<uint64_t>(0x3FF - i) << 52);
        a -= b[i] * std::bit_cast<double>(bits);
        maxNonZeroIndex = i;
      }
    }

    double x = solveMaximumLikelihoodEquation(a, b, maxNonZeroIndex, RELATIVE_ERROR_LIMIT);
    return x * std::ldexp(1.0, 27); // multiply by 2^27
  }

  static double unsignedLongToDouble(int64_t l) {
    uint64_t ul = static_cast<uint64_t>(l);
    double d = static_cast<double>(ul & 0x7FFFFFFFFFFFFFFFULL);
    if (l < 0) d += 0x1.0p63;
    return d;
  }

private:
  static int32_t countLeadingZeros64(uint64_t v) {
#if defined(__GNUG__) || defined(__clang__)
    if (v == 0) return 64;
    return __builtin_clzll(v);
#else
    if (v == 0) return 64;
    int32_t n = 0;
    while ((v & (1ULL << 63)) == 0) {
      n++;
      v <<= 1;
    }
    return n;
#endif
  }

  static int32_t countLeadingZeros64(int64_t v_signed) {
    return countLeadingZeros64(static_cast<uint64_t>(v_signed));
  }
};

} // namespace distinctcount
} // namespace hash4j
} // namespace dynatrace
