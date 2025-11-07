// Modified UltraLogLog.cpp — aligned line-by-line with UltraLogLog.java
// Java source used for comparison: :contentReference[oaicite:0]{index=0}
// C++ source (this file): :contentReference[oaicite:1]{index=1}

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

#include "UltraLogLog.hpp"
#include <cmath>
#include <limits>
#include <numeric> // for std::accumulate

namespace dynatrace {
namespace hash4j {
namespace distinctcount {

// using namespace DistinctCountUtil;

const UltraLogLog::MaximumLikelihoodEstimator &
UltraLogLog::getMaximumLikelihoodEstimator() {
  static const MaximumLikelihoodEstimator instance;
  return instance;
}

const UltraLogLog::OptimalFGRAEstimator &
UltraLogLog::getOptimalFGRAEstimator() {
  static const OptimalFGRAEstimator instance;
  return instance;
}

const UltraLogLogEstimator &UltraLogLog::getDefaultEstimator() {
  return getOptimalFGRAEstimator();
}

UltraLogLog::UltraLogLog(int p) : state(1 << p, 0) {}

UltraLogLog::UltraLogLog(std::vector<uint8_t> state)
    : state(std::move(state)) {}

UltraLogLog UltraLogLog::create(int p) {
  DistinctCountUtil::checkPrecisionParameter(p, MIN_P, MAX_P);
  return UltraLogLog(p);
}

UltraLogLog UltraLogLog::wrap(std::vector<uint8_t> state) {
  if (state.empty()) {
    throw std::invalid_argument("null argument");
  }
  if (state.size() > MAX_STATE_SIZE
      || state.size() < MIN_STATE_SIZE
      || !DistinctCountUtil::isUnsignedPowerOfTwo(static_cast<int32_t>(state.size()))) {
    throw DistinctCountUtil::getUnexpectedStateLengthException();
  }
  return UltraLogLog(std::move(state));
}

UltraLogLog UltraLogLog::copy() const {
  return UltraLogLog(this->state);
}

UltraLogLog UltraLogLog::downsize(int p) const {
  DistinctCountUtil::checkPrecisionParameter(p, MIN_P, MAX_P);
  if ((1 << p) >= state.size()) {
    return copy();
  } else {
    UltraLogLog newSketch = UltraLogLog::create(p);
    newSketch.add(*this);
    return newSketch;
  }
}

UltraLogLog UltraLogLog::merge(const UltraLogLog &sketch1,
                               const UltraLogLog &sketch2) {
  if (sketch1.state.size() <= sketch2.state.size()) {
    UltraLogLog mergedSketch = sketch1.copy();
    mergedSketch.add(sketch2);
    return mergedSketch;
  } else {
    UltraLogLog mergedSketch = sketch2.copy();
    mergedSketch.add(sketch1);
    return mergedSketch;
  }
}

const std::vector<uint8_t> &UltraLogLog::getState() const { return state; }

std::vector<uint8_t> &UltraLogLog::getState() { return state; }

int UltraLogLog::getP() const {
  return 31 - countl_zero_32(static_cast<uint32_t>(state.size()));
}

UltraLogLog &UltraLogLog::add(int64_t hashValue) {
  add(hashValue, nullptr);
  return *this;
}

UltraLogLog &UltraLogLog::addToken(int32_t token) {
  return add(DistinctCountUtil::reconstructHash1(token));
}

int32_t UltraLogLog::computeToken(int64_t hashValue) {
  return DistinctCountUtil::computeToken1(hashValue);
}

UltraLogLog &UltraLogLog::add(int64_t hashValue,
                              StateChangeObserver *stateChangeObserver) {
  
  int q = countl_zero_64(state.size() - 1ULL); // q = 64 - p

  // 2. 'int idx = (int) (hashValue >>> q);'
  uint32_t idx =
      static_cast<uint32_t>(static_cast<uint64_t>(hashValue) >> q);

  // 3. 'int nlz = Long.numberOfLeadingZeros(~(~hashValue << -q));'
  int p_for_nlz = 64 - q; 
  int32_t nlz = countl_zero_64(~(~hashValue << p_for_nlz));

  // 4. 'byte oldState = state[idx];'
  uint8_t oldState = state[idx];

  // 5. 'long hashPrefix = unpack(oldState);'
  int64_t hashPrefix = unpack(oldState);

  // 6. 'hashPrefix |= 1L << (nlz + ~q);'
  int64_t shift_amount = nlz + ~q;
  hashPrefix |= (1LL << (shift_amount & 0x3F));

  // 7. 'byte newState = pack(hashPrefix);'
  uint8_t newState = pack(hashPrefix);
  state[idx] = newState;

  if (stateChangeObserver != nullptr && newState != oldState) {
    // 8. 'int p = 64 - q;'
    int p = 64 - q;
    stateChangeObserver->stateChanged(
        (getScaledRegisterChangeProbability(oldState, p) -
         getScaledRegisterChangeProbability(newState, p)) *
        0x1.0p-64); // C++ hex float
  }
  return *this;
}

UltraLogLog &UltraLogLog::addToken(int32_t token,
                                   StateChangeObserver *stateChangeObserver) {
  return add(DistinctCountUtil::reconstructHash1(token), stateChangeObserver);
}

UltraLogLog &UltraLogLog::add(const UltraLogLog &other) {
  const std::vector<uint8_t> &otherData = other.state;
  if (otherData.size() < state.size()) {
    throw std::invalid_argument("other has smaller precision");
  } else if (otherData.size() == state.size()) {
    for (size_t i = 0; i < state.size(); ++i) {
      uint8_t otherR = otherData[i];
      if (otherR != 0) {
        state[i] = pack(unpack(state[i]) | unpack(otherR));
      }
    }
  } else {
    const int p = getP();
    const int otherP = other.getP();
    const int otherPMinusOne = otherP - 1;
    const int64_t kUpperBound = 1LL << (otherP - p);
    size_t j = 0;
    for (size_t i = 0; i < state.size(); ++i) {
      int64_t hashPrefix = unpack(state[i]) | unpack(otherData[j]);
      j += 1;
      for (int64_t k = 1; k < kUpperBound; ++k) {
        if (otherData[j] != 0) {
          hashPrefix |= (1LL << (countl_zero_64(k) + otherPMinusOne));
        }
        j += 1;
      }
      if (hashPrefix != 0) {
        state[i] = pack(hashPrefix);
      }
    }
  }
  return *this;
}


int64_t UltraLogLog::unpack(uint8_t reg) {

  int8_t reg_signed = static_cast<int8_t>(reg);
  
  int32_t reg_int = reg_signed; 
  
  uint32_t shift_base = static_cast<uint32_t>(reg_int) >> 2;
  
  int32_t shift_amount = static_cast<int32_t>(shift_base) - 2;

  return (4LL | (reg & 3)) << (shift_amount & 0x3F);
}

uint8_t UltraLogLog::pack(int64_t hashPrefix) {
  
  int32_t nlz = countl_zero_64(hashPrefix) + 1;
  
  uint64_t p1 = static_cast<uint64_t>(hashPrefix << (nlz & 0x3F));
  
  uint64_t p2 = p1 >> 62; 
  
  return static_cast<uint8_t>((-nlz << 2) | p2);
}

// ======================================================================

double UltraLogLog::getDistinctCountEstimate() const {
  return getDistinctCountEstimate(getDefaultEstimator());
}

double UltraLogLog::getDistinctCountEstimate(
    const UltraLogLogEstimator &estimator) const {
  return estimator.estimate(*this);
}

int64_t UltraLogLog::getScaledRegisterChangeProbability(uint8_t reg, int p) {
  if (reg == 0)
    return 1LL << ((-p) & 0x3F);

  int k = 1 - p + (reg >> 2);

  return (static_cast<uint64_t>(
              ((((reg & 2) | ((reg & 1) << 2)) ^ 7LL) << (~k & 0x3F))) >>
          p); 
}

double UltraLogLog::getStateChangeProbability() const {
  const int p = getP();
  int64_t sum = 0; // Java: long sum = 0;
  for (uint8_t x : state) {
    sum += getScaledRegisterChangeProbability(x, p);
  }
  if (sum == 0 && state[0] == 0) {
    return 1.;
  }
  return DistinctCountUtil::unsignedLongToDouble(
             static_cast<uint64_t>(sum)) *
         0x1.0p-64;
}

UltraLogLog &UltraLogLog::reset() {
  std::fill(state.begin(), state.end(), 0);
  return *this;
}

// ======================================================================
// UltraLogLog::MaximumLikelihoodEstimator
// ======================================================================

const double
    UltraLogLog::MaximumLikelihoodEstimator::INV_SQRT_FISHER_INFORMATION =
        0.7608621002725182;

const double UltraLogLog::MaximumLikelihoodEstimator::ML_EQUATION_SOLVER_EPS =
    0.001 * INV_SQRT_FISHER_INFORMATION;

const double
    UltraLogLog::MaximumLikelihoodEstimator::ML_BIAS_CORRECTION_CONSTANT =
        0.48147376527720065;

int64_t UltraLogLog::MaximumLikelihoodEstimator::contribute(
    int r, std::vector<int> &b, int p) {
  int r2 = r - (p << 2) - 4;
  if (r2 < 0) {
    int64_t ret = 4LL;
    if (r2 == -2 || r2 == -8) {
      b[0] += 1;
      ret -= 2;
    }
    if (r2 == -2 || r2 == -4) {
      b[1] += 1;
      ret -= 1;
    }
    return ret << (62 - p);
  } else {

    int k = r2 >> 2; 
    
    int64_t ret = 0xE000000000000000LL;
    int y0 = r & 1;
    int y1 = (r >> 1) & 1; // r 是 [0, 255], >> 1 OK.
    ret -= static_cast<int64_t>(y0) << 63;
    ret -= static_cast<int64_t>(y1) << 62;
    b[k] += y0;
    b[k + 1] += y1;
    b[k + 2] += 1;

    return static_cast<uint64_t>(ret) >> (k + p);
  }
}

double UltraLogLog::MaximumLikelihoodEstimator::estimate(
    const UltraLogLog &ultraLogLog) const {
  
  const std::vector<uint8_t> &state = ultraLogLog.state;
  int p = ultraLogLog.getP();

  int64_t sum = 0;
  std::vector<int> b(64, 0); // Java: new int[64]
  for (uint8_t reg : state) {
    sum += contribute(reg, b,
                      p);
  }
  int m = state.size();
  if (sum == 0) {
    return (state[0] == 0)
               ? 0
               : std::numeric_limits<double>::infinity(); // POSITIVE_INFINITY
  }
  
  b[63 - p] += b[64 - p];
  
  double factor = static_cast<double>(m << 1);
  
  double a = DistinctCountUtil::unsignedLongToDouble(static_cast<uint64_t>(sum)) * factor *
             0x1.0p-64; // C++ hex float '0x1p-64'

  return factor *
         DistinctCountUtil::solveMaximumLikelihoodEquation(
             a, b, 63 - p, ML_EQUATION_SOLVER_EPS / std::sqrt(m)) /
         (1. + ML_BIAS_CORRECTION_CONSTANT / m);
}

const double UltraLogLog::OptimalFGRAEstimator::ETA_0 = 4.663135422063788;
const double UltraLogLog::OptimalFGRAEstimator::ETA_1 = 2.1378502137958524;
const double UltraLogLog::OptimalFGRAEstimator::ETA_2 = 2.781144650979996;
const double UltraLogLog::OptimalFGRAEstimator::ETA_3 = 0.9824082545153715;
const double UltraLogLog::OptimalFGRAEstimator::TAU = 0.8194911375910897;
const double UltraLogLog::OptimalFGRAEstimator::V = 0.6118931496978437;

const double UltraLogLog::OptimalFGRAEstimator::POW_2_TAU =
    std::pow(2., TAU); 
const double UltraLogLog::OptimalFGRAEstimator::POW_2_MINUS_TAU =
    std::pow(2., -TAU);
const double UltraLogLog::OptimalFGRAEstimator::POW_4_MINUS_TAU =
    std::pow(4., -TAU); 
const double UltraLogLog::OptimalFGRAEstimator::MINUS_INV_TAU =
    -1 / TAU; 
const double UltraLogLog::OptimalFGRAEstimator::ETA_X =
    ETA_0 - ETA_1 - ETA_2 + ETA_3;
const double UltraLogLog::OptimalFGRAEstimator::ETA23X =
    (ETA_2 - ETA_3) / ETA_X;
const double UltraLogLog::OptimalFGRAEstimator::ETA13X =
    (ETA_1 - ETA_3) / ETA_X; 
const double UltraLogLog::OptimalFGRAEstimator::ETA3012XX =
    (ETA_3 * ETA_0 - ETA_1 * ETA_2) / (ETA_X * ETA_X);
const double UltraLogLog::OptimalFGRAEstimator::POW_4_MINUS_TAU_ETA_23 =
    POW_4_MINUS_TAU * (ETA_2 - ETA_3);
const double UltraLogLog::OptimalFGRAEstimator::POW_4_MINUS_TAU_ETA_01 =
    POW_4_MINUS_TAU * (ETA_0 - ETA_1);
const double UltraLogLog::OptimalFGRAEstimator::POW_4_MINUS_TAU_ETA_3 =
    POW_4_MINUS_TAU * ETA_3; 
const double UltraLogLog::OptimalFGRAEstimator::POW_4_MINUS_TAU_ETA_1 =
    POW_4_MINUS_TAU * ETA_1; 
const double UltraLogLog::OptimalFGRAEstimator::POW_2_MINUS_TAU_ETA_X =
    POW_2_MINUS_TAU * ETA_X; 
const double UltraLogLog::OptimalFGRAEstimator::PHI_1 =
    ETA_0 /
    (POW_2_TAU * (2. * POW_2_TAU - 1));
const double UltraLogLog::OptimalFGRAEstimator::P_INITIAL =
    ETA_X *
    (POW_4_MINUS_TAU / (2 - POW_2_MINUS_TAU));
const double UltraLogLog::OptimalFGRAEstimator::POW_2_MINUS_TAU_ETA_02 =
    POW_2_MINUS_TAU * (ETA_0 - ETA_2);
const double UltraLogLog::OptimalFGRAEstimator::POW_2_MINUS_TAU_ETA_13 =
    POW_2_MINUS_TAU * (ETA_1 - ETA_3);
const double UltraLogLog::OptimalFGRAEstimator::POW_2_MINUS_TAU_ETA_2 =
    POW_2_MINUS_TAU * ETA_2; 
const double UltraLogLog::OptimalFGRAEstimator::POW_2_MINUS_TAU_ETA_3 =
    POW_2_MINUS_TAU * ETA_3; 

const std::vector<double>
    UltraLogLog::OptimalFGRAEstimator::ESTIMATION_FACTORS = {
        94.59941722950778,     455.6358404615186,
        2159.476860400962,    10149.51036338182,
        47499.52712820488,    221818.76564766388,
        1034754.6840013304,   4824374.384717942,
        2.2486750611989766E7, 1.0479810199493326E8,
        4.8837185623048025E8, 2.275794725435168E9,
        1.0604938814719946E10, 4.9417362104242645E10,
        2.30276227770117E11,  1.0730444972228585E12,
        5.0001829613164E12,   2.329988778511272E13,
        1.0857295240912981E14, 5.059288069986326E14,
        2.3575295235667005E15, 1.0985627213141412E16,
        5.1190876745155888E16, 2.38539483395717152E17};

const std::vector<double>
    UltraLogLog::OptimalFGRAEstimator::REGISTER_CONTRIBUTIONS = {
        0.8484061093359406,   0.38895829052007685, 0.5059986252327467,
        0.17873835725405993,  0.48074234060273024, 0.22040001471443574,
        0.2867199572932749,   0.10128061935935387, 0.2724086914332655,
        0.12488785473931466,  0.16246750447680292, 0.057389829555353204,
        0.15435814343988866,  0.0707666752272979,  0.09206087452057209,
        0.03251947467566813,  0.08746577181824695, 0.0400993542020493,
        0.05216553700867983,  0.018426892732996067, 0.04956175987398336,
        0.022721969094305374, 0.029559172293066274, 0.01044144713836362,
        0.02808376340530896,  0.012875216815740723, 0.01674946174724118,
        0.005916560101748389, 0.015913433441643893, 0.0072956356627506685,
        0.009490944673308844, 0.0033525700962450116, 0.009017216113341773,
        0.004134011914931561, 0.0053779657012946284, 0.0018997062578498703,
        0.005109531310944485, 0.002342503834183061,  0.00304738001114257,
        0.001076452918957914, 0.0028952738727082267, 0.0013273605219527246,
        0.0017267728074345586, 6.09963188753462E-4,  0.0016405831157217021,
        7.521379173550258E-4, 9.78461602292084E-4,   3.4563062172237723E-4,
        9.2962292270938E-4,   4.2619276177576713E-4, 5.544372155028133E-4,
        1.958487477192352E-4, 5.267631795945699E-4,  2.4149862146135835E-4,
        3.141672858847145E-4, 1.1097608132071735E-4, 2.9848602115777116E-4,
        1.3684320663902123E-4, 1.7802030736817869E-4, 6.288368329501905E-5,
        1.6913464774658265E-4, 7.754107700464113E-5,  1.0087374230011362E-4,
        3.563252169014952E-5, 9.583875639268212E-5,  4.393801322487549E-5,
        5.715927601779108E-5, 2.0190875207520577E-5, 5.430624268457414E-5,
        2.4897113642537945E-5, 3.2388833410757184E-5, 1.144099329232623E-5,
        3.0772185549154786E-5, 1.4107744575453653E-5, 1.8352865935237916E-5,
        6.482944704957522E-6, 1.7436805727319977E-5, 7.99403737572986E-6,
        1.0399500462555932E-5, 3.67350727106242E-6,  9.880422483694849E-6,
        4.529755498675165E-6, 5.892791363067244E-6,  2.081562667074589E-6,
        5.5986600976661345E-6, 2.5667486794686803E-6, 3.339101736056405E-6,
        1.1795003568090263E-6, 3.1724346748254955E-6,  1.4544270182973653E-6,
        1.8920745223756656E-6, 6.683541714686068E-7,  1.7976340035771381E-6,
        8.241391019206623E-7, 1.072128458850476E-6,  3.7871739159788393E-7,
        1.0186145159929963E-6, 4.6699164053601817E-7, 6.075127690181302E-7,
        2.1459709360913574E-7, 5.77189533646426E-7,  2.6461697039041317E-7,
        3.442421115430427E-7, 1.2159967724530947E-7, 3.27059699739513E-7,
        1.4994302882644454E-7, 1.9506195985170504E-7, 6.890345650764188E-8,
        1.853256875916027E-7, 8.49639834530526E-8,   1.1053025444979778E-7,
        3.904357664636507E-8, 1.0501327589016596E-7, 4.814414208323267E-8,
        6.263105916717392E-8, 2.2123721430020238E-8, 5.9504908663745294E-8,
        2.7280481949286693E-8, 3.548937430686624E-8,  1.2536224699555158E-8,
        3.371796684815404E-8, 1.545826061452554E-8,  2.0109761920695445E-8,
        7.103548569567803E-9, 1.910600846054063E-8,  8.759296176321385E-9,
        1.139503111580109E-8, 4.0251673442004705E-9, 1.082626247715867E-8,
        4.963383100969449E-9, 6.456900615837058E-9,  2.28082795382416E-9,
        6.134612546958812E-9, 2.812460192131048E-9,  3.65874960227048E-9,
        1.292412391857717E-9, 3.476127720042246E-9,  1.5936574250689536E-9,
        2.0732003554895977E-9, 7.323348470132607E-10, 1.9697191686598677E-9,
        9.030328662369446E-10, 1.1747619217600795E-9, 4.1497151491950363E-10,
        1.1161251587553774E-9, 5.116961428952198E-10, 6.656691762391315E-10,
        2.351401942661752E-10, 6.324431369849931E-10, 2.899484087937328E-10,
        3.771959611450379E-10, 1.3324025619025952E-10, 3.5836869940773545E-10,
        1.6429687995368037E-10, 2.1373498756237659E-10, 7.549949478033437E-11,
        2.0306667462222755E-10, 9.309747508122088E-11,  1.2111117194789844E-10,
        4.2781167456975155E-11, 1.1506606020637118E-10, 5.275291818652914E-11,
        6.86266490006118E-11,  2.424159650745726E-11,  6.520123617549523E-11,
        2.9892007004129765E-11, 3.888672595026375E-11,  1.3736301184893309E-11,
        3.6945743959497274E-11, 1.693805979747882E-11,  2.2034843273746723E-11,
        7.783562034953282E-12, 2.093500180037604E-11,  9.597812206565218E-12,
        1.248586262365167E-11, 4.4104913787558985E-12,  1.2998242223663023E-11,
        5.959143881034847E-15, 7.752292944665042E-15,  2.7384108113817744E-15,
        7.365346997814574E-15, 3.376699844369893E-15,  4.392773006047039E-15,
        1.5516979527951759E-15, 4.173513269314059E-15,  1.9133791810691354E-15,
        2.4891286772044455E-15, 8.792568765435867E-16};

double
UltraLogLog::OptimalFGRAEstimator::calculateTheoreticalRelativeStandardError(
    int p) {
  return std::sqrt(V / (1 << p));
}

double UltraLogLog::OptimalFGRAEstimator::smallRangeEstimate(int64_t c0,
                                                             int64_t c4,
                                                             int64_t c8,
                                                             int64_t c10,
                                                             int64_t m) {
  int64_t alpha = m + 3 * (c0 + c4 + c8 + c10);
  int64_t beta = m - c0 - c4;
  int64_t gamma = 4 * c0 + 2 * c4 + 3 * c8 + c10;

  double quadRootZ =
      (std::sqrt(static_cast<double>(beta) * beta + 4.0 * alpha * gamma) -
       beta) /
      (2.0 * alpha);
  double rootZ = quadRootZ * quadRootZ;
  return rootZ * rootZ;
}

double UltraLogLog::OptimalFGRAEstimator::largeRangeEstimate(int64_t c4w0,
                                                             int64_t c4w1,
                                                             int64_t c4w2,
                                                             int64_t c4w3,
                                                             int64_t m) {
  int64_t alpha = m + 3 * (c4w0 + c4w1 + c4w2 + c4w3);
  int64_t beta = c4w0 + c4w1 + 2 * (c4w2 + c4w3);
  int64_t gamma = m + 2 * c4w0 + c4w2 - c4w3;
  return std::sqrt(
      (std::sqrt(static_cast<double>(beta) * beta + 4.0 * alpha * gamma) -
       beta) /
      (2.0 * alpha));
}

double UltraLogLog::OptimalFGRAEstimator::psiPrime(double z, double zSquare) {
  return (z + ETA23X) * (zSquare + ETA13X) + ETA3012XX;
}

double UltraLogLog::OptimalFGRAEstimator::sigma(double z) {
  if (z <= 0.)
    return ETA_3;
  if (z >= 1.)
    return std::numeric_limits<double>::infinity(); // POSITIVE_INFINITY

  double powZ = z;
  double nextPowZ = powZ * powZ;
  double s = 0;
  double powTau = ETA_X;
  while (true) {
    double oldS = s;
    double nextNextPowZ = nextPowZ * nextPowZ;
    s += powTau * (powZ - nextPowZ) * psiPrime(nextPowZ, nextNextPowZ);
    if (!(s > oldS))
      return s / z;
    powZ = nextPowZ;
    nextPowZ = nextNextPowZ;
    powTau *= POW_2_TAU;
  }
}

double UltraLogLog::OptimalFGRAEstimator::calculateContribution0(int c0,
                                                                 double z) {
  return c0 * sigma(z);
}

double UltraLogLog::OptimalFGRAEstimator::calculateContribution4(int c4,
                                                                 double z) {
  return c4 * POW_2_MINUS_TAU_ETA_X * psiPrime(z, z * z);
}

double UltraLogLog::OptimalFGRAEstimator::calculateContribution8(int c8,
                                                                 double z) {
  return c8 * (z * POW_4_MINUS_TAU_ETA_01 + POW_4_MINUS_TAU_ETA_1);
}

double UltraLogLog::OptimalFGRAEstimator::calculateContribution10(int c10,
                                                                  double z) {
  return c10 * (z * POW_4_MINUS_TAU_ETA_23 + POW_4_MINUS_TAU_ETA_3);
}

double UltraLogLog::OptimalFGRAEstimator::phi(double z, double zSquare) {
  if (z <= 0.)
    return 0.;
  if (z >= 1.)
    return PHI_1;
  double previousPowZ = zSquare;
  double powZ = z;
  double nextPowZ = std::sqrt(powZ);
  double p = P_INITIAL / (1. + nextPowZ);
  double ps = psiPrime(powZ, previousPowZ);
  double s = nextPowZ * (ps + ps) * p;
  while (true) {
    previousPowZ = powZ;
    powZ = nextPowZ;
    double oldS = s;
    nextPowZ = std::sqrt(powZ);
    double nextPs = psiPrime(powZ, previousPowZ);
    p *= POW_2_MINUS_TAU / (1. + nextPowZ);
    s += nextPowZ * ((nextPs + nextPs) - (powZ + nextPowZ) * ps) * p;
    if (!(s > oldS))
      return s;
    ps = nextPs;
  }
}

double UltraLogLog::OptimalFGRAEstimator::calculateLargeRangeContribution(
    int c4w0, int c4w1, int c4w2, int c4w3, int m, int w) {

  double z = largeRangeEstimate(c4w0, c4w1, c4w2, c4w3, m);

  double rootZ = std::sqrt(z);
  double s = phi(rootZ, z) * (c4w0 + c4w1 + c4w2 + c4w3);
  s += z * (1 + rootZ) *
       (c4w0 * ETA_0 + c4w1 * ETA_1 + c4w2 * ETA_2 + c4w3 * ETA_3);
  s += rootZ *
       ((c4w0 + c4w1) * (z * POW_2_MINUS_TAU_ETA_02 + POW_2_MINUS_TAU_ETA_2) +
        (c4w2 + c4w3) * (z * POW_2_MINUS_TAU_ETA_13 + POW_2_MINUS_TAU_ETA_3));
  return s * std::pow(POW_2_MINUS_TAU, w) / ((1 + rootZ) * (1 + z));
}

double UltraLogLog::OptimalFGRAEstimator::estimate(
    const UltraLogLog &ultraLogLog) const {
  const std::vector<uint8_t> &state = ultraLogLog.state;
  const int m = state.size();
  const int p = ultraLogLog.getP();

  int c0 = 0;
  int c4 = 0;
  int c8 = 0;
  int c10 = 0;

  int c4w0 = 0;
  int c4w1 = 0;
  int c4w2 = 0;
  int c4w3 = 0;

  double sum = 0;
  int off = (p << 2) + 4;
  for (uint8_t reg : state) {
    int r = reg;
    int r2 = r - off;
    if (r2 < 0) {
      if (r2 < -8)
        c0 += 1;
      if (r2 == -8)
        c4 += 1;
      if (r2 == -4)
        c8 += 1;
      if (r2 == -2)
        c10 += 1;
    } else if (r < 252) {
      sum += REGISTER_CONTRIBUTIONS[r2];
    } else {
      if (r == 252)
        c4w0 += 1;
      if (r == 253)
        c4w1 += 1;
      if (r == 254)
        c4w2 += 1;
      if (r == 255)
        c4w3 += 1;
    }
  }

  if (c0 > 0 || c4 > 0 || c8 > 0 || c10 > 0) {
    double z = smallRangeEstimate(c0, c4, c8, c10, m);
    if (c0 > 0)
      sum += calculateContribution0(c0, z);
    if (c4 > 0)
      sum += calculateContribution4(c4, z);
    if (c8 > 0)
      sum += calculateContribution8(c8, z);
    if (c10 > 0)
      sum += calculateContribution10(c10, z);
  }

  if (c4w0 > 0 || c4w1 > 0 || c4w2 > 0 || c4w3 > 0) {
    sum += calculateLargeRangeContribution(c4w0, c4w1, c4w2, c4w3, m, 65 - p);
  }

  return ESTIMATION_FACTORS[p - MIN_P] * std::pow(sum, MINUS_INV_TAU);
}

} // namespace distinctcount
} // namespace hash4j
} // namespace dynatrace
