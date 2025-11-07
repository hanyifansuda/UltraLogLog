// main.cpp
#include "UltraLogLog.hpp"
#include <iostream>
#include <fstream>
#include <sstream>
#include <vector>
#include <cmath>
#include <ctime>
#include <cstdlib>
#include <iomanip>

#include <random>

std::mt19937_64 rng(std::random_device{}());
std::uniform_int_distribution<uint64_t> dist;


int main() {

    using namespace dynatrace::hash4j::distinctcount;
    using namespace std;

    int memory = 463;
    double log_val = std::log2(memory / 8.0);

    double ceil_val = std::ceil(log_val);

    int p = static_cast<int>(ceil_val);
    
    const int NF_ACTUAL_CARDINALITY = 1000000000;
    const int EPOCHS = 1000; 
    
    UltraLogLog initialSketch = UltraLogLog::create(p);
    const int numRegisters = 1 << p;

    cout << "--- UltraLogLog settings ---" << endl;
    cout << "Calculated p: " << p << endl;
    cout << "Number of Registers (2^p): " << numRegisters << endl;
    cout << "Actual Cardinality (nf): " << NF_ACTUAL_CARDINALITY << endl;
    cout << "Number of Epochs: " << EPOCHS << endl;
    cout << "-----------------------------" << endl;

    int nf = NF_ACTUAL_CARDINALITY;

    std::vector<double> resultRatioList;

    std::srand(static_cast<unsigned>(std::time(NULL)));
    
    for (int epoch = 0; epoch < EPOCHS; ++epoch) {
        
        UltraLogLog sketch = UltraLogLog::create(p); 
        
        for (int64_t i = 1; i <= nf; ++i) {
            uint64_t x = dist(rng);
            sketch.add(x);
        }

        double estimate = sketch.getDistinctCountEstimate();

        resultRatioList.push_back(estimate / nf);

        if (epoch % (EPOCHS / 10) == 0 && EPOCHS >= 10) {
            std::cout << "Progress: " << (epoch * 100 / EPOCHS) << "%\r" << std::flush;
        }
    }
    std::cout << "Progress: 100%" << std::endl;

    std::ostringstream filenameStream;
    filenameStream << "./extend_results/m=" << memory << "_n=" << nf << "_p=" << p << ".txt";
    
    std::string filename = filenameStream.str();

    std::ofstream outFile(filename);

    if (outFile.is_open()) {
        outFile << std::fixed << std::setprecision(6);
        for (const auto& ratio : resultRatioList) {
            outFile << ratio << std::endl;
        }
        outFile.close();
        std::cout << "Results saved to: " << filename << std::endl;
    } else {
        std::cerr << "Error: Could not open file for writing at " << filename << std::endl;
        std::cerr << "Please ensure the directory './extend_results_ull/' exists." << std::endl;
    }

    return 0;
}