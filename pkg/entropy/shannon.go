package entropy

import (
	"math"
)

const (
	DefaultBase64EntropyThreshold = 4.5
	DefaultHexEntropyThreshold    = 3.0
)

// Shannon calculates the Shannon entropy of a given string.
// Formula: H(X) = - sum(P(x) * log2(P(x)))
func Shannon(s string) float64 {
	if len(s) == 0 {
		return 0.0
	}

	freq := make(map[rune]float64)
	for _, r := range s {
		freq[r]++
	}

	var h float64
	lenF := float64(len([]rune(s)))
	for _, count := range freq {
		p := count / lenF
		h -= p * math.Log2(p)
	}

	return h
}

// CharacterClassEntropy evaluates entropy against expected character distribution
func CharacterClassEntropy(s string) (shannon float64, isHighEntropy bool) {
	shannon = Shannon(s)
	if len(s) >= 16 && shannon >= DefaultBase64EntropyThreshold {
		return shannon, true
	}
	if len(s) >= 32 && shannon >= DefaultHexEntropyThreshold {
		return shannon, true
	}
	return shannon, false
}