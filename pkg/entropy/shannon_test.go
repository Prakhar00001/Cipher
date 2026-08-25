package entropy

import (
	"testing"
)

func TestShannon(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		minScore float64
		maxScore float64
	}{
		{"Empty string", "", 0.0, 0.0},
		{"Low entropy repeated chars", "aaaaaaaaaaaa", 0.0, 0.1},
		{"English sentence", "The quick brown fox jumps over the lazy dog", 3.5, 4.6},
		{"High entropy base64 token", "dGhpcy1pcy1hLXJlYWxseS1zZWNyZXQtdG9rZW4tMTIzNDU2", 4.3, 5.0},
		{"High entropy random hex", "4f9a2c1b8e7d6f5a3b2c1e0f8a7b6c5d", 3.2, 4.0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Shannon(tt.input)
			if got < tt.minScore || got > tt.maxScore {
				t.Errorf("Shannon(%q) = %v, expected between %v and %v", tt.input, got, tt.minScore, tt.maxScore)
			}
		})
	}
}