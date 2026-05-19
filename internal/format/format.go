// Package format provides shared formatting helpers used by both the
// commands layer and the network layer. Pulling these into a dedicated
// package keeps the implementations in lockstep — divergence between two
// near-identical copies was a real source of subtle UI inconsistencies.
package format

import "fmt"

// Size renders a byte count as a human-friendly string ("12.3 MB"). Uses
// decimal SI units (1 kB = 1000 B) to match how operating systems display
// sizes in their file managers; users can mentally compare against those.
func Size(size int64) string {
	const unit = 1000
	if size < unit {
		return fmt.Sprintf("%d B", size)
	}
	div, exp := int64(unit), 0
	for n := size / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(size)/float64(div), "KMGTPE"[exp])
}
