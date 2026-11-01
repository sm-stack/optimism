package types

import _ "embed"

// LeanVmTreeClassKey is the leanVM tree class key whose digest is LeanVmTreeClassKeyDigest: the
// dimensions of the class's circuits and the commitments to their fixed polynomials, which a
// root's seal opens against, in about 1 KB. op-leanvm-tree's class_key example writes it
// (`cd rust && just leanvm-class-key`), and a test there checks this copy is the class it builds.
//
//go:embed leanvm_class_key.bin
var LeanVmTreeClassKey []byte
