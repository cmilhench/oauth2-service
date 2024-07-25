package main

import (
	_ "embed" // The "embed" package must be imported when using go:embed
)

//go:generate sh -c "./scripts/version.sh > .version"
//go:embed .version
var Revision string
