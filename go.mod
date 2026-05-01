module golang.zx2c4.com/wireguard

go 1.26.1

require (
	github.com/miniusercoder/bee2go v0.0.0
	golang.org/x/net v0.39.0
	golang.org/x/sys v0.32.0
	golang.zx2c4.com/wintun v0.0.0-20230126152724-0fa3db229ce2
	gvisor.dev/gvisor v0.0.0-20250503011706-39ed1f5ac29c
)

replace github.com/miniusercoder/bee2go => ./bee2go

require (
	github.com/google/btree v1.1.2 // indirect
	golang.org/x/time v0.7.0 // indirect
)
