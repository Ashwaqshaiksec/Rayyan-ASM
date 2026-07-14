// This is a module-boundary marker, not a real Go module — frontend/ has
// no .go files of its own. Without it, `go build ./...` / `go vet ./...` /
// `go test ./...` run from the repo root descend into frontend/node_modules
// looking for Go packages, because one npm package (flatted) ships a stray
// "golang/" subfolder with a .go file in it. Declaring frontend/ as its own
// (empty, unused) module stops the root module's `./...` from walking into
// node_modules at all, regardless of what npm installs there or when.
module rayyan-asm-frontend-boundary

go 1.22
