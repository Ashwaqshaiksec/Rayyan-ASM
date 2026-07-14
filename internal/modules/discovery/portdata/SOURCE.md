# Port Data Source

`top1000_tcp.txt` is a comma-separated list of the 1,000 TCP ports with the
highest open-frequency, derived from Nmap's `nmap-services` database
(https://github.com/nmap/nmap, `nmap-services` file) — the same data source
`nmap --top-ports 1000` uses. Distributed under the Nmap Public Source
License; only the resulting port *numbers* (not the full nmap-services file,
service names, or comments) are embedded here.

Backs `Options.PortProfile = "top1000"` in `ports.go`.
