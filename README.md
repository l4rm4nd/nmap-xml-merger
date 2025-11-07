# nmap-xml-merger
Python3 script to merge Nmap XML files and de-duplicate results

```bash
usage: nmap-xml-merger.py [-h] [-f FILE] [-d DIR] [-o OUT_XML] [-k {address,hostname}] [--prefer-state PREFER_STATE]
                          [-q] [--no-html] [--xsl-file XSL_PATH]

Merge Nmap XML files with host de-duplication while preserving data.

options:
  -h, --help            show this help message and exit
  -f, --file FILE       Nmap XML file (can be provided multiple times)
  -d, --dir DIR         Directory containing Nmap XML files
  -o, --output OUT_XML  Output XML filename (default: nMap_Merged_<timestamp>.xml)
  -k, --dedupe-key {address,hostname}
                        Host identity key (default: address)
  --prefer-state PREFER_STATE
                        Comma-separated state preference order (best first)
  -q, --quiet           Don't print status messages to stdout
  --no-html             Don't attempt to generate HTML via xsltproc
  --xsl-file XSL_PATH   Path to XSL stylesheet for HTML conversion (requires xsltproc)
```
