#!/usr/bin/env python3
"""
nmap-xml-merger.py
Combine Nmap XML files into one XML, de-duplicating hosts while preserving data.
Key goals:
- Single <host> per identity (by IP/hostname; configurable).
- Preserve all discovered data:
  * All <address> and <hostname> entries are kept (deduped by value).
  * All <port> entries are kept, unique by (protocol, portid).
  * For conflicting port states, prefer a configurable order (default: open > open|filtered > filtered > closed),
    but keep scripts/services from all sources. If attributes like 'reason' are present, we keep the chosen state's
    attributes and fill missing fields from alternates when possible.
  * Merge <os>, <hostscript>, <uptime>, <trace>, <times>, <tcpsequence>, <ipidsequence>, <tcptssequence> conservatively:
    keep the first seen section and add unique children if they have distinguishing attributes (e.g., id).
  * Keep all <script> under host and ports, dedup by id where possible.
- Produce a valid <nmaprun> document with synthesized <runstats>.
Usage examples:
  python nmap-xml-merger.py -f scan1.xml -f scan2.xml
  python nmap-xml-merger.py -d ./nmap_xmls
  python nmap-xml-merger.py -d ./nmap_xmls --dedupe-key hostname
  python nmap-xml-merger.py -d ./nmap_xmls --prefer-state "open,open|filtered,filtered,closed,unfiltered,closed|filtered"
"""
import os
import re
import sys
import logging
import argparse
import xml.etree.ElementTree as ET
from datetime import datetime
# ------------------------- utilities -------------------------
def parse_state_order(order_spec: str):
    parts = [p.strip().lower() for p in order_spec.split(",") if p.strip()]
    return {state: i for i, state in enumerate(parts)}
DEFAULT_STATE_ORDER = parse_state_order("open,open|filtered,unfiltered,filtered,closed,closed|filtered")
def better_state(a: str, b: str, order_map):
    a = (a or "").lower()
    b = (b or "").lower()
    if a == b:
        return a
    pa = order_map.get(a, 999)
    pb = order_map.get(b, 999)
    return a if pa <= pb else b
def ensure_child(parent, tag):
    c = parent.find(tag)
    if c is None:
        c = ET.Element(tag)
        parent.append(c)
    return c
def dedup_children_by_attribute(parent, tag, attr_name):
    seen = set()
    for child in list(parent.findall(tag)):
        key = child.get(attr_name)
        if key in seen:
            parent.remove(child)
        else:
            seen.add(key)
def serialize_element(elem):
    return ET.tostring(elem, encoding="unicode", method="xml")
def host_identity_key(host, mode="address"):
    """Return a stable dedupe key for a host."""
    mode = (mode or "address").lower()
    if mode == "address":
        # Prefer first ipv4/ipv6
        for addr in host.findall("address"):
            t = (addr.get("addrtype") or "").lower()
            if t in {"ipv4", "ipv6"}:
                v = (addr.get("addr") or "").strip()
                if v:
                    return f"{t}:{v}"
        # fallback hostname
        hn = host.find("hostnames/hostname")
        if hn is not None:
            name = (hn.get("name") or "").strip()
            if name:
                return f"hostname:{name.lower()}"
    elif mode == "hostname":
        hn = host.find("hostnames/hostname")
        if hn is not None:
            name = (hn.get("name") or "").strip()
            if name:
                return f"hostname:{name.lower()}"
        # fallback address
        for addr in host.findall("address"):
            t = (addr.get("addrtype") or "").lower()
            if t in {"ipv4", "ipv6"}:
                v = (addr.get("addr") or "").strip()
                if v:
                    return f"{t}:{v}"
    # As a last resort, try MAC (not ideal as identity)
    for addr in host.findall("address"):
        t = (addr.get("addrtype") or "").lower()
        if t == "mac":
            v = (addr.get("addr") or "").strip()
            if v:
                return f"mac:{v}"
    return None
# ------------------------- merging primitives -------------------------
def union_addresses(dst_host, src_host):
    dst = dst_host
    existing = {(a.get("addr",""), a.get("addrtype","").lower(), a.get("vendor",""))
                for a in dst.findall("address")}
    for a in src_host.findall("address"):
        key = (a.get("addr",""), a.get("addrtype","").lower(), a.get("vendor",""))
        if key not in existing:
            dst.append(a)
            existing.add(key)
def union_hostnames(dst_host, src_host):
    dst_hns = ensure_child(dst_host, "hostnames")
    existing = {(h.get("name","").lower(), h.get("type","")) for h in dst_hns.findall("hostname")}
    src_hns = src_host.find("hostnames")
    if src_hns is None:
        return
    for h in src_hns.findall("hostname"):
        key = ((h.get("name","") or "").lower(), h.get("type",""))
        if key not in existing:
            dst_hns.append(h)
            existing.add(key)
def merge_status(dst_host, src_host):
    ds = dst_host.find("status")
    ss = src_host.find("status")
    if ss is None and ds is None:
        return
    if ds is None:
        dst_host.append(ss)
        return
    if ss is None:
        return
    # prefer "up" if any is up; else keep existing state
    ds_state = (ds.get("state") or "").lower()
    ss_state = (ss.get("state") or "").lower()
    if ss_state == "up" and ds_state != "up":
        # replace state and copy attributes if present
        for k, v in ss.attrib.items():
            ds.set(k, v)
def ensure_ports(dst_host):
    return ensure_child(dst_host, "ports")
def port_key(p):
    return ((p.get("protocol") or "").lower(), (p.get("portid") or ""))
def merge_port_states(dst_port, src_port, state_order):
    ds = dst_port.find("state")
    ss = src_port.find("state")
    if ds is None and ss is None:
        return
    if ds is None:
        # copy full state element
        dst_port.append(ss)
        return
    if ss is None:
        return
    best = better_state(ds.get("state"), ss.get("state"), state_order)
    # preserve attributes from the chosen best; fill missing attrs from the other
    if best.lower() != (ds.get("state") or "").lower():
        # replace ds attributes with ss attributes (chosen)
        ds.attrib.clear()
        for k, v in ss.attrib.items():
            ds.set(k, v)
    else:
        # keep ds as main; add any missing attributes from ss
        for k, v in ss.attrib.items():
            if k not in ds.attrib:
                ds.set(k, v)
def merge_service(dst_port, src_port):
    dsvc = dst_port.find("service")
    ssvc = src_port.find("service")
    if dsvc is None and ssvc is None:
        return
    if dsvc is None:
        dst_port.append(ssvc)
        return
    if ssvc is None:
        return
    # Choose the richer service (more attributes); then fill missing attrs
    if len(ssvc.attrib) > len(dsvc.attrib):
        # swap by replacing attributes
        dsvc.attrib.clear()
        for k, v in ssvc.attrib.items():
            dsvc.set(k, v)
    else:
        # add any missing attributes from src
        for k, v in ssvc.attrib.items():
            if k not in dsvc.attrib:
                dsvc.set(k, v)
def union_scripts(dst_elem, src_elem):
    # dedup by script id if present; otherwise dedup by (id, output)
    existing = set()
    for s in dst_elem.findall("script"):
        key = (s.get("id"), s.get("output"))
        existing.add(key)
    for s in src_elem.findall("script"):
        key = (s.get("id"), s.get("output"))
        if key not in existing:
            dst_elem.append(s)
            existing.add(key)
def merge_ports(dst_host, src_host, state_order):
    dp = ensure_ports(dst_host)
    sp = src_host.find("ports")
    if sp is None:
        return
    # build index for existing ports
    idx = {}
    for p in dp.findall("port"):
        idx[port_key(p)] = p
    for p in sp.findall("port"):
        k = port_key(p)
        if k not in idx:
            dp.append(p)
            idx[k] = p
        else:
            dp_port = idx[k]
            merge_port_states(dp_port, p, state_order)
            merge_service(dp_port, p)
            union_scripts(dp_port, p) # scripts under <port>
    # merge any "extraports" blocks if not already present with same attributes
    existing_extra = {serialize_element(e) for e in dp.findall("extraports")}
    for e in sp.findall("extraports"):
        se = serialize_element(e)
        if se not in existing_extra:
            dp.append(e)
            existing_extra.add(se)
def merge_os(dst_host, src_host):
    if src_host.find("os") is None:
        return
    d = dst_host.find("os")
    if d is None:
        dst_host.append(src_host.find("os"))
        return
    # union osclass and osmatch by a simple serialized signature
    seen = {serialize_element(x) for x in d}
    for x in src_host.find("os"):
        sx = serialize_element(x)
        if sx not in seen:
            d.append(x)
            seen.add(sx)
def merge_hostscript(dst_host, src_host):
    sh = src_host.find("hostscript")
    if sh is None:
        return
    dh = dst_host.find("hostscript")
    if dh is None:
        dst_host.append(sh)
        return
    union_scripts(dh, sh)
def merge_misc_sections(dst_host, src_host, tags):
    """Copy sections if not present; if present, append unique children when meaningful."""
    for tag in tags:
        s = src_host.find(tag)
        if s is None:
            continue
        d = dst_host.find(tag)
        if d is None:
            dst_host.append(s)
            continue
        # try to union by distinguishing attributes or serialized child elements
        seen = {serialize_element(x) for x in d}
        for x in s:
            sx = serialize_element(x)
            if sx not in seen:
                d.append(x)
                seen.add(sx)
def merge_host(dst_host, src_host, state_order):
    union_addresses(dst_host, src_host)
    union_hostnames(dst_host, src_host)
    merge_status(dst_host, src_host)
    merge_ports(dst_host, src_host, state_order)
    merge_os(dst_host, src_host)
    merge_hostscript(dst_host, src_host)
    merge_misc_sections(dst_host, src_host,
                        tags=["uptime","times","trace","tcpsequence","ipidsequence","tcptssequence"])
# ------------------------- document synthesis -------------------------
def synthesize_root():
    root = ET.Element("nmaprun", {
        "scanner":"nmap",
        "args":"merged",
        "start": str(int(datetime.now().timestamp())),
        "startstr": datetime.now().isoformat(timespec="seconds"),
        "version":"merged",
        "xmloutputversion":"1.04"
    })
    root.append(ET.Comment("Merged by nMapMerge (dedupe+preserve)"))
    ET.SubElement(root, "verbose", {"level":"0"})
    ET.SubElement(root, "debugging", {"level":"0"})
    return root
def add_runstats(root, total_hosts):
    runstats = ET.SubElement(root, "runstats")
    ET.SubElement(runstats, "finished", {
        "time": str(int(datetime.now().timestamp())),
        "timestr": datetime.now().isoformat(timespec="seconds"),
        "elapsed":"0",
        "summary": f"Nmap merge complete; {total_hosts} unique host(s).",
        "exit":"success"
    })
def write_pretty(tree, out_path):
    # Python 3.9+ has ET.indent
    try:
        ET.indent(tree, space=" ") # type: ignore[attr-defined]
    except Exception:
        pass
    tree.write(out_path, encoding="utf-8", xml_declaration=True)
def xslt_to_html(xml_path, xsl_path=None):
    cmd = "/usr/bin/xsltproc"
    if not os.path.isfile(cmd):
        return None
    if not xsl_path or not os.path.isfile(xsl_path):
        return None
    out = re.sub(r"\.xml$", ".html", xml_path, flags=re.IGNORECASE)
    os.system(f'{cmd} -o "{out}" "{xsl_path}" "{xml_path}"')
    if os.path.isfile(out):
        return os.path.abspath(out)
    return None
# ------------------------- main -------------------------
def read_hosts_from_file(path):
    tree = ET.parse(path)
    root = tree.getroot()
    if root.tag == "nmaprun":
        hosts = root.findall("host")
    else:
        hosts = root.findall(".//host")
    return hosts
def main():
    ap = argparse.ArgumentParser(description="Merge Nmap XML files with host de-duplication while preserving data.")
    ap.add_argument("-f", "--file", dest="files", metavar="FILE", action="append",
                    help="Nmap XML file (can be provided multiple times)")
    ap.add_argument("-d", "--dir", dest="directory", metavar="DIR",
                    help="Directory containing Nmap XML files")
    ap.add_argument("-o", "--output", dest="output", metavar="OUT_XML",
                    help="Output XML filename (default: nMap_Merged_<timestamp>.xml)")
    ap.add_argument("-k", "--dedupe-key", dest="dedupe_key", default="address",
                    choices=["address","hostname"], help="Host identity key (default: address)")
    ap.add_argument("--prefer-state", dest="prefer_state",
                    default="open,open|filtered,unfiltered,filtered,closed,closed|filtered",
                    help="Comma-separated state preference order (best first)")
    ap.add_argument("-q", "--quiet", dest="verbose", action="store_false", default=True,
                    help="Don't print status messages to stdout")
    ap.add_argument("--no-html", action="store_true", help="Don't attempt to generate HTML via xsltproc")
    ap.add_argument("--xsl-file", dest="xsl_file", metavar="XSL_PATH",
                    help="Path to XSL stylesheet for HTML conversion (requires xsltproc)")
    args = ap.parse_args()
    if args.verbose:
        logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')
        print("Debug On")
    # collect files
    paths = []
    if args.files:
        for f in args.files:
            if f and f.lower().endswith(".xml"):
                if os.path.isfile(f):
                    paths.append(f)
                else:
                    logging.warning("File does not exist: %r", f)
    if args.directory:
        if os.path.isdir(args.directory):
            for name in os.listdir(args.directory):
                if name.lower().endswith(".xml"):
                    paths.append(os.path.join(args.directory, name))
        else:
            logging.warning("Not a directory: %r", args.directory)
    if not paths:
        print("No XML files were found ... No work to do")
        sys.exit(1)
    state_order = parse_state_order(args.prefer_state) if args.prefer_state else DEFAULT_STATE_ORDER
    # output name
    if args.output:
        out_xml = args.output
    else:
        dt = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        out_xml = f"nMap_Merged_{dt}.xml"
    root = synthesize_root()
    unique = {} # key -> host element
    total_input_hosts = 0
    for p in paths:
        try:
            hosts = read_hosts_from_file(p)
        except ET.ParseError as e:
            logging.error("Skipping %s due to parse error: %s", p, e)
            continue
        logging.debug("Parsing: %r (%d host(s))", p, len(hosts))
        for h in hosts:
            total_input_hosts += 1
            key = host_identity_key(h, args.dedupe_key)
            if key is None:
                # If no identity can be built, append as-is (avoid data loss)
                # but still ensure uniqueness by serialized value
                ser = serialize_element(h)
                if ser not in unique:
                    # use serialized xml as key to prevent duplicates
                    unique[ser] = h
                    root.append(h)
                continue
            if key not in unique:
                unique[key] = h
                root.append(h)
            else:
                merge_host(unique[key], h, state_order)
    add_runstats(root, total_hosts=len([c for c in root if c.tag == "host"]))
    tree = ET.ElementTree(root)
    write_pretty(tree, out_xml)
    print("")
    print("Input XML files:", len(paths))
    print("Total input <host> elements:", total_input_hosts)
    print("Unique hosts written:", len([c for c in root if c.tag == "host"]))
    print("Output XML File:", os.path.abspath(out_xml))
    if not args.no_html:
        html = xslt_to_html(out_xml, args.xsl_file)
        if html:
            print("Output HTML File:", html)
        else:
            print("HTML conversion skipped (xsltproc not found or XSL file not provided/valid).")
if __name__ == "__main__":
    if sys.version_info <= (3, 0):
        sys.stdout.write("This script requires Python 3.x\n")
        sys.exit(1)
    main()
