# Threat-intel feeds

Every `*.txt` file in this directory is loaded as a feed named after the file:
one IP or CIDR per line, with `#` or `;` starting a comment.

Download public feeds with:

```bash
python scripts/update_intel.py
```

Downloaded feeds are git-ignored. A demo feed for the sample scenario lives in
`samples/intel/`.
