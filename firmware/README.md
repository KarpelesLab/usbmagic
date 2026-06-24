# firmware/

Prebuilt Cynthion gateware bitstreams (`*.bit`), vendored here via **Git LFS**, so
`usbmagic` ships a known-good bitstream and can flash the board out of the box
(`usbmagic flash`).

These are **built artifacts** — the source lives in
[`KarpelesLab/usbmagic-gateware`](https://github.com/KarpelesLab/usbmagic-gateware),
which builds them reproducibly in Docker via GitHub Actions.

## Updating

Pull the latest built bitstream from the gateware repo (needs `gh`):

```sh
scripts/pull-gateware.sh        # downloads *.bit into firmware/
```

Then record what was pulled in [`VERSION`](VERSION), and commit (the `.bit` goes
to LFS automatically via `.gitattributes`).

> No `.bit` is committed yet — pull one after the first `usbmagic-gateware` build
> completes.
