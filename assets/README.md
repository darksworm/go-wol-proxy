# Logo assets

`doormouse.svg` is the logo — transparent, scalable, 541×415 at its natural
size. It is the only artwork the repo carries; export a raster from it if you
need one.

## Colors

`doormouse.svg` carries a fixed palette that clears 4:1 contrast on white,
`#F6F8FA`, `#0D1117` and `#0C0E14`, so it stays legible on any background
without knowing which one it landed on:

- neutral `#737884`
- accent `#8467C9`

It deliberately does **not** use `prefers-color-scheme`, which follows the OS
theme rather than the background the logo actually sits on — a light page viewed
with a dark OS theme would paint the logo white on white.

Inlined in HTML the artwork does better than the fixed palette: `#dm-neutral`
follows the page's `color`, and `--dm-accent` recolors the accent.

```html
<!-- safe anywhere -->
<img src="assets/doormouse.svg" alt="doormouse" width="400">
```

```html
<!-- inlined: picks up the surrounding theme -->
<span style="color: #F8F8F8; --dm-accent: #9079D0">
  <svg>…</svg>
</span>
```
