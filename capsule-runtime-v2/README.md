### run

install cli with

```bash
cargo install --path cli --force
capsule run {program}
```

### maintenance

Most of what is added to the project
will be a new lib. Libs have no main.

create a new lib with

```bash
cargo new --lib libname
```

and a new bin with

```bash
cargo new --bin binname
```

though, the cli should be the only bin.
