# ZigcloneDX

CycloneDX SBOM generator for Zig.

> Please note that this project is WIP, i.e., a lot of features are missing and
> the interface will most likely change.

## Getting Started

Add the following to your `build.zig.zon`.

```zig
.zigclonedx = .{
    .url = "https://github.com/r4gus/zigclonedx/archive/refs/heads/master.tar.gz",
    .hash = "122036a7c96a6a285882cd9598a2c28222c018c117beb1b2bdeb29fb0e7b035ee700",
}
```

> Don't forget to change the hash if applicable.

Then in your `build.zig` import `zigclonedx`.

```zig
const zigclonedx: type = @import("zigclonedx");
```

Within you `build` function add the following.

```zig
pub fn build(b: *std.Build) !void {
    // ...
    
    // Create a BOM from std.Build
    //
    // As there is currently no support for reading `build.zig.zon`
    // one must, among other things, define the version manually.
    //
    // The main component of the BOM is the project itself. Modules,
    // Libraries and Executables are added as (sub-)components, e.g.,
    // the uuid project consists of exactly one module also called uuid.
    var bom = try zigclonedx.CycloneDX.fromBuild(b, .{
        .type = .library,
        .name = "uuid",
        .group = "thesugar.de",
        .version = "0.2.1",
        .allocator = b.allocator,
        .authors = &.{
            .{
                .name = "David P. Sugar",
                .email = "david@thesugar.de",
            },
        },
    });
    defer bom.deinit(b.allocator);
    
    // To generate the BOM call `toJson`.
    const bom_string = try bom.toJson(b.allocator);
    defer b.allocator.free(bom_string);
    
    // You can now write the BOM to file, print it, or do
    // whatever you want with it.
    std.debug.print("{s}\n", .{bom_string}); 

    // ...
}
```

For `https://github.com/r4gus/uuid-zig` this will create something like the following:

```json
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "serialNumber": "urn:uuid:5660989d-12d3-4ad1-8ca0-242c4169123d",
  "version": 1,
  "metadata": {
    "tools": [
      {
        "type": "library",
        "name": "zigclonedx",
        "version": "0.1.0-alpha",
        "description": "Generate CycloneDX SBOMs for your Zig projects.",
        "externalReferences": [
          {
            "url": "https://github.com/r4gus/zigclonedx",
            "comment": "CycloneDX SBOM generator for Zig.",
            "type": "vcs"
          }
        ]
      }
    ],
    "component": {
      "type": "library",
      "bom-ref": "thesugar.de/uuid-0.2.1",
      "authors": [
        {
          "name": "David P. Sugar",
          "email": "david@thesugar.de"
        }
      ],
      "group": "thesugar.de",
      "name": "uuid",
      "version": "0.2.1",
      "components": [
        {
          "type": "library",
          "bom-ref": "thesugar.de/module/uuid-0.2.1",
          "group": "thesugar.de",
          "name": "uuid",
          "version": "0.2.1",
          "description": "Zig module"
        }
      ]
    }
  }
}
```
