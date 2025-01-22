const std = @import("std");
const Allocator = std.mem.Allocator;

const VERSION = "0.1.0-alpha";
const NAME = "zigclonedx";

pub const CycloneDX = struct {
    /// Specifies the format of the BOM. This helps to identify
    /// the file as CycloneDX since BOMs do not have a filename
    /// convention, nor does JSON schema support namespaces.
    bomFormat: []const u8 = "CycloneDX",
    /// The version of the CycloneDX specification the BOM conforms to.
    specVersion: []const u8 = "1.6",
    /// Every BOM generated SHOULD have a unique serial number, even if
    /// the contents of the BOM have not changed over time. If specified,
    /// the serial number must conform to RFC 4122. Use of serial numbers
    /// is recommended.
    serialNumber: [45]u8,
    /// Whenever an existing BOM is modified, either manually or through
    /// automated processes, the version of the BOM SHOULD be incremented
    /// by 1. When a system is presented with multiple BOMs with identical
    /// serial numbers, the system SHOULD use the most recent version of the
    /// BOM. The default version is '1'.
    version: usize = 1,
    /// Provides additional information about a BOM.
    metadata: ?struct {
        tools: ?[]const Component = null,
        component: ?Component = null,

        pub fn deinit(self: *const @This(), allocator: Allocator) void {
            if (self.component) |component| component.deinit(allocator);
        }
    } = null,

    pub const Component = struct {
        /// Specifies the type of component.
        type: Type,
        /// The optional mime-type of the component. When used on file components,
        /// the mime-type can provide additional context about the kind of file
        /// being represented, such as an image, font, or executable. Some library
        /// or framework components may also have an associated mime-type.
        @"mime-type": ?[]const u8 = null,
        /// An optional identifier which can be used to reference the component
        /// elsewhere in the BOM. Every bom-ref must be unique within the BOM.
        /// Value SHOULD not start with the BOM-Link intro 'urn:cdx:' to avoid
        /// conflicts with BOM-Links.
        @"bom-ref": ?[]const u8 = null,
        /// The person(s) who created the component. Authors are common in
        /// components created through manual processes.
        authors: ?[]Author = null,
        /// The person(s) or organization(s) that published the component.
        publisher: ?[]const u8 = null,
        /// The grouping name or identifier. This will often be a shortened,
        /// single name of the company or project that produced the component,
        /// or the source package or domain name. Whitespace and special characters
        /// should be avoided. Examples include: apache, org.apache.commons,
        /// and apache.org.
        group: ?[]const u8 = null,
        /// The name of the component. This will often be a shortened, single
        /// name of the component. Examples: commons-lang3 and jquery.
        name: []const u8,
        /// The component version. The version should ideally comply with semantic
        /// versioning but is not enforced.
        version: ?[]const u8 = null,
        /// Specifies a description for the component.
        description: ?[]const u8 = null,
        /// Specifies the scope of the component. If scope is not specified,
        /// 'required' scope SHOULD be assumed by the consumer of the BOM.
        scope: ?Scope = null,
        /// The hashes of the component.
        hashes: ?[]const Hash = null,
        /// A list of software and hardware components included in the parent
        /// component. This is not a dependency tree. It provides a way to
        /// specify a hierarchical representation of component assemblies,
        /// similar to system → subsystem → parts assembly in physical supply chains.
        ///
        /// For Zig this could mean a project consisting of a build.zig,
        /// build.zig.zon, and corresponding source code, where build.zig
        /// defines multiple executables, modules, or libraries, e.g.: a
        /// a KDBX repository that consists of a library and an command line
        /// application to manipulate KDBX files.
        components: ?[]const @This() = null,
        /// External references provide a way to document systems, sites, and
        /// information that may be relevant but are not included with the BOM.
        /// They may also establish specific relationships within or external
        /// to the BOM.
        externalReferences: ?[]Reference = null,

        pub const Reference = struct {
            /// The URI (URL or URN) to the external reference. External references
            /// are URIs and therefore can accept any URL scheme including https
            /// (RFC-7230), mailto (RFC-2368), tel (RFC-3966), and dns (RFC-4501).
            /// External references may also include formally registered URNs such
            /// as CycloneDX BOM-Link to reference CycloneDX BOMs or any object within
            /// a BOM. BOM-Link transforms applicable external references into
            /// relationships that can be expressed in a BOM or across BOMs.
            url: []const u8,
            /// An optional comment describing the external reference.
            comment: ?[]const u8 = null,
            /// Specifies the type of external reference.
            type: @This().Type,

            pub const Type = enum {
                /// Version Control System (e.g. Git)
                vcs,
                @"issue-tracker",
                website,
                advisories,
                bom,
                @"mailing-list",
                social,
                chat,
                documentation,
                support,
                @"source-distribution",
                distribution,
                @"distribution-intake",
                license,
                @"build-meta",
                @"build-system",
                @"release-notes",
                @"security-contact",
                @"model-card",
                log,
                configuration,
                evidence,
                formulation,
                attestation,
                @"threat-model",
                @"adversary-model",
                @"risk-assessment",
                @"vulnerability-assertion",
                @"exploitability-statement",
                @"pentest-report",
                @"static-analysis-report",
                @"dynamic-analysis-report",
                @"runtime-analysis-report",
                @"component-analysis-report",
                @"maturity-report",
                @"certification-report",
                @"codified-infrastructure",
                @"quality-metrics",
                poam,
                @"electronic-signature",
                @"rfc-9116",
                other,
            };
        };

        /// Specifies the type of component. For software components, classify
        /// as application if no more specific appropriate classification is
        /// available or cannot be determined for the component.
        pub const Type = enum {
            application,
            framework,
            library,
            container,
            platform,
            @"operating-system",
            device,
            @"device-driver",
            firmware,
            file,
            @"machine-learning-model",
            data,
            @"cryptographic-asset",
        };

        pub const Author = struct {
            @"bom-ref": ?[]const u8 = null,
            /// The name of a contact
            name: ?[]const u8 = null,
            /// The email address of the contact.
            email: ?[]const u8 = null,
            /// The phone number of the contact.
            phone: ?[]const u8 = null,

            pub fn deinit(self: *const @This(), allocator: Allocator) void {
                if (self.@"bom-ref") |d| allocator.free(d);
                if (self.name) |d| allocator.free(d);
                if (self.email) |d| allocator.free(d);
                if (self.phone) |d| allocator.free(d);
            }

            pub fn clone(self: *const @This(), allocator: Allocator) !@This() {
                const @"bom-ref" = if (self.@"bom-ref") |br| try allocator.dupe(u8, br) else null;
                errdefer if (@"bom-ref") |br| allocator.free(br);
                const name = if (self.name) |br| try allocator.dupe(u8, br) else null;
                errdefer if (name) |br| allocator.free(br);
                const email = if (self.email) |br| try allocator.dupe(u8, br) else null;
                errdefer if (email) |br| allocator.free(br);
                const phone = if (self.phone) |br| try allocator.dupe(u8, br) else null;
                errdefer if (phone) |br| allocator.free(br);

                return .{
                    .@"bom-ref" = @"bom-ref",
                    .name = name,
                    .email = email,
                    .phone = phone,
                };
            }
        };

        pub const Scope = enum {
            /// The component is required for runtime.
            required,
            /// The component is optional at runtime. Optional components are
            /// components that are not capable of being called due to them not
            /// being installed or otherwise accessible by any means. Components
            /// that are installed but due to configuration or other restrictions
            /// are prohibited from being called must be scoped as 'required'.
            optional,
            /// Components that are excluded provide the ability to document component
            /// usage for test and other non-runtime purposes. Excluded components are
            /// not reachable within a call graph at runtime.
            excluded,
        };

        pub const Hash = struct {
            /// The algorithm that generated the hash value.
            alg: Alg,
            /// The value of the hash as hex-string.
            content: []const u8,

            pub const Alg = enum {
                MD5,
                @"SHA-1",
                @"SHA-256",
                @"SHA-384",
                @"SHA-512",
                @"SHA3-256",
                @"SHA3-384",
                @"SHA3-512",
                @"BLAKE2b-256",
                @"BLAKE2b-384",
                @"BLAKE2b-512",
                BLAKE3,
            };

            pub fn deinit(self: *const @This(), allocator: Allocator) void {
                allocator.free(self.content);
            }
        };

        pub fn deinit(self: *const @This(), allocator: Allocator) void {
            if (self.@"mime-type") |d| allocator.free(d);
            if (self.@"bom-ref") |d| allocator.free(d);
            if (self.authors) |authors| {
                for (authors) |author| author.deinit(allocator);
                allocator.free(authors);
            }
            if (self.publisher) |d| allocator.free(d);
            if (self.group) |d| allocator.free(d);
            allocator.free(self.name);
            if (self.version) |d| allocator.free(d);
            if (self.description) |d| allocator.free(d);
            if (self.hashes) |hashes| {
                for (hashes) |hash| hash.deinit(allocator);
                allocator.free(hashes);
            }
            if (self.components) |components| {
                for (components) |component| component.deinit(allocator);
                allocator.free(components);
            }
        }

        pub fn new(@"type": Type, name: []const u8, allocator: Allocator) !@This() {
            return .{
                .type = @"type",
                .name = try allocator.dupe(u8, name),
            };
        }

        pub fn setVersionFromCompileStep(
            self: *@This(),
            target: *std.Build.Step.Compile,
            allocator: Allocator,
        ) !void {
            self.version = if (target.version) |v|
                try std.fmt.allocPrint(
                    allocator,
                    "{d}.{d}.{d}",
                    .{ v.major, v.minor, v.patch },
                )
            else
                null;
        }

        pub fn setVersion(
            self: *@This(),
            v: []const u8,
            allocator: Allocator,
        ) !void {
            self.version = try allocator.dupe(u8, v);
        }

        pub fn setGroup(self: *@This(), group: []const u8, allocator: Allocator) !void {
            self.group = try allocator.dupe(u8, group);
        }

        pub fn setDescription(self: *@This(), desc: []const u8, allocator: Allocator) !void {
            self.description = try allocator.dupe(u8, desc);
        }

        pub fn generateBomRef(
            self: *@This(),
            alt: []const []const u8,
            allocator: Allocator,
        ) !void {
            var bom_ref = std.ArrayList(u8).init(allocator);
            errdefer bom_ref.deinit();

            if (self.group) |group| {
                try bom_ref.appendSlice(group);
                try bom_ref.append('/');
            }

            for (alt) |a| {
                try bom_ref.appendSlice(a);
                try bom_ref.append('/');
            }

            try bom_ref.appendSlice(self.name);

            if (self.version) |v| {
                try bom_ref.append('-');
                try bom_ref.appendSlice(v);
            }

            self.@"bom-ref" = try bom_ref.toOwnedSlice();
        }

        pub fn fromModule(
            name: []const u8,
            group: []const u8,
            v: ?[]const u8,
            module: *std.Build.Module,
            allocator: Allocator,
        ) !@This() {
            _ = module;

            var comp = try @This().new(.library, name, allocator);
            try comp.setDescription("Zig module", allocator);
            if (v) |v_| {
                try comp.setVersion(v_, allocator);
            }
            try comp.setGroup(group, allocator);
            try comp.generateBomRef(&.{"module"}, allocator);

            return comp;
        }

        pub fn setComponents(self: *@This(), comps: []const @This()) void {
            self.components = comps;
        }

        pub fn addAuthor(self: *@This(), author: Author, allocator: Allocator) !void {
            var authors = if (self.authors) |authors|
                std.ArrayList(Author).fromOwnedSlice(allocator, authors)
            else
                std.ArrayList(Author).init(allocator);
            try authors.append(author);
            self.authors = try authors.toOwnedSlice();
        }
    };

    pub fn new(allocator: Allocator) !@This() {
        var serialNumber: [45]u8 = .{0} ** 45;
        const uuid = uuidV4();
        const urn = serialize(uuid);
        @memcpy(serialNumber[0..9], "urn:uuid:");
        @memcpy(serialNumber[9..], urn[0..]);

        var bom: @This() = .{
            .serialNumber = serialNumber,
        };
        errdefer bom.deinit(allocator);

        bom.version = 1;

        return bom;
    }

    pub fn deinit(self: *@This(), allocator: Allocator) void {
        if (self.metadata) |metadata| metadata.deinit(allocator);
    }

    pub fn toJson(self: *@This(), allocator: Allocator) ![]u8 {
        return try std.json.stringifyAlloc(
            allocator,
            self,
            .{
                .emit_strings_as_arrays = false,
                .whitespace = .indent_2,
                .emit_null_optional_fields = false,
            },
        );
    }

    pub const Options = struct {
        /// The type of the component that the SBOM describes.
        type: Component.Type = .application,
        /// The main components name. Usually the name specified in build.zig.zon.
        name: []const u8,
        /// A group name like a company name, project name, or domain name.
        group: []const u8 = "thesugar.de",
        /// The version numer. Usually the version number set in build.zig.zon.
        version: ?[]const u8 = null,
        /// A description of the main component.
        description: ?[]const u8 = null,
        /// A list of authors of the main component.
        authors: ?[]const Component.Author = null,
        allocator: Allocator,
    };

    //pub fn fromModule(
    //    module: *std.Build.Module,
    //    options: Options
    //) !@This() {
    //    var bom = try CycloneDX.new(options.allocator);

    //    var main_component = try CycloneDX.Component.new(
    //        options.type,
    //        target.name,
    //        options.allocator,
    //    );
    //    if (options.version) |v| {
    //        try main_component.setVersion(v, options.allocator);
    //    } else {
    //        try main_component.setVersionFromCompileStep(
    //            target,
    //            options.allocator,
    //        );
    //    }
    //    try main_component.setGroup(options.group, options.allocator);
    //    try main_component.generateBomRef(options.allocator);
    //    if (options.description) |desc| try main_component.setDescription(desc, options.allocator);

    //    bom.metadata = .{
    //        .component = main_component,
    //    };

    //    return bom;
    //}

    pub fn fromBuild(
        b: *std.Build,
        options: Options,
    ) !@This() {
        var bom = try CycloneDX.new(options.allocator);

        var main_component = try CycloneDX.Component.new(
            options.type,
            options.name,
            options.allocator,
        );
        if (options.version) |v| {
            try main_component.setVersion(v, options.allocator);
        }
        try main_component.setGroup(options.group, options.allocator);
        try main_component.generateBomRef(&.{}, options.allocator);
        if (options.description) |desc| try main_component.setDescription(desc, options.allocator);

        var module_iterator = b.modules.iterator();
        var modules = std.ArrayList(Component).init(options.allocator);
        errdefer modules.deinit();
        while (module_iterator.next()) |kv| {
            try modules.append(try Component.fromModule(
                kv.key_ptr.*,
                options.group,
                options.version,
                kv.value_ptr.*,
                options.allocator,
            ));
        }
        main_component.setComponents(try modules.toOwnedSlice());

        const tool = try generateToolFromOwn(options.allocator);
        var tools = std.ArrayList(CycloneDX.Component).init(options.allocator);
        errdefer tools.deinit();
        try tools.append(tool);

        if (options.authors) |authors| {
            for (authors) |author|
                try main_component.addAuthor(
                    try author.clone(options.allocator),
                    options.allocator,
                );
        }

        bom.metadata = .{
            .component = main_component,
            .tools = try tools.toOwnedSlice(),
        };

        return bom;
    }

    pub fn fromCompileStep(
        target: *std.Build.Step.Compile,
        options: Options,
    ) !@This() {
        var bom = try CycloneDX.new(options.allocator);

        var main_component = try CycloneDX.Component.new(
            options.type,
            target.name,
            options.allocator,
        );
        if (options.version) |v| {
            try main_component.setVersion(v, options.allocator);
        } else {
            try main_component.setVersionFromCompileStep(
                target,
                options.allocator,
            );
        }
        try main_component.setGroup(options.group, options.allocator);
        try main_component.generateBomRef(&.{}, options.allocator);
        if (options.description) |desc| try main_component.setDescription(desc, options.allocator);

        bom.metadata = .{
            .component = main_component,
        };

        return bom;
    }
};

fn generateToolFromOwn(
    allocator: Allocator,
) !CycloneDX.Component {
    var comp = try CycloneDX.Component.new(.library, NAME, allocator);
    try comp.setDescription("Generate CycloneDX SBOMs for your Zig projects.", allocator);
    try comp.setVersion(VERSION, allocator);

    return comp;
}

pub fn build(b: *std.Build) !void {
    _ = b;
}

// UUID
// -----------------------------------------

/// Universally Unique IDentifier
///
/// A UUID is 128 bits long, and can guarantee uniqueness across space and time (RFC4122).
pub const Uuid = u128;

/// Switch between little and big endian
pub fn switchU16(v: u16) u16 {
    return ((v >> 8) & 0x00ff) | ((v << 8) & 0xff00);
}

/// Switch between little and big endian
pub fn switchU32(v: u32) u32 {
    return ((v >> 24) & 0x000000ff) | ((v >> 8) & 0x0000ff00) | ((v << 8) & 0x00ff0000) | ((v << 24) & 0xff000000);
}

/// Switch between little and big endian
pub fn switchU48(v: u48) u48 {
    return ((v >> 40) & 0x0000000000ff) | ((v >> 24) & 0x00000000ff00) | ((v >> 8) & 0x000000ff0000) | ((v << 8) & 0x0000ff000000) | ((v << 24) & 0x00ff00000000) | ((v << 40) & 0xff0000000000);
}

pub fn getTimeLow(uuid: Uuid) u32 {
    return switchU32(@as(u32, @intCast(uuid & 0xffffffff)));
}

pub fn setTimeLow(uuid: *Uuid, v: u32) void {
    uuid.* &= ~@as(Uuid, @intCast(0xffffffff));
    uuid.* |= @as(Uuid, @intCast(switchU32(v)));
}

pub fn getTimeMid(uuid: Uuid) u16 {
    return switchU16(@as(u16, @intCast((uuid >> 32) & 0xffff)));
}

pub fn setTimeMid(uuid: *Uuid, v: u16) void {
    uuid.* &= ~(@as(Uuid, @intCast(0xffff)) << 32);
    uuid.* |= @as(Uuid, @intCast(switchU16(v))) << 32;
}

pub fn getTimeHiAndVersion(uuid: Uuid) u16 {
    return switchU16(@as(u16, @intCast((uuid >> 48) & 0xffff)));
}

pub fn setTimeHiAndVersion(uuid: *Uuid, v: u16) void {
    uuid.* &= ~(@as(Uuid, @intCast(0xffff)) << 48);
    uuid.* |= @as(Uuid, @intCast(switchU16(v))) << 48;
}

pub fn getClockSeqHiAndReserved(uuid: Uuid) u8 {
    return @as(u8, @intCast((uuid >> 64) & 0xff));
}

pub fn setClockSeqHiAndReserved(uuid: *Uuid, v: u8) void {
    uuid.* &= ~(@as(Uuid, @intCast(0xff)) << 64);
    uuid.* |= @as(Uuid, @intCast(v)) << 64;
}

pub fn getClockSeqLow(uuid: Uuid) u8 {
    return @as(u8, @intCast((uuid >> 72) & 0xff));
}

pub fn setClockSeqLow(uuid: *Uuid, v: u8) void {
    uuid.* &= ~(@as(Uuid, @intCast(0xff)) << 72);
    uuid.* |= @as(Uuid, @intCast(v)) << 72;
}

pub fn getNode(uuid: Uuid) u48 {
    return switchU48(@as(u48, @intCast((uuid >> 80) & 0xffffffffffff)));
}

pub fn setNode(uuid: *Uuid, v: u48) void {
    uuid.* &= ~(@as(Uuid, @intCast(0xffffffffffff)) << 80);
    uuid.* |= @as(Uuid, @intCast(switchU48(v))) << 80;
}

/// The variant field determines the layout of the UUID
pub const Variant = enum {
    /// Reserved, NCS backward compatibility
    reserved_bw,
    /// The variant specified in RFC4122
    rfc4122,
    /// Reserved, Micorsoft Corporation backward compatibility
    reserved_ms,
    /// Reserved for future definition
    reserved_fu,
    /// Version 6, 7 and 8
    new_formats,
};

/// Get the variant of the given UUID
pub fn variant(uuid: Uuid) Variant {
    // Msb0  Msb1  Msb2
    //  0      x     x
    //  1      0     x
    //  1      1     0
    //  1      1     1
    return switch (getClockSeqHiAndReserved(uuid) >> 5) {
        0, 1, 2, 3 => .reserved_bw,
        4, 5 => .rfc4122,
        6 => .reserved_ms,
        7 => .reserved_fu,
        8, 9, 0xA, 0xB => .new_formats,
        else => unreachable,
    };
}

/// The version (sub-type) of a UUID
///
/// Versions:
///
/// * `v1` - Version 1 UUIDs using a timestamp and monotonic counter
/// * `v2` - Version 2 DCE UUIDs
/// * `v3` - Version 3 UUIDs based on the MD5 hash of some data
/// * `v4` - Version 4 UUIDs with random data
/// * `v5` - Version 5 UUIDs based on the SHA1 hash of some data
/// * `v6` - Version 6 UUIDs using a gregorian calendar time stamp
/// * `v7` - Version 7 UUIDs using a epoch time stamp
/// * `v8` - Version 8 UUIDs are vendor specific
pub const Version = enum(u4) {
    // old (RFC4122)
    time_based = 1,
    dce_security = 2,
    name_based_md5 = 3,
    random = 4,
    name_based_sha1 = 5,
    // new
    time_based_greg = 6,
    time_based_epoch = 7,
    custom = 8,
    ndef,
};

/// Get the version of the given UUID
pub fn version(uuid: Uuid) Version {
    return switch ((getTimeHiAndVersion(uuid) >> 12) & 0xf) {
        1 => .time_based,
        2 => .dce_security,
        3 => .name_based_md5,
        4 => .random,
        5 => .name_based_sha1,
        6 => .time_based_greg,
        7 => .time_based_epoch,
        8 => .custom,
        else => .ndef,
    };
}

pub const Urn = [36]u8;

/// Serialize the given UUID into a URN
///
/// Each field is separated by a `-` and printed as a zero-filled
/// hexadecimal digit string with the most significant digit first.
///
/// The caller is responsible for deallocating the string returned
/// by this function.
pub fn serialize(uuid: Uuid) Urn {
    var urn: Urn = undefined;
    _ = std.fmt.bufPrint(&urn, "{x:0>8}-{x:0>4}-{x:0>4}-{x:0>2}{x:0>2}-{x:0>12}", .{
        getTimeLow(uuid),
        getTimeMid(uuid),
        getTimeHiAndVersion(uuid),
        getClockSeqHiAndReserved(uuid),
        getClockSeqLow(uuid),
        getNode(uuid),
    }) catch unreachable;
    return urn;
}

fn hex2hw(h: u8) !u8 {
    return switch (h) {
        48...57 => h - 48,
        65...70 => h - 65 + 10,
        97...102 => h - 97 + 10,
        else => return error.InvalidHexChar,
    };
}

/// Deserialize the given URN into a UUID
///
/// If the given URN is malformed, a error is returned.
pub fn deserialize(s: []const u8) !Uuid {
    if (s.len != 36) {
        return error.MalformedUrn;
    } else if (std.mem.count(u8, s, "-") != 4) {
        return error.MalformedUrn;
    } else if (s[8] != '-' or s[13] != '-' or s[18] != '-' or s[23] != '-') {
        return error.MalformedUrn;
    }

    var uuid: Uuid = 0;
    var i: usize = 0;
    var j: u7 = 0;
    while (i <= 34) {
        if (s[i] == '-') {
            i += 1;
            continue;
        }

        const digit: u8 = (try hex2hw(s[i]) << 4) | try hex2hw(s[i + 1]);
        uuid |= @as(Uuid, @intCast(digit)) << (j * 8);
        i += 2;
        j += 1;
    }

    return uuid;
}

/// Create a version 4 UUID using a user provided RNG
pub fn uuidV4() Uuid {
    // Set all bits to pseudo-randomly chosen values.
    var uuid: Uuid = std.crypto.random.int(Uuid);
    // Set the two most significant bits of the
    // clock_seq_hi_and_reserved to zero and one.
    // Set the four most significant bits of the
    // time_hi_and_version field to the 4-bit version number.
    uuid &= 0xffffffffffffff3fff0fffffffffffff;
    uuid |= 0x00000000000000800040000000000000;
    return uuid;
}
