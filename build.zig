const std = @import("std");

const name = "ssh";
const version: std.SemanticVersion = .{
    .major = 0,
    .minor = 11,
    .patch = 1,
};

const Options = struct {
    linkage: std.builtin.LinkMode = .static,
    global_bind_config: []const u8 = "/etc/ssh/libssh_server_config",
    global_client_config: []const u8 = "/etc/ssh/ssh_config",
};

pub fn build(b: *std.Build) !void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const options: Options = .{
        .linkage = b.option(std.builtin.LinkMode, "linkage", "Whether to build as a static or dynamic library (default: static)") orelse .static,
        .global_bind_config = b.option([]const u8, "global_bind_config", "") orelse "/etc/ssh/libssh_server_config",
        .global_client_config = b.option([]const u8, "global_client_config", "") orelse "/etc/ssh/ssh_config",
    };

    const openssl = b.dependency("openssl", .{
        .target = target,
        .optimize = optimize,
    });
    const libcrypto = openssl.artifact("crypto");
    libcrypto.linkage = .static;

    const mod = b.createModule(.{
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });

    // libcrypto
    for (libcrypto.root_module.include_dirs.items) |dir| {
        try mod.include_dirs.append(b.allocator, dir);
    }
    mod.addCSourceFiles(.{ .root = b.path("src"), .files = &.{
        "threads/libcrypto.c",
        "pki_crypto.c",
        "ecdh_crypto.c",
        "getrandom_crypto.c",
        "md_crypto.c",
        "libcrypto.c",
        "dh_crypto.c",
    } });

    try addCSourceFiles(mod);
    mod.addIncludePath(b.path("include"));
    const libssh_version_h = addVersionHeader(mod);
    const config_h = addConfigHeader(mod, options);

    const lib = b.addLibrary(.{
        .name = name,
        .version = version,
        .root_module = mod,
        .linkage = options.linkage,
    });

    lib.installConfigHeader(libssh_version_h);
    lib.installConfigHeader(config_h);
    lib.installHeadersDirectory(b.path("include/libssh"), "libssh", .{});
    b.installArtifact(lib);
}

fn addVersionHeader(mod: *std.Build.Module) *std.Build.Step.ConfigHeader {
    const b = mod.owner;
    const header = b.addConfigHeader(.{
        .style = .{ .cmake = b.path("include/libssh/libssh_version.h.cmake") },
        .include_path = "libssh/libssh_version.h",
    }, .{
        .libssh_VERSION_MAJOR = @as(i64, @intCast(version.major)),
        .libssh_VERSION_MINOR = @as(i64, @intCast(version.minor)),
        .libssh_VERSION_PATCH = @as(i64, @intCast(version.patch)),
    });
    mod.addConfigHeader(header);
    return header;
}

fn addConfigHeader(mod: *std.Build.Module, options: Options) *std.Build.Step.ConfigHeader {
    const b = mod.owner;

    const os = mod.resolved_target.?.result.os.tag;

    const header = b.addConfigHeader(.{ .style = .{ .cmake = b.path("config.h.cmake") } }, .{
        .PROJECT_NAME = "lib" ++ name,
        .PROJECT_VERSION = b.fmt("{}", .{version}),

        // used for tests
        .SYSCONFDIR = null,
        .BINARYDIR = null,
        .SOURCEDIR = null,

        .GLOBAL_BIND_CONFIG = options.global_bind_config,
        .GLOBAL_CLIENT_CONFIG = options.global_client_config,

        // libcrypto
        .HAVE_LIBCRYPTO = true,

        .HAVE_PTHREAD = os != .windows and os != .wasi,

        // headers
        .HAVE_TERMIOS_H = os != .windows,
        .HAVE_SYS_TIME_H = true,

        // check_function_exists
        .HAVE_ISBLANK = true,
        .HAVE_STRNCPY = true,
        .HAVE_STRNDUP = os != .windows,
        .HAVE_STRTOULL = true,
        .HAVE_EXPLICIT_BZERO = os != .windows,
        .HAVE_MEMSET_S = os != .windows,
        .HAVE_COMPILER__FUNC__ = true,
        .HAVE_GETADDRINFO = true,
    });
    mod.addConfigHeader(header);
    return header;
}

fn addCSourceFiles(mod: *std.Build.Module) !void {
    const b = mod.owner;

    const src = b.path("src/");

    const os = mod.resolved_target.?.result.os.tag;

    // unconditional source files
    mod.addCSourceFiles(.{
        .root = src,
        .files = &.{
            "agent.c",
            "auth.c",
            "base64.c",
            "bignum.c",
            "buffer.c",
            "callbacks.c",
            "channels.c",
            "client.c",
            "config.c",
            "connect.c",
            "connector.c",
            "crypto_common.c",
            "curve25519.c",
            "dh.c",
            "ecdh.c",
            "error.c",
            "getpass.c",
            "init.c",
            "kdf.c",
            "kex.c",
            "known_hosts.c",
            "knownhosts.c",
            "legacy.c",
            "log.c",
            "match.c",
            "messages.c",
            "misc.c",
            "options.c",
            "packet.c",
            "packet_cb.c",
            "packet_crypt.c",
            "pcap.c",
            "pki.c",
            "pki_container_openssh.c",
            "poll.c",
            "session.c",
            "scp.c",
            "socket.c",
            "string.c",
            "threads.c",
            "threads/noop.c",
            "ttyopts.c",
            "wrapper.c",
            "external/bcrypt_pbkdf.c",
            "external/blowfish.c",
            "config_parser.c",
            "token.c",
            "pki_ed25519_common.c",
        },
    });

    // os-specific threads
    switch (os) {
        .windows => mod.addCSourceFile(.{ .file = try src.join(b.allocator, "threads/winlocks.c") }),
        .wasi => {},
        else => mod.addCSourceFile(.{ .file = try src.join(b.allocator, "threads/pthread.c") }),
    }
}
