const std = @import("std");

const name = "libssh";
const version: std.SemanticVersion = .{
    .major = 0,
    .minor = 11,
    .patch = 1,
};

const Options = struct {
    crypto: enum { gcrypt, mbedtls, crypto } = .crypto,
    linkage: std.builtin.LinkMode = .static,
    global_bind_config: []const u8,
    global_client_config: []const u8,
};

pub fn build(b: *std.Build) !void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const options: Options = .{
        .crypto = b.option(std.meta.fieldInfo(Options, .crypto).type, "crypto", "The cryptography library to use (default: crypto)") orelse .crypto,
        .linkage = b.option(std.builtin.LinkMode, "linkage", "Whether to build as a static or dynamic library (default: static)") orelse .static,
        .global_bind_config = b.option([]const u8, "global_bind_config", "") orelse "/etc/ssh/libssh_server_config",
        .global_client_config = b.option([]const u8, "global_client_config", "") orelse "/etc/ssh/ssh_config",
    };

    const mod = b.createModule(.{
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });
    try addCSourceFiles(b, mod, options);
    mod.addIncludePath(b.path("include"));
    addVersionHeader(mod);
    addConfigHeader(mod, options);

    const lib = b.addLibrary(.{
        .name = name,
        .version = version,
        .root_module = mod,
        .linkage = options.linkage,
    });

    b.installArtifact(lib);
}

fn addVersionHeader(mod: *std.Build.Module) void {
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
}

fn addConfigHeader(mod: *std.Build.Module, options: Options) void {
    const b = mod.owner;
    const header = b.addConfigHeader(.{ .style = .{ .cmake = b.path("config.h.cmake") } }, .{
        .PROJECT_NAME = name,
        .PROJECT_VERSION = b.fmt("{}", .{version}),
        // .SYSCONFDIR = if (mod.resolved_target.?.result.os.tag == .linux) "/etc" else null,
        .SYSCONFDIR = null,
        .BINARYDIR = b.makeTempPath(),
        .SOURCEDIR = b.build_root.path.?,

        .GLOBAL_BIND_CONFIG = options.global_bind_config,
        .GLOBAL_CLIENT_CONFIG = options.global_client_config,
    });
    mod.addConfigHeader(header);
}

fn getThreadsLib(target: std.Target) ?enum { pthreads, win32 } {
    return switch (target.os.tag) {
        .windows => .win32,
        .wasi => null,
        else => .pthreads,
    };
}

fn addCSourceFiles(b: *std.Build, mod: *std.Build.Module, options: Options) !void {
    const src = b.path("src/");
    const flags: []const []const u8 = &.{};

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
            "ttyopts.c",
            "wrapper.c",
            "external/bcrypt_pbkdf.c",
            "external/blowfish.c",
            "config_parser.c",
            "token.c",
            "pki_ed25519_common.c",
        },
        .flags = flags,
    });

    // threads
    mod.addCSourceFile(.{
        .file = try src.join(b.allocator, "threads/noop.c"),
        .flags = flags,
    });
    if (getThreadsLib(mod.resolved_target.?.result)) |threads| mod.addCSourceFile(.{
        .file = switch (threads) {
            .pthreads => try src.join(b.allocator, "threads/pthread.c"),
            .win32 => try src.join(b.allocator, "threads/winlocks.c"),
        },
        .flags = flags,
    });

    // crypto
    mod.addCSourceFiles(.{ .root = src, .files = switch (options.crypto) {
        .gcrypt => &.{
            "threads/libgcrypt.c",
            "libgcrypt.c",
            "gcrypt_missing.c",
            "pki_gcrypt.c",
            "ecdh_gcrypt.c",
            "getrandom_gcrypt.c",
            "md_gcrypt.c",
            "dh_key.c",
            "pki_ed25519.c",
            "external/ed25519.c",
            "external/fe25519.c",
            "external/ge25519.c",
            "external/sc25519.c",
        },
        .mbedtls => &.{
            "threads/mbedtls.c",
            "libmbedcrypto.c",
            "mbedcrypto_missing.c",
            "pki_mbedcrypto.c",
            "ecdh_mbedcrypto.c",
            "getrandom_mbedcrypto.c",
            "md_mbedcrypto.c",
            "dh_key.c",
            "pki_ed25519.c",
            "external/ed25519.c",
            "external/fe25519.c",
            "external/ge25519.c",
            "external/sc25519.c",
        },
        .crypto => &.{
            "threads/libcrypto.c",
            "pki_crypto.c",
            "ecdh_crypto.c",
            "getrandom_crypto.c",
            "md_crypto.c",
            "libcrypto.c",
            "dh_crypto.c",
        },
    }, .flags = flags });
}
