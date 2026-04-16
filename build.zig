const std = @import("std");

const TlsImpl = enum {
    bearssl,
    s2n_tls,
};

pub fn build(b: *std.Build) void {
    const tls = b.option(TlsImpl, "tls", "Choose between bearssl and s2n_tls implementation") orelse .bearssl;

    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const options = b.addOptions();
    options.addOption(TlsImpl, "tls", tls);

    const lib = b.addModule("secsock", .{
        .root_source_file = b.path("src/lib.zig"),
        .target = target,
        .optimize = optimize,
    });

    const tardy = b.dependency("tardy", .{
        .target = target,
        .optimize = optimize,
    }).module("tardy");

    lib.addImport("tardy", tardy);
    lib.addImport("options", options.createModule());

    switch (tls) {
        .bearssl => if (b.lazyDependency("bearssl", .{
            .target = target,
            .optimize = optimize,
            .BR_LE_UNALIGNED = false,
            .BR_BE_UNALIGNED = false,
        })) |bearssl| {
            const bearssl_lib = bearssl.artifact("bearssl");

            const upstream = bearssl.builder.dependency("bearssl", .{
                .target = target,
                .optimize = optimize,
            });
            const bearssl_h = b.addTranslateC(.{
                .optimize = optimize,
                .target = target,
                .link_libc = true,
                .root_source_file = upstream.path("inc/bearssl.h"),
            }).createModule();

            lib.linkLibrary(bearssl_lib);
            lib.addImport("bearssl_h", bearssl_h);
            add_example(b, "bearssl", target, optimize, tardy, lib);
        },
        .s2n_tls => if (b.lazyDependency("s2n_tls", .{
            .target = target,
            .optimize = optimize,
        })) |s2n_tls| {
            const s2n_lib = s2n_tls.artifact("s2n");

            const upstream = s2n_tls.builder.dependency("s2n_tls", .{
                .target = target,
                .optimize = optimize,
            });
            const s2n_h = b.addTranslateC(.{
                .optimize = optimize,
                .target = target,
                .link_libc = true,
                .root_source_file = upstream.path("api/s2n.h"),
            }).createModule();

            lib.linkLibrary(s2n_lib);
            lib.addImport("s2n_h", s2n_h);
            add_example(b, "s2n", target, optimize, tardy, lib);
        },
    }
}

fn add_example(
    b: *std.Build,
    name: []const u8,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
    tardy_module: *std.Build.Module,
    secsock_module: *std.Build.Module,
) void {
    const mod = b.createModule(.{
        .root_source_file = b.path(b.fmt("examples/{s}/main.zig", .{name})),
        .target = target,
        .optimize = optimize,
        .strip = false,
        .link_libc = if (target.result.os.tag == .windows) true else false,
    });
    mod.addImport("tardy", tardy_module);
    mod.addImport("secsock", secsock_module);

    const example = b.addExecutable(.{
        .name = b.fmt("{s}", .{name}),
        .root_module = mod,
        // error: undefined symbol: tardy_swap_frame
        .use_llvm = true,
    });

    const install_artifact = b.addInstallArtifact(example, .{});
    b.getInstallStep().dependOn(&install_artifact.step);

    const build_step = b.step(b.fmt("{s}", .{name}), b.fmt("Build tardy example ({s})", .{name}));
    build_step.dependOn(&install_artifact.step);

    const run_artifact = b.addRunArtifact(example);
    run_artifact.step.dependOn(&install_artifact.step);

    const run_step = b.step(b.fmt("run_{s}", .{name}), b.fmt("Run tardy example ({s})", .{name}));
    run_step.dependOn(&install_artifact.step);
    run_step.dependOn(&run_artifact.step);
}
