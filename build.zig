const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});
    const test_filters = parseTestFilters(b);

    const zio_dep = b.dependency("zio", .{
        .target = target,
        .optimize = optimize,
    });
    const zio_mod = zio_dep.module("zio");

    // The public library module consumers import as `mantle`.
    const mantle_mod = b.addModule("mantle", .{
        .root_source_file = b.path("src/mantle.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{
            .{ .name = "zio", .module = zio_mod },
        },
    });

    // Offline unit tests run the `test` blocks defined in the library module.
    const mod_tests = b.addTest(.{
        .root_module = mantle_mod,
        .filters = test_filters,
    });
    const run_mod_tests = b.addRunArtifact(mod_tests);

    const test_step = b.step("test", "Run offline unit tests");
    test_step.dependOn(&run_mod_tests.step);

    // Integration tests run against a real MySQL server.
    const integration_tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("integration_tests/main.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "mantle", .module = mantle_mod },
                .{ .name = "zio", .module = zio_mod },
            },
        }),
        .filters = test_filters,
    });

    const run_integration_tests = b.addRunArtifact(integration_tests);
    const integration_test_step = b.step("integration_test", "Run integration tests against a real MySQL server");
    integration_test_step.dependOn(&run_integration_tests.step);

    // Benchmarks (architecture §21). A standalone executable in examples/ (it
    // reuses common.zig's Config/Db helpers), not a `addTest`: the `--listen=-`
    // test-runner protocol aborts its IPC shutdown as soon as a test writes to
    // stderr, and a benchmark exists to print results. Run with
    // `-Doptimize=ReleaseFast` for representative numbers; it exercises a real
    // MySQL server.
    const benchmark = b.addExecutable(.{
        .name = "benchmark",
        .root_module = b.createModule(.{
            .root_source_file = b.path("examples/benchmark.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "mantle", .module = mantle_mod },
                .{ .name = "zio", .module = zio_mod },
            },
        }),
    });
    const run_benchmark = b.addRunArtifact(benchmark);
    const benchmark_step = b.step("benchmark", "Run benchmarks against a real MySQL server");
    benchmark_step.dependOn(&run_benchmark.step);

    // Runnable example programs (examples/), numbered in learning order.
    // `zig build examples` compiles and installs all of them; `zig build
    // example-<name>` builds and runs one against a live MySQL server
    // (configurable via MANTLE_* env vars).
    const examples = [_]struct { name: []const u8, file: []const u8 }{
        .{ .name = "connect", .file = "examples/01_connect.zig" },
        .{ .name = "query", .file = "examples/02_query.zig" },
        .{ .name = "crud", .file = "examples/03_crud.zig" },
        .{ .name = "transaction", .file = "examples/04_transaction.zig" },
        .{ .name = "pool", .file = "examples/05_pool.zig" },
    };

    const examples_step = b.step("examples", "Build the example programs");
    for (examples) |example| {
        const exe = b.addExecutable(.{
            .name = example.name,
            .root_module = b.createModule(.{
                .root_source_file = b.path(example.file),
                .target = target,
                .optimize = optimize,
                .imports = &.{
                    .{ .name = "mantle", .module = mantle_mod },
                    .{ .name = "zio", .module = zio_mod },
                },
            }),
        });
        examples_step.dependOn(&b.addInstallArtifact(exe, .{}).step);

        const run_exe = b.addRunArtifact(exe);
        const run_step = b.step(
            b.fmt("example-{s}", .{example.name}),
            b.fmt("Run the {s} example against a live MySQL server", .{example.name}),
        );
        run_step.dependOn(&run_exe.step);
    }
}

fn parseTestFilters(b: *std.Build) []const []const u8 {
    const args = b.args orelse return &.{};

    var filters: std.ArrayList([]const u8) = .empty;
    var i: usize = 0;
    while (i < args.len) : (i += 1) {
        const arg = args[i];
        if (std.mem.eql(u8, arg, "--test-filter")) {
            i += 1;
            if (i >= args.len) {
                std.debug.panic("missing value after --test-filter", .{});
            }
            filters.append(b.allocator, args[i]) catch @panic("out of memory");
        } else if (std.mem.startsWith(u8, arg, "--test-filter=")) {
            filters.append(b.allocator, arg["--test-filter=".len..]) catch @panic("out of memory");
        } else {
            std.debug.panic("unsupported test argument: {s}", .{arg});
        }
    }

    return filters.toOwnedSlice(b.allocator) catch @panic("out of memory");
}
