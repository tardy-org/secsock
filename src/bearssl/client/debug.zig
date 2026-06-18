/// Debug utilities for TLS traffic inspection and diagnostics
///
/// This module provides comprehensive debugging capabilities for BearSSL TLS operations,
/// including traffic inspection, hex dumps, connection state logging, and diagnostic tools.
///
/// Key features:
/// - Formatted hex dumps of TLS traffic with ASCII representation
/// - Connection state logging and diagnostics
/// - TLS engine state inspection
/// - Memory usage tracking and reporting
/// - Error statistics and monitoring
const std = @import("std");

const log = std.log.scoped(.bearssl_debug);

/// Debug utilities for TLS traffic inspection and diagnostics
pub const DebugUtils = struct {
    /// Returns true if a byte is a printable ASCII character
    pub fn isPrintableAscii(byte: u8) bool {
        return byte >= 32 and byte < 127;
    }

    /// Formats one line of a hex dump with offset, hex bytes, and ASCII representation
    pub fn formatHexDumpLine(writer: anytype, offset: usize, line_data: []const u8) !void {
        const max_bytes_per_line = 16;

        // Print offset
        try writer.print("{X:0>8}  ", .{offset});

        // Print hex bytes (up to 16 per line)
        for (line_data, 0..) |byte, j| {
            if (j == 8) try writer.writeByte(' ');
            try writer.print(" {X:0>2}", .{byte});
        }

        // Padding for alignment if we don't have a full line
        for (0..max_bytes_per_line - line_data.len) |_| {
            try writer.writeAll("   ");
        }
        // Add extra space if we're not crossing the middle boundary
        if (line_data.len <= 8) try writer.writeByte(' ');

        // Print ASCII representation
        try writer.writeAll("  |");
        for (line_data) |byte_val| {
            try writer.writeByte(if (isPrintableAscii(byte_val)) byte_val else '.');
        }
        try writer.writeAll("|");
    }

    /// Logs a header for the hex dump with size information
    pub fn logHexDumpHeader(direction: []const u8, data_len: usize, display_len: usize, max_display_bytes: usize) void {
        if (max_display_bytes > 0 and display_len < data_len) {
            log.debug("BearSSL {s} ({d} bytes, showing first {d}):", .{ direction, data_len, display_len });
        } else {
            log.debug("BearSSL {s} ({d} bytes):", .{ direction, data_len });
        }
    }

    /// Formatted hex dump of TLS traffic for debugging
    ///
    /// This function creates a well-formatted hexadecimal dump of TLS traffic,
    /// displaying both hex values and printable ASCII characters.
    ///
    /// Parameters:
    /// - direction: A label indicating the direction of traffic ("SENT" or "RECEIVED")
    /// - data: The binary data to dump
    pub fn dumpBlob(trace_enabled: bool, direction: []const u8, data: []const u8) void {
        if (!trace_enabled or data.len == 0) return;

        // Config for max bytes to display (0 = unlimited/full dump)
        const max_display_bytes: usize = 0; // Set to a value like 1024 to limit output

        // Determine display length (use all data if max_display_bytes is 0)
        const display_len = if (max_display_bytes > 0) @min(data.len, max_display_bytes) else data.len;
        const display_data = data[0..display_len];

        // Log header with size information
        logHexDumpHeader(direction, data.len, display_len, max_display_bytes);

        // Process data in chunks of up to 16 bytes
        const bytes_per_line = 16;
        var i: usize = 0;

        while (i < display_len) {
            var line_buf: [128]u8 = undefined;
            var fbs = std.io.fixedBufferStream(&line_buf);

            // Determine how many bytes to put on this line
            const bytes_in_line = @min(display_len - i, bytes_per_line);
            const line_data = display_data[i..(i + bytes_in_line)];

            // Format and log the line
            formatHexDumpLine(fbs.writer(), i, line_data) catch {};
            log.debug("{s}", .{fbs.getWritten()});

            i += bytes_in_line;
        }

        // Show indication if we truncated the output
        if (max_display_bytes > 0 and display_len < data.len) {
            log.debug("... {d} more bytes not shown", .{data.len - display_len});
        }
    }
};

/// TLS connection state diagnostics and inspection
pub const StateInspector = struct {
    /// Log comprehensive TLS engine state for debugging
    ///
    /// This function provides detailed diagnostics about the current state of
    /// the TLS connection, including engine state, protocols, and certificate
    /// validation status.
    pub fn logEngineState(title: []const u8, client_ctx: anytype, x509_ctx: anytype, trust_anchor_count: usize, memory_stats: anytype, error_stats: anytype) void {
        log.debug("--- {s} ---", .{title});

        const eng = &client_ctx.eng;
        const c = @cImport({
            @cInclude("bearssl.h");
        });
        const state = c.br_ssl_engine_current_state(eng);
        const error_code = c.br_ssl_engine_last_error(eng);

        log.debug("Engine state: {d}, error: {d}", .{ state, error_code });
        log.debug("Protocol version: 0x{X:0>4}", .{eng.version_in});
        log.debug("X.509 error: {d}, certs: {d}", .{ x509_ctx.err, x509_ctx.num_certs });
        log.debug("Trust anchors: {d}", .{trust_anchor_count});
        
        // Log memory usage statistics
        log.debug("Memory usage: {d} bytes, {d}/{d} contexts allocated", .{
            memory_stats.getTotalMemoryUsage(), memory_stats.contexts_allocated, memory_stats.total_contexts
        });
        
        // Log error statistics
        if (error_stats.total_errors > 0) {
            log.debug("Error stats: {d} total, {d} handshake, {d} cert, {d} I/O, {d} protocol", .{
                error_stats.total_errors, error_stats.handshake_failures, 
                error_stats.certificate_errors, error_stats.io_errors, error_stats.protocol_errors
            });
        }
    }

    /// Generate detailed connection diagnostics report
    pub fn generateDiagnosticsReport(writer: anytype, client_ctx: anytype, x509_ctx: anytype, memory_stats: anytype, error_stats: anytype) !void {
        try writer.print("=== TLS Connection Diagnostics ===\n");
        
        const eng = &client_ctx.eng;
        const c = @cImport({
            @cInclude("bearssl.h");
        });
        const state = c.br_ssl_engine_current_state(eng);
        const error_code = c.br_ssl_engine_last_error(eng);
        
        try writer.print("Engine State: {d}\n", .{state});
        try writer.print("Last Error: {d}\n", .{error_code});
        try writer.print("Protocol Version: 0x{X:0>4}\n", .{eng.version_in});
        try writer.print("X.509 Validation Error: {d}\n", .{x509_ctx.err});
        try writer.print("Certificate Count: {d}\n", .{x509_ctx.num_certs});
        
        try writer.print("\n--- Memory Statistics ---\n");
        try writer.print("Total Memory Usage: {d} bytes\n", .{memory_stats.getTotalMemoryUsage()});
        try writer.print("Contexts Allocated: {d}/{d}\n", .{memory_stats.contexts_allocated, memory_stats.total_contexts});
        
        try writer.print("\n--- Error Statistics ---\n");
        try writer.print("Total Errors: {d}\n", .{error_stats.total_errors});
        try writer.print("Handshake Failures: {d}\n", .{error_stats.handshake_failures});
        try writer.print("Certificate Errors: {d}\n", .{error_stats.certificate_errors});
        try writer.print("I/O Errors: {d}\n", .{error_stats.io_errors});
        try writer.print("Protocol Errors: {d}\n", .{error_stats.protocol_errors});
        
        try writer.print("=== End Diagnostics ===\n");
    }

    /// Check if TLS engine is in a healthy state
    pub fn isEngineHealthy(client_ctx: anytype) bool {
        const eng = &client_ctx.eng;
        const c = @cImport({
            @cInclude("bearssl.h");
        });
        const state = c.br_ssl_engine_current_state(eng);
        const error_code = c.br_ssl_engine_last_error(eng);
        
        // Engine is healthy if no errors and in a valid state
        return error_code == 0 and state != c.BR_SSL_CLOSED;
    }

    /// Get human-readable description of engine state
    pub fn getEngineStateDescription(state: u32) []const u8 {
        const c = @cImport({
            @cInclude("bearssl.h");
        });
        
        return switch (state) {
            c.BR_SSL_CLOSED => "Closed",
            c.BR_SSL_SENDREC => "Send/Receive Ready", 
            c.BR_SSL_SENDAPP => "Send Application Data",
            c.BR_SSL_RECVAPP => "Receive Application Data",
            else => "Unknown State",
        };
    }
};

/// Performance monitoring and profiling utilities
pub const PerformanceMonitor = struct {
    start_time: i64,
    operation_counts: OperationCounts,
    
    const OperationCounts = struct {
        handshakes: u64 = 0,
        reads: u64 = 0,
        writes: u64 = 0,
        bytes_read: u64 = 0,
        bytes_written: u64 = 0,
    };
    
    pub fn init() PerformanceMonitor {
        return .{
            .start_time = std.time.timestamp(),
            .operation_counts = .{},
        };
    }
    
    pub fn recordHandshake(self: *PerformanceMonitor) void {
        self.operation_counts.handshakes += 1;
    }
    
    pub fn recordRead(self: *PerformanceMonitor, bytes: usize) void {
        self.operation_counts.reads += 1;
        self.operation_counts.bytes_read += bytes;
    }
    
    pub fn recordWrite(self: *PerformanceMonitor, bytes: usize) void {
        self.operation_counts.writes += 1;
        self.operation_counts.bytes_written += bytes;
    }
    
    pub fn getElapsedSeconds(self: *const PerformanceMonitor) i64 {
        return std.time.timestamp() - self.start_time;
    }
    
    pub fn generatePerformanceReport(self: *const PerformanceMonitor, writer: anytype) !void {
        const elapsed = self.getElapsedSeconds();
        
        try writer.print("=== Performance Report ===\n");
        try writer.print("Session Duration: {d} seconds\n", .{elapsed});
        try writer.print("Handshakes: {d}\n", .{self.operation_counts.handshakes});
        try writer.print("Read Operations: {d} ({d} bytes)\n", .{self.operation_counts.reads, self.operation_counts.bytes_read});
        try writer.print("Write Operations: {d} ({d} bytes)\n", .{self.operation_counts.writes, self.operation_counts.bytes_written});
        
        if (elapsed > 0) {
            const bytes_per_sec_read = self.operation_counts.bytes_read / @as(u64, @intCast(elapsed));
            const bytes_per_sec_write = self.operation_counts.bytes_written / @as(u64, @intCast(elapsed));
            try writer.print("Average Read Throughput: {d} bytes/sec\n", .{bytes_per_sec_read});
            try writer.print("Average Write Throughput: {d} bytes/sec\n", .{bytes_per_sec_write});
        }
        
        try writer.print("=== End Performance Report ===\n");
    }
};

/// Debug configuration and utilities
pub const DebugConfig = struct {
    /// Enable/disable traffic hex dumps
    enable_traffic_dumps: bool = false,
    
    /// Enable/disable state logging
    enable_state_logging: bool = true,
    
    /// Enable/disable performance monitoring
    enable_performance_monitoring: bool = false,
    
    /// Maximum bytes to display in hex dumps (0 = unlimited)
    max_dump_bytes: usize = 1024,
    
    /// Log level for debug output
    log_level: LogLevel = .info,
    
    const LogLevel = enum {
        debug,
        info,
        warn,
        err,
    };
    
    pub fn createVerbose() DebugConfig {
        return .{
            .enable_traffic_dumps = true,
            .enable_state_logging = true,
            .enable_performance_monitoring = true,
            .max_dump_bytes = 0, // Unlimited
            .log_level = .debug,
        };
    }
    
    pub fn createMinimal() DebugConfig {
        return .{
            .enable_traffic_dumps = false,
            .enable_state_logging = false,
            .enable_performance_monitoring = false,
            .log_level = .err,
        };
    }
};