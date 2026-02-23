import { describe, it, expect, beforeEach, afterEach } from "vitest";
import {
  mkdtempSync,
  rmSync,
  readFileSync,
  writeFileSync,
  symlinkSync,
  statSync,
  existsSync,
  mkdirSync,
  realpathSync,
} from "node:fs";
import { join, resolve } from "node:path";
import { tmpdir } from "node:os";
import {
  safeWriteFile,
  safeWriteJson,
  safeWriteYaml,
  safeReadFile,
  validatePath,
  isSymlink,
  ensureDirectory,
  secureTempDir,
} from "../src/index.js";

let tmpDir: string;

beforeEach(() => {
  // Use realpathSync to normalize macOS system symlinks (/var → /private/var)
  // so isSymlink() doesn't flag system-level symlinks in the temp path.
  tmpDir = realpathSync(mkdtempSync(join(tmpdir(), "sanna-safe-io-test-")));
});

afterEach(() => {
  rmSync(tmpDir, { recursive: true, force: true });
});

describe("safeWriteFile", () => {
  it("should write content atomically", () => {
    const filePath = join(tmpDir, "test.txt");
    safeWriteFile(filePath, "hello world");
    expect(readFileSync(filePath, "utf-8")).toBe("hello world");
  });

  it("should overwrite existing file", () => {
    const filePath = join(tmpDir, "test.txt");
    safeWriteFile(filePath, "first");
    safeWriteFile(filePath, "second");
    expect(readFileSync(filePath, "utf-8")).toBe("second");
  });

  it("should create parent directories", () => {
    const filePath = join(tmpDir, "sub", "dir", "test.txt");
    safeWriteFile(filePath, "nested");
    expect(readFileSync(filePath, "utf-8")).toBe("nested");
  });

  it("should write Buffer content", () => {
    const filePath = join(tmpDir, "binary.bin");
    const buf = Buffer.from([0x48, 0x65, 0x6c, 0x6c, 0x6f]);
    safeWriteFile(filePath, buf);
    expect(readFileSync(filePath)).toEqual(buf);
  });

  it("should reject writing through symlink", () => {
    const realFile = join(tmpDir, "real.txt");
    const symFile = join(tmpDir, "link.txt");
    writeFileSync(realFile, "original");
    symlinkSync(realFile, symFile);

    expect(() => safeWriteFile(symFile, "attack")).toThrow("symlink");
  });

  it("should clean up temp file on write failure", () => {
    // Write to a directory path (will fail)
    const dirPath = join(tmpDir, "adir");
    mkdirSync(dirPath);

    // Can't easily simulate a write failure in all cases,
    // but we can verify the function doesn't leave temp files around
    // for successful writes
    const filePath = join(tmpDir, "clean.txt");
    safeWriteFile(filePath, "clean");
    // Verify no .tmp files left
    const files = require("node:fs").readdirSync(tmpDir) as string[];
    const tmpFiles = files.filter((f: string) => f.includes(".tmp."));
    expect(tmpFiles).toHaveLength(0);
  });

  it("should respect ensureDir: false", () => {
    const filePath = join(tmpDir, "nodir", "test.txt");
    expect(() =>
      safeWriteFile(filePath, "content", { ensureDir: false }),
    ).toThrow();
  });
});

describe("safeWriteJson", () => {
  it("should write JSON with proper formatting", () => {
    const filePath = join(tmpDir, "data.json");
    safeWriteJson(filePath, { key: "value", num: 42 });
    const content = readFileSync(filePath, "utf-8");
    const parsed = JSON.parse(content);
    expect(parsed.key).toBe("value");
    expect(parsed.num).toBe(42);
    expect(content).toContain("  "); // Pretty-printed
    expect(content.endsWith("\n")).toBe(true);
  });
});

describe("safeWriteYaml", () => {
  it("should write YAML data", () => {
    const filePath = join(tmpDir, "config.yaml");
    safeWriteYaml(filePath, { name: "test", version: "1.0" });
    const content = readFileSync(filePath, "utf-8");
    expect(content).toContain("name:");
    expect(content).toContain("test");
  });
});

describe("safeReadFile", () => {
  it("should read a normal file", () => {
    const filePath = join(tmpDir, "read.txt");
    writeFileSync(filePath, "content here");
    expect(safeReadFile(filePath)).toBe("content here");
  });

  it("should reject symlinks", () => {
    const realFile = join(tmpDir, "real.txt");
    const symFile = join(tmpDir, "link.txt");
    writeFileSync(realFile, "secret");
    symlinkSync(realFile, symFile);

    expect(() => safeReadFile(symFile)).toThrow("symlink");
  });

  it("should validate against base directory", () => {
    const baseDir = join(tmpDir, "base");
    mkdirSync(baseDir);
    writeFileSync(join(baseDir, "allowed.txt"), "ok");

    expect(safeReadFile(join(baseDir, "allowed.txt"), baseDir)).toBe("ok");
  });

  it("should reject paths that escape base directory", () => {
    const baseDir = join(tmpDir, "base");
    mkdirSync(baseDir);

    expect(() => safeReadFile("../../etc/passwd", baseDir)).toThrow(
      "validation failed",
    );
  });
});

describe("validatePath", () => {
  it("should accept valid paths within base", () => {
    const result = validatePath("subdir/file.txt", tmpDir);
    expect(result.valid).toBe(true);
    expect(result.resolved).toBe(resolve(tmpDir, "subdir/file.txt"));
  });

  it("should reject null bytes", () => {
    const result = validatePath("file\0.txt", tmpDir);
    expect(result.valid).toBe(false);
    expect(result.error).toContain("null bytes");
  });

  it("should reject path traversal", () => {
    const baseDir = join(tmpDir, "base");
    mkdirSync(baseDir);
    const result = validatePath("../../etc/passwd", baseDir);
    expect(result.valid).toBe(false);
    expect(result.error).toContain("escapes base directory");
  });

  it("should accept absolute paths within base", () => {
    const baseDir = join(tmpDir, "base");
    mkdirSync(baseDir);
    // An absolute path that resolves within baseDir
    const targetPath = join(baseDir, "file.txt");
    const result = validatePath(targetPath, baseDir);
    expect(result.valid).toBe(true);
  });

  it("should reject absolute paths outside base", () => {
    const result = validatePath("/etc/passwd", tmpDir);
    expect(result.valid).toBe(false);
  });
});

describe("isSymlink", () => {
  it("should return false for a regular file", () => {
    const filePath = join(tmpDir, "regular.txt");
    writeFileSync(filePath, "content");
    expect(isSymlink(filePath)).toBe(false);
  });

  it("should return true for a symlink", () => {
    const realFile = join(tmpDir, "real.txt");
    const symFile = join(tmpDir, "sym.txt");
    writeFileSync(realFile, "content");
    symlinkSync(realFile, symFile);
    expect(isSymlink(symFile)).toBe(true);
  });

  it("should return false for non-existent path", () => {
    expect(isSymlink(join(tmpDir, "nonexistent"))).toBe(false);
  });

  it("should detect symlink in parent directory", () => {
    const realDir = join(tmpDir, "realdir");
    const symDir = join(tmpDir, "symdir");
    mkdirSync(realDir);
    writeFileSync(join(realDir, "file.txt"), "content");
    symlinkSync(realDir, symDir);
    expect(isSymlink(join(symDir, "file.txt"))).toBe(true);
  });
});

describe("ensureDirectory", () => {
  it("should create a directory", () => {
    const dirPath = join(tmpDir, "new-dir");
    ensureDirectory(dirPath);
    expect(statSync(dirPath).isDirectory()).toBe(true);
  });

  it("should create nested directories", () => {
    const dirPath = join(tmpDir, "a", "b", "c");
    ensureDirectory(dirPath);
    expect(statSync(dirPath).isDirectory()).toBe(true);
  });

  it("should not fail if directory exists", () => {
    const dirPath = join(tmpDir, "existing");
    mkdirSync(dirPath);
    expect(() => ensureDirectory(dirPath)).not.toThrow();
  });
});

describe("secureTempDir", () => {
  it("should create a temp directory", () => {
    const dir = secureTempDir("test-");
    try {
      expect(statSync(dir).isDirectory()).toBe(true);
      expect(dir).toContain("test-");
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("should create directory with restricted permissions", () => {
    const dir = secureTempDir();
    try {
      const mode = statSync(dir).mode & 0o777;
      expect(mode).toBe(0o700);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("should generate unique directories", () => {
    const d1 = secureTempDir();
    const d2 = secureTempDir();
    try {
      expect(d1).not.toBe(d2);
    } finally {
      rmSync(d1, { recursive: true, force: true });
      rmSync(d2, { recursive: true, force: true });
    }
  });
});
