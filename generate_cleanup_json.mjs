#!/usr/bin/env node

import { spawn, spawnSync } from "node:child_process";
import {
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  renameSync,
  rmSync,
  statSync,
  writeFileSync,
} from "node:fs";
import { availableParallelism, cpus, tmpdir } from "node:os";
import { dirname, join } from "node:path";

const REPO_ROOT = process.cwd();
const OUTPUT_DIR = join(REPO_ROOT, "cleanup");
const OUTPUT_PATH = join(OUTPUT_DIR, "go-code-deduplication.json");
const DUPLO_BINARY = process.env.DUPLO_BIN ?? "/bin/duplo";
const PMD_BINARY = process.env.PMD_BIN ?? "pmd";
const MIN_DUPLICATE_LINES = 7;
const MIN_DUPLICATE_TOKENS = 69;
const CPD_FLAGS = ["--ignore-identifiers", "--ignore-literal-sequences"];
const GO_CODE = 0;
const GO_LINE_COMMENT = 1;
const GO_BLOCK_COMMENT = 2;
const GO_RAW_STRING = 3;
const GO_STRING = 4;
const GO_RUNE = 5;
const THREADS = Math.max(
  1,
  typeof availableParallelism === "function"
    ? availableParallelism()
    : cpus().length,
);

function run(command, args, options = {}) {
  const result = spawnSync(command, args, {
    cwd: REPO_ROOT,
    encoding: "utf8",
    maxBuffer: 16 * 1024 * 1024,
    ...options,
  });
  if (result.error) throw result.error;
  if (result.status !== 0 && !options.acceptStatuses?.includes(result.status)) {
    throw new Error(`${command} exited with status ${result.status}\n${result.stderr}`);
  }
  return result;
}

function runAsync(command, args, options = {}) {
  return new Promise((resolve, reject) => {
    const child = spawn(command, args, { cwd: REPO_ROOT });
    const stdoutChunks = [];
    const stderrChunks = [];
    child.stdout.setEncoding("utf8").on("data", (chunk) => stdoutChunks.push(chunk));
    child.stderr.setEncoding("utf8").on("data", (chunk) => stderrChunks.push(chunk));
    child.on("error", reject);
    child.on("close", (status) => {
      const stdout = stdoutChunks.join("");
      const stderr = stderrChunks.join("");
      if (status !== 0 && !options.acceptStatuses?.includes(status)) {
        reject(new Error(`${command} exited with status ${status}\n${stderr}`));
        return;
      }
      resolve({ stdout, stderr, status });
    });
    if (options.input !== undefined) child.stdin.end(options.input);
    else child.stdin.end();
  });
}

function usage() {
  console.log(
    [
      "Usage:",
      "  node generate_cleanup_json.mjs [--go]",
      "",
      "Scans every tracked or untracked, non-ignored Go file for duplicate",
      "blocks of at least 7 lines (Duplo, textual) and at least 69 normalized",
      "tokens (PMD CPD, structural). Writes cleanup/go-code-deduplication.json.",
    ].join("\n"),
  );
}

function parseArgs(args) {
  for (const arg of args) {
    if (arg === "--help" || arg === "-h") {
      usage();
      process.exit(0);
    }
    if (arg !== "--go") throw new Error(`unknown argument: ${arg}`);
  }
}

function gitFiles(args) {
  return run("git", args).stdout.split("\0").filter(Boolean);
}

function inventory() {
  const deleted = new Set(gitFiles(["ls-files", "--deleted", "-z"]));
  const tracked = gitFiles(["ls-files", "-z"]);
  const untracked = gitFiles(["ls-files", "--others", "--exclude-standard", "-z"]);
  const files = [...new Set([...tracked, ...untracked])]
    .filter((path) => path.toLowerCase().endsWith(".go") && !deleted.has(path))
    .sort();

  const newlinePaths = files.filter((path) => path.includes("\n"));
  if (newlinePaths.length > 0) {
    throw new Error(
      `newline-delimited detector inputs cannot represent these Go paths:\n${newlinePaths.join("\n")}`,
    );
  }

  const unavailable = files.filter((path) => {
    const absolutePath = join(REPO_ROOT, path);
    return !existsSync(absolutePath) || !statSync(absolutePath).isFile();
  });
  if (unavailable.length > 0) {
    throw new Error(`Go paths are unavailable in the worktree:\n${unavailable.join("\n")}`);
  }

  return {
    files,
    deletedFiles: [...deleted].filter((path) => path.toLowerCase().endsWith(".go")).sort(),
  };
}

async function runDuplo(files) {
  if (files.length === 0) return { hits: [], status: 0, stderr: "" };

  let result;
  try {
    result = await runAsync(
      DUPLO_BINARY,
      ["-j", String(THREADS), "-ml", String(MIN_DUPLICATE_LINES), "-ip", "-json", "-", "-"],
      { input: files.join("\n"), acceptStatuses: [1] },
    );
  } catch (error) {
    if (error?.code === "ENOENT") {
      throw new Error(
        `${DUPLO_BINARY} is not installed; install Duplo or point DUPLO_BIN at its executable`,
      );
    }
    throw error;
  }

  const stderr = result.stderr.trim();
  if (/(^|\n)\s*(error|fatal):/iu.test(stderr)) {
    throw new Error(`duplo reported an input or scan failure:\n${stderr}`);
  }
  const hits = result.stdout.trim() ? (JSON.parse(result.stdout) ?? []) : [];
  if (!Array.isArray(hits)) throw new Error("duplo JSON output is not an array");
  return { hits, status: result.status, stderr };
}

function decodeXmlAttribute(value) {
  return value.replace(
    /&(lt|gt|amp|quot|apos|#x[0-9a-f]+|#\d+);/giu,
    (entity, name) => {
      switch (name.toLowerCase()) {
        case "lt":
          return "<";
        case "gt":
          return ">";
        case "amp":
          return "&";
        case "quot":
          return '"';
        case "apos":
          return "'";
        default:
          return String.fromCodePoint(
            name[1].toLowerCase() === "x"
              ? Number.parseInt(name.slice(2), 16)
              : Number.parseInt(name.slice(1), 10),
          );
      }
    },
  );
}

function parseXmlAttributes(tag) {
  const attributes = {};
  for (const match of tag.matchAll(/([\w:-]+)="([^"]*)"/gu)) {
    attributes[match[1]] = decodeXmlAttribute(match[2]);
  }
  return attributes;
}

function parseCpdXml(xml) {
  const duplications = [];
  for (const block of xml.matchAll(/<duplication\b([^>]*)>([\s\S]*?)<\/duplication>/gu)) {
    const header = parseXmlAttributes(block[1]);
    const lineCount = Number(header.lines);
    const tokenCount = Number(header.tokens);
    if (
      !Number.isInteger(lineCount) ||
      lineCount < 1 ||
      !Number.isInteger(tokenCount) ||
      tokenCount < 1
    ) {
      throw new Error(`cpd returned an invalid duplication header: ${block[0].slice(0, 200)}`);
    }

    const body = block[2].replace(/<codefragment>[\s\S]*?<\/codefragment>/gu, "");
    const occurrences = [];
    for (const fileTag of body.matchAll(/<file\b([^>]*)\/>/gu)) {
      const attributes = parseXmlAttributes(fileTag[1]);
      const start = Number(attributes.line);
      const end = Number(attributes.endline);
      if (
        !attributes.path ||
        !Number.isInteger(start) ||
        !Number.isInteger(end) ||
        start < 1 ||
        end < start
      ) {
        throw new Error(`cpd returned an invalid source range: ${fileTag[0]}`);
      }
      occurrences.push({ path: attributes.path, start, end });
    }
    if (occurrences.length < 2) {
      throw new Error(
        `cpd returned a duplication with fewer than two occurrences: ${block[0].slice(0, 200)}`,
      );
    }
    duplications.push({ lineCount, tokenCount, occurrences });
  }
  return duplications;
}

async function runCpd(files) {
  if (files.length === 0) return { duplications: [], status: 0, stderr: "" };

  const tempDirectory = mkdtempSync(join(tmpdir(), "go-cpd-file-list-"));
  const fileListPath = join(tempDirectory, "files.txt");
  let result;
  try {
    writeFileSync(fileListPath, `${files.join("\n")}\n`, "utf8");
    result = await runAsync(
      PMD_BINARY,
      [
        "cpd",
        "--file-list",
        fileListPath,
        "--language",
        "go",
        "--minimum-tokens",
        String(MIN_DUPLICATE_TOKENS),
        ...CPD_FLAGS,
        "--format",
        "xml",
        "--no-fail-on-violation",
      ],
      { acceptStatuses: [4, 5] },
    );
  } catch (error) {
    if (error?.code === "ENOENT") {
      throw new Error(
        `${PMD_BINARY} is not installed; install PMD 7 or point PMD_BIN at its launcher`,
      );
    }
    throw error;
  } finally {
    rmSync(tempDirectory, { recursive: true, force: true });
  }

  const stderr = result.stderr.trim();
  if (result.status === 5 || /(^|\n)\s*\[ERROR\]/u.test(stderr) || /<error\b/iu.test(result.stdout)) {
    throw new Error(`cpd could not lex every Go file:\n${stderr}`);
  }
  return { duplications: parseCpdXml(result.stdout), status: result.status, stderr };
}

function repoRelativePath(path) {
  const repoPrefix = `${REPO_ROOT}/`;
  if (path.startsWith(repoPrefix)) return path.slice(repoPrefix.length);
  if (!path.startsWith("/")) return path;
  throw new Error(`cpd returned a path outside the repository: ${path}`);
}

function mergeOverlappingRanges(ranges) {
  ranges.sort((left, right) => left[0] - right[0] || left[1] - right[1]);
  const merged = [];
  for (const [start, end] of ranges) {
    const previous = merged[merged.length - 1];
    if (previous && start <= previous[1]) previous[1] = Math.max(previous[1], end);
    else merged.push([start, end]);
  }
  return merged;
}

function commonDirectory(paths) {
  const directories = paths.map((path) => {
    const directory = dirname(path);
    return directory === "." ? [] : directory.split("/");
  });
  const commonParts = [];
  const shortestLength = Math.min(...directories.map((parts) => parts.length));
  for (let index = 0; index < shortestLength; index += 1) {
    const part = directories[0][index];
    if (!directories.every((parts) => parts[index] === part)) break;
    commonParts.push(part);
  }
  return commonParts.join("/");
}

function createHit(lineCount, tokenCount, rangesByFile) {
  const files = Array.from(rangesByFile, ([path, ranges]) => ({
    path,
    lines: mergeOverlappingRanges(ranges),
  })).sort((left, right) => left.path.localeCompare(right.path));
  const occurrenceCount = files.reduce((count, file) => count + file.lines.length, 0);
  const sharedDirectory = commonDirectory(files.map((file) => file.path));
  const crossFile = files.length > 1;
  return {
    kind: crossFile ? "cross-file" : "within-file",
    line_count: lineCount,
    ...(tokenCount === undefined ? {} : { token_count: tokenCount }),
    file_count: files.length,
    occurrence_count: occurrenceCount,
    removable_duplicate_lines: lineCount * (occurrenceCount - 1),
    ...(crossFile
      ? {
          highest_shared_directory: sharedDirectory || ".",
          shared_code_directory: sharedDirectory || "shared",
        }
      : {}),
    files,
  };
}

function structuralHits(duplications, scannedFiles) {
  const scanned = new Set(scannedFiles);
  return duplications
    .map((duplication) => {
      const rangesByFile = new Map();
      for (const occurrence of duplication.occurrences) {
        const path = repoRelativePath(occurrence.path);
        if (!scanned.has(path)) {
          throw new Error(`cpd returned a path outside the exhaustive scan: ${path}`);
        }
        const ranges = rangesByFile.get(path) ?? [];
        ranges.push([occurrence.start, occurrence.end]);
        rangesByFile.set(path, ranges);
      }
      return createHit(duplication.lineCount, duplication.tokenCount, rangesByFile);
    })
    .filter((hit) => hit.occurrence_count >= 2);
}

function hitLineCount(hit) {
  const explicit = Number(hit.LineCount);
  if (Number.isInteger(explicit) && explicit > 0) return explicit;
  const start = Number(hit.StartLineNumber1);
  const end = Number(hit.EndLineNumber1);
  return Number.isInteger(start) && Number.isInteger(end) && end >= start
    ? end - start + 1
    : 0;
}

function hitOccurrence(hit, side) {
  const path = String(hit[`SourceFile${side}`] ?? "");
  const start = Number(hit[`StartLineNumber${side}`]);
  const end = Number(hit[`EndLineNumber${side}`]);
  if (!path || !Number.isInteger(start) || !Number.isInteger(end) || start < 1 || end < start) {
    throw new Error(`duplo returned an invalid source range: ${JSON.stringify(hit)}`);
  }
  return { path, start, end };
}

function goCodeLines(source) {
  let lineCount = 1;
  for (let index = 0; index < source.length; index += 1) {
    if (source.charCodeAt(index) === 10) lineCount += 1;
  }
  const code = new Uint8Array(lineCount);
  let line = 0;
  let state = GO_CODE;
  let escaped = false;

  for (let index = 0; index < source.length; index += 1) {
    const character = source.charCodeAt(index);
    const next = source.charCodeAt(index + 1);
    if (character === 10) {
      line += 1;
      if (state === GO_LINE_COMMENT || state === GO_STRING || state === GO_RUNE) {
        state = GO_CODE;
      }
      escaped = false;
      continue;
    }
    if (state === GO_LINE_COMMENT) continue;
    if (state === GO_BLOCK_COMMENT) {
      if (character === 42 && next === 47) {
        state = GO_CODE;
        index += 1;
      }
      continue;
    }
    if (state === GO_RAW_STRING) {
      if (character === 96) state = GO_CODE;
      continue;
    }
    if (state === GO_STRING || state === GO_RUNE) {
      if (escaped) escaped = false;
      else if (character === 92) escaped = true;
      else if (
        (state === GO_STRING && character === 34) ||
        (state === GO_RUNE && character === 39)
      ) {
        state = GO_CODE;
      }
      continue;
    }
    if (character === 47 && next === 47) {
      state = GO_LINE_COMMENT;
      index += 1;
    } else if (character === 47 && next === 42) {
      state = GO_BLOCK_COMMENT;
      index += 1;
    } else if (character === 34) {
      state = GO_STRING;
    } else if (character === 39) {
      state = GO_RUNE;
    } else if (character === 96) {
      state = GO_RAW_STRING;
    } else if (character > 32) {
      code[line] = 1;
    }
  }
  return code;
}

function duplicateCodeLineCount(occurrence, cache) {
  let lines = cache.get(occurrence.path);
  if (lines === undefined) {
    lines = goCodeLines(readFileSync(join(REPO_ROOT, occurrence.path), "utf8"));
    cache.set(occurrence.path, lines);
  }
  let count = 0;
  const end = Math.min(occurrence.end, lines.length);
  for (let line = occurrence.start - 1; line < end; line += 1) count += lines[line];
  return count;
}

function filterDuploToCode(rawHits) {
  const cache = new Map();
  const hits = rawHits.filter((hit) =>
    [hitOccurrence(hit, 1), hitOccurrence(hit, 2)].every(
      (occurrence) => duplicateCodeLineCount(occurrence, cache) >= MIN_DUPLICATE_LINES,
    ),
  );
  return { hits, filteredCount: rawHits.length - hits.length };
}

function duplicateKey(hit) {
  if (Array.isArray(hit.Lines) && hit.Lines.length > 0) {
    return `${hitLineCount(hit)}\0${hit.Lines.join("\n")}`;
  }
  return [
    "locations",
    hitLineCount(hit),
    hit.SourceFile1,
    hit.StartLineNumber1,
    hit.EndLineNumber1,
    hit.SourceFile2,
    hit.StartLineNumber2,
    hit.EndLineNumber2,
  ].join("\0");
}

function compactHits(rawHits, scannedFiles) {
  const scanned = new Set(scannedFiles);
  const groups = new Map();
  for (const hit of rawHits) {
    const occurrences = [hitOccurrence(hit, 1), hitOccurrence(hit, 2)];
    for (const occurrence of occurrences) {
      if (!scanned.has(occurrence.path)) {
        throw new Error(`duplo returned a path outside the exhaustive scan: ${occurrence.path}`);
      }
    }
    const key = duplicateKey(hit);
    const group = groups.get(key) ?? { lineCount: 0, occurrences: new Map() };
    group.lineCount = Math.max(group.lineCount, hitLineCount(hit));
    for (const occurrence of occurrences) {
      group.occurrences.set(
        `${occurrence.path}\0${occurrence.start}\0${occurrence.end}`,
        occurrence,
      );
    }
    groups.set(key, group);
  }

  return Array.from(groups.values(), (group) => {
    const rangesByFile = new Map();
    for (const occurrence of group.occurrences.values()) {
      const ranges = rangesByFile.get(occurrence.path) ?? [];
      ranges.push([occurrence.start, occurrence.end]);
      rangesByFile.set(occurrence.path, ranges);
    }
    return createHit(group.lineCount, undefined, rangesByFile);
  });
}

function compareHits(left, right) {
  if (left.kind !== right.kind) return left.kind === "cross-file" ? -1 : 1;
  return (
    right.file_count - left.file_count ||
    right.occurrence_count - left.occurrence_count ||
    right.line_count - left.line_count ||
    left.files[0].path.localeCompare(right.files[0].path) ||
    left.files[0].lines[0][0] - right.files[0].lines[0][0]
  );
}

function summarize(hits) {
  let crossFileHits = 0;
  let removableDuplicateLines = 0;
  const files = new Set();
  for (const hit of hits) {
    if (hit.kind === "cross-file") crossFileHits += 1;
    removableDuplicateLines += hit.removable_duplicate_lines;
    for (const file of hit.files) files.add(file.path);
  }
  return {
    hit_count: hits.length,
    cross_file_hits: crossFileHits,
    within_file_hits: hits.length - crossFileHits,
    affected_file_count: files.size,
    removable_duplicate_lines: removableDuplicateLines,
  };
}

function writeReport(report) {
  mkdirSync(OUTPUT_DIR, { recursive: true });
  const temporaryPath = join(OUTPUT_DIR, `.go-code-deduplication.${process.pid}.tmp`);
  try {
    writeFileSync(temporaryPath, `${JSON.stringify(report, null, 2)}\n`, "utf8");
    renameSync(temporaryPath, OUTPUT_PATH);
  } finally {
    rmSync(temporaryPath, { force: true });
  }
}

async function main() {
  parseArgs(process.argv.slice(2));
  const startedAt = Date.now();
  const inventoryResult = inventory();
  const [duplo, cpd] = await Promise.all([
    runDuplo(inventoryResult.files),
    runCpd(inventoryResult.files),
  ]);
  const codeOnlyDuplo = filterDuploToCode(duplo.hits);
  const hits = compactHits(codeOnlyDuplo.hits, inventoryResult.files).sort(compareHits);
  const structural = structuralHits(cpd.duplications, inventoryResult.files).sort(compareHits);
  const report = {
    generated_at: new Date().toISOString(),
    purpose: "Exhaustive Go block duplication detection with Duplo and PMD CPD",
    scope: {
      file_sources: [
        ["git", "ls-files", "-z"],
        ["git", "ls-files", "--others", "--exclude-standard", "-z"],
      ],
      included_suffixes: [".go"],
      scanned_file_count: inventoryResult.files.length,
      worktree_deleted_go_files: inventoryResult.deletedFiles,
      missing_go_files: [],
    },
    duplo: {
      binary: DUPLO_BINARY,
      min_lines: MIN_DUPLICATE_LINES,
      content_filter: "comments and string/rune literals excluded",
      non_code_hits_filtered: codeOnlyDuplo.filteredCount,
      threads: THREADS,
      status: duplo.status,
      stderr: duplo.stderr,
    },
    cpd: {
      binary: PMD_BINARY,
      language: "go",
      min_tokens: MIN_DUPLICATE_TOKENS,
      flags: CPD_FLAGS,
      status: cpd.status,
      stderr: cpd.stderr,
    },
    hit_order: [
      "cross-file before within-file",
      "higher file count",
      "higher occurrence count",
      "higher line count",
    ],
    summary: summarize(hits),
    structural_summary: summarize(structural),
    hits,
    structural_hits: structural,
  };
  writeReport(report);

  console.log(
    [
      "wrote cleanup/go-code-deduplication.json",
      `scanned ${inventoryResult.files.length} Go files`,
      `duplo (textual): ${report.summary.cross_file_hits} cross-file and ${report.summary.within_file_hits} within-file groups`,
      `cpd (structural): ${report.structural_summary.cross_file_hits} cross-file and ${report.structural_summary.within_file_hits} within-file groups`,
      `timing: ${((Date.now() - startedAt) / 1000).toFixed(1)}s`,
    ].join("\n"),
  );
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
