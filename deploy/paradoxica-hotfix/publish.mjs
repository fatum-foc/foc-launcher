import { createHash, verify } from "node:crypto";
import { readFile } from "node:fs/promises";

let phase = "startup";
let fatalReported = false;
function reportFatal(error) {
  if (fatalReported) return;
  fatalReported = true;
  console.error(`::error title=FoC publisher failure::phase=${phase}`);
  console.error(error instanceof Error ? error.message : "Unknown publication failure.");
  process.exit(1);
}
process.on("uncaughtException", reportFatal);
process.on("unhandledRejection", reportFatal);

const repository = process.env.GITHUB_REPOSITORY;
const token = process.env.GITHUB_TOKEN;
const tag = "client-0.0.3";
const root = new URL("./", import.meta.url);
const canonicalManifestName = "stable.json";
const canonicalSignatureName = "stable.json.sig";
const backupManifestName = "stable-0.0.6-before-xaero-nether-layer-20260822.json";
const backupSignatureName = `${backupManifestName}.sig`;
const prerequisiteObjects = [
  {
    path: "mods/FoC-Midnight-Deal-1.12.2.jar",
    hash: "225fc7263a455775fb915a123599f9d0380a4051c417e45bfbe06cc54a090a4c",
  },
  {
    path: "mods/FoC-Paradoxica-1.1.4.jar",
    hash: "b0519bad25c22f103c6e99388798fa638f68ef71e874f136b9e81a18ea287831",
  },
  {
    path: "mods/FoC-Mausoleum-Guard-1.0.0.jar",
    hash: "a890ceb35a6007688c1025d514fa66a8b116cb1dfbefb16f050c9a7e1010dd22",
  },
];
const expectedObjects = [
  {
    path: "mods/FoC-Xaero-Nether-Layer-1.0.0.jar",
    hash: "f175dc5d39312155cfb4cf71613c04b4fc5b756f1c35d1183cc53f75d4755993",
    size: 6476,
  },
];

phase = "local-validation";
if (!repository || !token) throw new Error("GitHub Actions authorization is unavailable.");

const manifestBytes = await readFile(new URL("stable.json", root));
const signatureBytes = await readFile(new URL("stable.json.sig", root));
const publicKey = await readFile(new URL("launcher-manifest-public.pem", root), "utf8");
const manifest = JSON.parse(manifestBytes.toString("utf8"));

function sha256(bytes) {
  return createHash("sha256").update(bytes).digest("hex");
}

function sameBytes(left, right) {
  return left.length === right.length && left.equals(right);
}

function verifyPair(data, signature, label) {
  if (signature.length !== 64) throw new Error(`${label}: signature is not 64 bytes.`);
  const valid = verify("sha256", data, { key: publicKey, dsaEncoding: "ieee-p1363" }, signature);
  if (!valid) throw new Error(`${label}: ECDSA signature is invalid.`);
}

verifyPair(manifestBytes, signatureBytes, "Prepared manifest");
if (manifest.clientVersion !== "0.0.6") throw new Error("Prepared clientVersion must remain 0.0.6.");
if (!Array.isArray(manifest.files) || manifest.files.length !== 602) {
  throw new Error("Prepared manifest must contain exactly 602 files.");
}
for (const prerequisite of prerequisiteObjects) {
  const matches = manifest.files.filter(
    (file) => file.path === prerequisite.path && file.sha256 === prerequisite.hash,
  );
  if (matches.length !== 1) {
    throw new Error(`Prepared manifest lost a required current object: ${prerequisite.path}`);
  }
}
if (manifest.files.some((file) => file.path.startsWith("mods/FoC-Paradoxica-Sudden-Strike-Patch-"))) {
  throw new Error("Prepared manifest still contains a separate Sudden Strike patch.");
}

const objectBytes = new Map();
for (const expected of expectedObjects) {
  const entry = manifest.files.filter((file) => file.path === expected.path);
  if (entry.length !== 1 || entry[0].sha256 !== expected.hash || entry[0].size !== expected.size) {
    throw new Error(`Prepared manifest has an invalid entry for ${expected.path}.`);
  }
  const bytes = await readFile(new URL(expected.hash, root));
  if (bytes.length !== expected.size || sha256(bytes) !== expected.hash) {
    throw new Error(`Prepared object failed integrity validation: ${expected.hash}`);
  }
  objectBytes.set(expected.hash, bytes);
}

async function request(url, options = {}) {
  const headers = {
    Accept: "application/vnd.github+json",
    "X-GitHub-Api-Version": "2022-11-28",
    "User-Agent": "FoC-Xaero-Nether-Layer-safe-publisher",
    Authorization: `Bearer ${token}`,
    ...(options.headers ?? {}),
  };
  const response = await fetch(url, { ...options, headers, redirect: "follow" });
  if (!response.ok) {
    const detail = (await response.text()).slice(0, 500);
    throw new Error(`GitHub HTTP ${response.status} for ${options.method ?? "GET"} ${url}: ${detail}`);
  }
  return response;
}

async function requestJson(url, options) {
  return (await request(url, options)).json();
}

phase = "release-read";
const release = await requestJson(`https://api.github.com/repos/${repository}/releases/tags/${tag}`);
const releaseId = release.id;

async function listAssets() {
  const result = [];
  for (let page = 1; ; page += 1) {
    const batch = await requestJson(
      `https://api.github.com/repos/${repository}/releases/${releaseId}/assets?per_page=100&page=${page}`,
    );
    result.push(...batch);
    if (batch.length < 100) return result;
  }
}

function getAsset(assets, name, optional = false) {
  const matches = assets.filter((asset) => asset.name === name);
  if (matches.length > 1) throw new Error(`Duplicate release asset: ${name}`);
  if (matches.length === 0) {
    if (optional) return null;
    throw new Error(`Missing release asset: ${name}`);
  }
  return matches[0];
}

async function downloadAsset(asset) {
  const response = await request(asset.url, { headers: { Accept: "application/octet-stream" } });
  return Buffer.from(await response.arrayBuffer());
}

async function deleteAsset(asset) {
  await request(`https://api.github.com/repos/${repository}/releases/assets/${asset.id}`, { method: "DELETE" });
}

async function uploadAsset(name, bytes) {
  const url = `https://uploads.github.com/repos/${repository}/releases/${releaseId}/assets?name=${encodeURIComponent(name)}`;
  return requestJson(url, {
    method: "POST",
    headers: { "Content-Type": "application/octet-stream" },
    body: bytes,
  });
}

async function renameAsset(asset, name) {
  return requestJson(`https://api.github.com/repos/${repository}/releases/assets/${asset.id}`, {
    method: "PATCH",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ name }),
  });
}

async function ensureImmutableAsset(name, bytes) {
  let assets = await listAssets();
  let asset = getAsset(assets, name, true);
  if (!asset) asset = await uploadAsset(name, bytes);
  const remote = await downloadAsset(asset);
  if (!sameBytes(remote, bytes)) throw new Error(`Remote immutable asset differs: ${name}`);
  return asset;
}

async function replaceStage(name, bytes) {
  const existing = getAsset(await listAssets(), name, true);
  if (existing) await deleteAsset(existing);
  const asset = await uploadAsset(name, bytes);
  if (!sameBytes(await downloadAsset(asset), bytes)) throw new Error(`Staging upload differs: ${name}`);
  return asset;
}

async function publicDownload(name) {
  const url = `https://github.com/${repository}/releases/download/${tag}/${encodeURIComponent(name)}?verify=${Date.now()}`;
  const response = await fetch(url, { redirect: "follow", cache: "no-store" });
  if (!response.ok) throw new Error(`Public download failed for ${name}: HTTP ${response.status}`);
  return Buffer.from(await response.arrayBuffer());
}

async function restore(previousManifestBytes, previousSignatureBytes) {
  let assets = await listAssets();
  for (const name of [canonicalSignatureName, canonicalManifestName]) {
    const asset = getAsset(assets, name, true);
    if (asset) await deleteAsset(asset);
    assets = await listAssets();
  }
  await uploadAsset(canonicalSignatureName, previousSignatureBytes);
  await uploadAsset(canonicalManifestName, previousManifestBytes);
  assets = await listAssets();
  const restoredManifest = await downloadAsset(getAsset(assets, canonicalManifestName));
  const restoredSignature = await downloadAsset(getAsset(assets, canonicalSignatureName));
  if (!sameBytes(restoredManifest, previousManifestBytes) || !sameBytes(restoredSignature, previousSignatureBytes)) {
    throw new Error("Automatic rollback bytes do not match the previous signed pair.");
  }
  verifyPair(restoredManifest, restoredSignature, "Restored manifest");
}

phase = "current-assets-list";
let assets = await listAssets();
const currentManifestAsset = getAsset(assets, canonicalManifestName);
const currentSignatureAsset = getAsset(assets, canonicalSignatureName);
phase = "current-pair-download";
const previousManifestBytes = await downloadAsset(currentManifestAsset);
const previousSignatureBytes = await downloadAsset(currentSignatureAsset);
phase = "current-pair-validation";
verifyPair(previousManifestBytes, previousSignatureBytes, "Current public manifest");

if (sameBytes(previousManifestBytes, manifestBytes) && sameBytes(previousSignatureBytes, signatureBytes)) {
  phase = "idempotent-object-validation";
  for (const expected of expectedObjects) await ensureImmutableAsset(expected.hash, objectBytes.get(expected.hash));
  console.log("Xaero Nether Layer client update is already published and verified.");
  process.exit(0);
}

const previousManifest = JSON.parse(previousManifestBytes.toString("utf8"));
phase = "current-state-validation";
if (previousManifest.clientVersion !== "0.0.6") throw new Error("Current public clientVersion is not 0.0.6.");
if (!Array.isArray(previousManifest.files) || previousManifest.files.length !== 601) {
  throw new Error("Current public manifest must contain exactly 601 files.");
}
for (const old of prerequisiteObjects) {
  const matches = previousManifest.files.filter(
    (file) => file.path === old.path && file.sha256 === old.hash,
  );
  if (matches.length !== 1) {
    throw new Error(`Current public manifest does not contain the expected object: ${old.path}`);
  }
}
if (previousManifest.files.some((file) => file.path.startsWith("mods/FoC-Xaero-Nether-Layer-"))) {
  throw new Error("Current public manifest already contains a Xaero Nether Layer entry.");
}
if (manifest.files.length !== previousManifest.files.length + 1) {
  throw new Error("Xaero Nether Layer update must add exactly one file.");
}

phase = "rollback-backup-upload";
await ensureImmutableAsset(backupManifestName, previousManifestBytes);
await ensureImmutableAsset(backupSignatureName, previousSignatureBytes);
phase = "content-object-upload";
for (const expected of expectedObjects) await ensureImmutableAsset(expected.hash, objectBytes.get(expected.hash));

const suffix = (process.env.GITHUB_SHA ?? Date.now().toString()).slice(0, 12);
const stageManifestName = `stable.json.next-xaero-nether-layer-${suffix}`;
const stageSignatureName = `stable.json.sig.next-xaero-nether-layer-${suffix}`;
phase = "staging-pair-upload";
const stageManifest = await replaceStage(stageManifestName, manifestBytes);
const stageSignature = await replaceStage(stageSignatureName, signatureBytes);

let switchStarted = false;
try {
  phase = "canonical-pair-switch";
  switchStarted = true;
  await deleteAsset(currentSignatureAsset);
  await renameAsset(stageSignature, canonicalSignatureName);
  await deleteAsset(currentManifestAsset);
  await renameAsset(stageManifest, canonicalManifestName);

  phase = "final-api-validation";
  assets = await listAssets();
  const finalManifest = await downloadAsset(getAsset(assets, canonicalManifestName));
  const finalSignature = await downloadAsset(getAsset(assets, canonicalSignatureName));
  if (!sameBytes(finalManifest, manifestBytes) || !sameBytes(finalSignature, signatureBytes)) {
    throw new Error("Canonical signed pair differs after the switch.");
  }
  verifyPair(finalManifest, finalSignature, "Final public manifest");
  for (const expected of expectedObjects) {
    const remote = await downloadAsset(getAsset(assets, expected.hash));
    if (remote.length !== expected.size || sha256(remote) !== expected.hash) {
      throw new Error(`Final object verification failed: ${expected.hash}`);
    }
  }

  phase = "anonymous-public-validation";
  let publicVerified = false;
  for (let attempt = 1; attempt <= 10; attempt += 1) {
    try {
      const publicManifest = await publicDownload(canonicalManifestName);
      const publicSignature = await publicDownload(canonicalSignatureName);
      if (sameBytes(publicManifest, manifestBytes) && sameBytes(publicSignature, signatureBytes)) {
        verifyPair(publicManifest, publicSignature, "Anonymous public manifest");
        publicVerified = true;
        break;
      }
    } catch (error) {
      if (attempt === 10) throw error;
    }
    await new Promise((resolve) => setTimeout(resolve, 2000));
  }
  if (!publicVerified) throw new Error("Anonymous public signed pair did not converge to the new bytes.");

  console.log(`Published Xaero Nether Layer client update: ${manifest.files.length} files.`);
  console.log(`Manifest SHA-256: ${sha256(manifestBytes)}`);
  console.log(`New objects: ${expectedObjects.map((entry) => entry.hash).join(", ")}`);
  console.log(`Prerequisite objects retained: ${prerequisiteObjects.map((entry) => entry.hash).join(", ")}`);
} catch (error) {
  if (switchStarted) {
    phase = "automatic-rollback";
    console.error("Publication verification failed; restoring the previous signed pair.");
    await restore(previousManifestBytes, previousSignatureBytes);
  }
  throw error;
}
