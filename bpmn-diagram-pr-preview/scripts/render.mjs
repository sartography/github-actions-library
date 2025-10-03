import { convertAll } from "bpmn-to-image";
import fs from "fs/promises";
import path from "path";
import { execSync } from "child_process";
import FormData from "form-data";
import fetch from "node-fetch";
import crypto from "crypto";


// npm install bpmn-to-image node-fetch form-data
// Usage: node .github/scripts/render.mjs "A\tpath/to/new.bpmn" "M\tpath/to/modified.bpmn"
// Where A = added file, M = modified file (tab-separated status and path)

const IMAGE_STORE_API_URL = process.env.IMAGE_STORE_API_URL;
const SUPABASE_ANON_KEY = process.env.SUPABASE_ANON_KEY;

/**
 * Compares two image files to check if they are identical.
 * @param {string} filePath1 Path to the first image file
 * @param {string} filePath2 Path to the second image file
 * @returns {Promise<boolean>} True if the images are identical, false otherwise
 */
async function areImagesIdentical(filePath1, filePath2) {
  try {
    const [file1Content, file2Content] = await Promise.all([
      fs.readFile(filePath1),
      fs.readFile(filePath2)
    ]);
    
    // Compare file sizes first (quick check)
    if (file1Content.length !== file2Content.length) {
      return false;
    }
    
    // Compare file hashes
    const hash1 = crypto.createHash('sha256').update(file1Content).digest('hex');
    const hash2 = crypto.createHash('sha256').update(file2Content).digest('hex');
    
    return hash1 === hash2;
  } catch (error) {
    console.error(`Error comparing images ${filePath1} and ${filePath2}: ${error.message}`);
    return false;
  }
}

/**
 * Uploads multiple image files to the image store API.
 * @param {string[]} filePaths An array of paths to the image files to upload. These are the temporary PNG paths.
 * @returns {Promise<Object.<string, string>>} A promise that resolves to an object
 *   mapping temporary PNG file paths to their uploaded URLs.
 */
async function uploadImages(filePaths) {
  if (filePaths.length === 0) {
    return {};
  }

  const form = new FormData();
  for (const filePath of filePaths) {
    try {
      const fileContent = await fs.readFile(filePath);
      form.append("images", fileContent, { filename: path.basename(filePath) });
    } catch (readErr) {
      console.error(`Error reading file ${filePath}: ${readErr.message}`);
      throw new Error(`Failed to read image file ${filePath}: ${readErr.message}`);
    }
  }

  let response;
  try {
    response = await fetch(IMAGE_STORE_API_URL, {
      method: "POST",
      body: form,
      headers: {
        ...form.getHeaders(),
        Authorization: `Bearer ${SUPABASE_ANON_KEY}`,
      },
    });
  } catch (fetchErr) {
    console.error(`Fetch error: ${fetchErr.message}`);
    throw new Error(`Failed to connect to image store API: ${fetchErr.message}`);
  }


  if (!response.ok) {
    const errorText = await response.text();
    console.error(`API response not OK: ${response.status} ${response.statusText} - ${errorText}`);
    throw new Error(
      `Failed to upload images: ${response.status} ${response.statusText} - ${errorText}`,
    );
  }

  const data = await response.json();

  if (
    data.results &&
    Array.isArray(data.results) &&
    data.results.length === filePaths.length
  ) {
    const uploadedUrls = {};
    data.results.forEach((result) => {
      // Find the original temporary file path based on the filename returned by the API.
      // This assumes basenames are unique among the files being uploaded in this batch.
      // If not, a more robust mapping (e.g., using a UUID in the temp filename) would be needed.
      const originalTempFilePath = filePaths.find(
        (p) => path.basename(p) === result.filename,
      );
      if (originalTempFilePath) {
        uploadedUrls[originalTempFilePath] = result.url;
      } else {
        console.error(`Warning: Could not find original temp file path for uploaded filename: ${result.filename}`);
      }
    });
    return uploadedUrls;
  }
  console.error(`Unexpected response from image store API. Expected ${filePaths.length} results, got ${data.results ? data.results.length : 'none'}. Full data: ${JSON.stringify(data)}`);
  throw new Error(
    `Unexpected response from image store API: ${JSON.stringify(data)}`,
  );
}

async function main() {
  // Parse arguments which come as "STATUS\tPATH" format
  const bpmnFileEntries = process.argv.slice(2).map(arg => {
    // Remove any surrounding quotes from arguments that may have been added by shell
    let cleanArg = arg;
    if ((arg.startsWith('"') && arg.endsWith('"')) || 
        (arg.startsWith("'") && arg.endsWith("'"))) {
      cleanArg = arg.slice(1, -1);
    }
    
    // Split on tab to get status and path
    const parts = cleanArg.split('\t');
    if (parts.length === 2) {
      return { status: parts[0], path: parts[1] };
    } else {
      // Fallback for old format (just path)
      return { status: 'M', path: cleanArg };
    }
  }).filter(entry => entry.path && entry.path.trim() !== ''); // Filter out empty paths
  
  const bpmnFilePaths = bpmnFileEntries.map(entry => entry.path);
  const BASE_SHA = process.env.BASE_SHA;
  const HEAD_SHA = process.env.HEAD_SHA;
  const TEMP_DIR = "output";

  if (!BASE_SHA || !HEAD_SHA) {
    console.error("Error: BASE_SHA and HEAD_SHA environment variables must be set.");
    process.exit(1);
  }

  if (bpmnFilePaths.length === 0) {
    console.error("No BPMN files provided to render.");
    process.stdout.write(JSON.stringify({}));
    process.exit(0);
  }
  await fs.mkdir(TEMP_DIR, { recursive: true });

  const conversions = [];
  const filesToUpload = [];
  const bpmnFileToPngMap = {};
  const finalOutput = {};

  try {
    for (const bpmnFilePath of bpmnFilePaths) {
      const filename = path.basename(bpmnFilePath, ".bpmn");
      // Create unique temporary filenames to avoid clashes if basenames are identical
      const uniqueId = Math.random().toString(36).substring(2, 8); // Short unique ID
      const beforeBpmnTempPath = path.join(
        TEMP_DIR,
        `before-${filename}-${uniqueId}.bpmn`,
      );
      const afterBpmnTempPath = path.join(
        TEMP_DIR,
        `after-${filename}-${uniqueId}.bpmn`,
      );
      const beforePngTempPath = path.join(
        TEMP_DIR,
        `before-${filename}-${uniqueId}.png`,
      );
      const afterPngTempPath = path.join(
        TEMP_DIR,
        `after-${filename}-${uniqueId}.png`,
      );

      let beforeContentExists = false;
      let afterContentExists = false;

      // Try to get 'before' content from BASE_SHA
      try {
        const stdout = execSync(`git show ${BASE_SHA}:"${bpmnFilePath}"`, {
          encoding: "utf8",
          stdio: ["pipe", "pipe", "ignore"],
        }); // Ignore stderr
        await fs.writeFile(beforeBpmnTempPath, stdout);
        conversions.push({
          input: beforeBpmnTempPath,
          outputs: [beforePngTempPath],
        });
        filesToUpload.push(beforePngTempPath);
        beforeContentExists = true;
      } catch (e) {
        console.error(
          `Warning: Could not retrieve 'before' content for ${bpmnFilePath} from ${BASE_SHA}. It might be a new file. Error: ${e.message.split("\n")[0]}`,
        );
      }

      // Get 'after' content from HEAD_SHA (should always exist for changed/added files)
      try {
        const stdout = execSync(`git show ${HEAD_SHA}:"${bpmnFilePath}"`, {
          encoding: "utf8",
          stdio: ["pipe", "pipe", "ignore"],
        }); // Ignore stderr
        await fs.writeFile(afterBpmnTempPath, stdout);
        conversions.push({
          input: afterBpmnTempPath,
          outputs: [afterPngTempPath],
        });
        filesToUpload.push(afterPngTempPath);
        afterContentExists = true;
      } catch (e) {
        console.error(
          `Error: Could not retrieve 'after' content for ${bpmnFilePath} from ${HEAD_SHA}. This should not happen. Error: ${e.message.split("\n")[0]}`,
        );
        finalOutput[bpmnFilePath] = {
          error: `Failed to get 'after' content: ${e.message.split("\n")[0]}`,
        };
        continue;
      }

      bpmnFileToPngMap[bpmnFilePath] = {
        beforePng: beforeContentExists ? beforePngTempPath : null,
        afterPng: afterContentExists ? afterPngTempPath : null, // Should always be true if no error
      };
    }

    if (conversions.length > 0) {
      console.error(`Successfully prepared ${conversions.length} BPMN file(s) for rendering.`);
      await convertAll(conversions);
      console.error(`Successfully rendered ${conversions.length} BPMN file(s).`);
    } else {
      console.error("No valid BPMN files to render after content retrieval.");
      process.stdout.write(JSON.stringify({}));
      process.exit(0);
    }

    console.error("Uploading rendered images to image store...");
    const uploadedUrls = await uploadImages(filesToUpload);

    for (const bpmnFilePath in bpmnFileToPngMap) {
      const pngPaths = bpmnFileToPngMap[bpmnFilePath];
      const fileEntry = bpmnFileEntries.find(entry => entry.path === bpmnFilePath);
      const status = fileEntry ? fileEntry.status : 'M';
      
      // Check if before and after images are identical (skip if they are)
      if (pngPaths.beforePng && pngPaths.afterPng) {
        const imagesIdentical = await areImagesIdentical(pngPaths.beforePng, pngPaths.afterPng);
        if (imagesIdentical) {
          console.error(`Skipping ${bpmnFilePath} - before and after images are identical`);
          continue; // Skip this file entirely
        }
      }
      
      finalOutput[bpmnFilePath] = {
        beforeUrl: pngPaths.beforePng ? uploadedUrls[pngPaths.beforePng] : null,
        afterUrl: pngPaths.afterPng ? uploadedUrls[pngPaths.afterPng] : null,
        status: status,
      };
    }

    process.stdout.write(JSON.stringify(finalOutput));
  } catch (err) {
    console.error("Failed to render or upload BPMN file(s):", err);
    process.exit(1);
  } finally {
    try {
      await fs.rm(TEMP_DIR, { recursive: true, force: true });
    } catch (e) {
      console.error(`Error cleaning up temporary directory ${TEMP_DIR}: ${e.message}`);
    }
  }
  
  // Force process to exit to prevent hanging
  process.exit(0);
}

main();
