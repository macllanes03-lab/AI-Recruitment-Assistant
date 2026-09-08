//**
 // AI Recruitment Assistant — server.js
 //

// =============================================================================
// SECTION 1: IMPORTS
// =============================================================================
require("dotenv").config();

const express  = require("express");
const multer   = require("multer");
const path     = require("path");
const fs       = require("fs");
const mammoth  = require("mammoth");
const { Pool } = require("pg");
const bcrypt   = require("bcryptjs");

const { PDFParse, VerbosityLevel } = require("pdf-parse");
const Anthropic = require("@anthropic-ai/sdk");

const app  = express();
const PORT = process.env.PORT || 4000;

app.use(express.static("public"));
app.use(express.json());

// =============================================================================
// SECTION 2: CORS
// =============================================================================
app.use((req, res, next) => {
  res.header("Access-Control-Allow-Origin", "*");
  res.header("Access-Control-Allow-Methods", "POST, GET, PATCH, DELETE, OPTIONS");
  res.header("Access-Control-Allow-Headers", "Content-Type");
  if (req.method === "OPTIONS") return res.sendStatus(200);
  next();
});

// =============================================================================
// SECTION 3: DATABASE CONNECTION
// =============================================================================
const pool = new Pool({
  host:     process.env.PGHOST     || "localhost",
  port:     process.env.PGPORT     || 5432,
  user:     process.env.PGUSER     || "postgres",
  password: process.env.PGPASSWORD || "",
  database: process.env.PGDATABASE || "ai_recruitment",
});

pool.query(`ALTER TABLE interview_drafts ADD COLUMN IF NOT EXISTS verification JSONB`)
  .then(() => console.log("[db] interview_drafts.verification column ready"))
  .catch(err => console.warn("[db] could not ensure interview_drafts.verification column:", err.message));

// =============================================================================
// SECTION 4: IN-MEMORY STORES & HELPERS
// =============================================================================
global.candidatesStore      = global.candidatesStore || {};
global.batchesStore         = global.batchesStore || {};

async function persistCandidate(candidateId) {
  const data = global.candidatesStore[candidateId];
  if (!data) return;
  try {
    await pool.query(
      `INSERT INTO candidates (id, data, updated_at) VALUES ($1, $2, now())
       ON CONFLICT (id) DO UPDATE SET data = EXCLUDED.data, updated_at = now()`,
      [candidateId, JSON.stringify(data)]
    );
  } catch (e) {
    console.error(`[persist] Failed to persist candidate ${candidateId}: ${e.message}`);
  }
}

async function persistBatch(batchId) {
  const data = global.batchesStore[batchId];
  if (!data) return;
  try {
    await pool.query(
      `INSERT INTO batches (batch_id, data, updated_at) VALUES ($1, $2, now())
       ON CONFLICT (batch_id) DO UPDATE SET data = EXCLUDED.data, updated_at = now()`,
      [batchId, JSON.stringify(data)]
    );
  } catch (e) {
    console.error(`[persist] Failed to persist batch ${batchId}: ${e.message}`);
  }
}

async function rehydrateStores() {
  try {
    const candRes = await pool.query(`SELECT id, data FROM candidates`);
    candRes.rows.forEach(r => { global.candidatesStore[r.id] = r.data; });

    const batchRes = await pool.query(`SELECT batch_id, data FROM batches`);
    batchRes.rows.forEach(r => { global.batchesStore[r.batch_id] = r.data; });

    console.log(`[rehydrate] Restored ${candRes.rows.length} candidate(s) and ${batchRes.rows.length} batch(es) from the database.`);
  } catch (e) {
    console.error(`[rehydrate] Failed to restore in-memory stores from the database: ${e.message}`);
    console.error(`[rehydrate] Candidate/batch state from before this restart will be unavailable until this is fixed.`);
  }
}

const BCRYPT_ROUNDS = 12;

function isValidEmail(email) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}

// =============================================================================
// SECTION 5: EMPLOYER ACCOUNT ROUTES
// =============================================================================

app.post("/api/employers/signup", async (req, res) => {
  const { companyName, fullName, email, password } = req.body || {};
  if (!companyName || !fullName || !email || !password)
    return res.status(400).json({ error: "All fields are required." });
  if (!isValidEmail(email))
    return res.status(400).json({ error: "Please enter a valid email address." });
  if (password.length < 8)
    return res.status(400).json({ error: "Password must be at least 8 characters." });
  try {
    const passwordHash = await bcrypt.hash(password, BCRYPT_ROUNDS);
    const result = await pool.query(
      `INSERT INTO employer_accounts (company_name, admin_full_name, admin_email, password_hash, status)
       VALUES ($1, $2, $3, $4, 'pending')
       RETURNING id, company_name, admin_email, status, created_at`,
      [companyName, fullName, email, passwordHash]
    );
    return res.status(201).json({
      message: "Account created. It is pending platform approval before you can sign in.",
      account: result.rows[0],
    });
  } catch (err) {
    if (err.code === "23505")
      return res.status(409).json({ error: "An account with this email already exists." });
    console.error(err);
    return res.status(500).json({ error: "Something went wrong. Please try again.", detail: process.env.NODE_ENV === "production" ? undefined : err.message });
  }
});

app.post("/api/auth/login", async (req, res) => {
  const { email, password } = req.body || {};
  if (!email || !password)
    return res.status(400).json({ error: "Email and password are required." });
  try {
    const adminResult = await pool.query(
      `SELECT id, full_name, password_hash FROM platform_admins WHERE LOWER(email) = LOWER($1)`,
      [email]
    );
    if (adminResult.rows.length > 0) {
      const admin = adminResult.rows[0];
      const match = await bcrypt.compare(password, admin.password_hash);
      if (!match) return res.status(401).json({ error: "Invalid email or password." });
      return res.json({ role: "admin", name: admin.full_name });
    }
    const empResult = await pool.query(
      `SELECT id, company_name, admin_full_name, password_hash, status FROM employer_accounts WHERE LOWER(admin_email) = LOWER($1)`,
      [email]
    );
    if (empResult.rows.length > 0) {
      const emp = empResult.rows[0];
      const match = await bcrypt.compare(password, emp.password_hash);
      if (!match) return res.status(401).json({ error: "Invalid email or password." });
      if (emp.status === "pending")
        return res.status(403).json({ error: "Your account is still pending approval." });
      if (emp.status === "suspended")
        return res.status(403).json({ error: "Your account has been suspended. Contact support." });
      return res.json({ role: "employer", companyName: emp.company_name, name: emp.admin_full_name });
    }
    return res.status(401).json({ error: "Invalid email or password." });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ error: "Something went wrong. Please try again.", detail: process.env.NODE_ENV === "production" ? undefined : err.message });
  }
});

app.get("/api/admin/employers", async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT id, company_name, admin_full_name, admin_email, status, created_at
       FROM employer_accounts ORDER BY created_at DESC`
    );
    res.json({ employers: result.rows });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Could not load employer accounts.", detail: process.env.NODE_ENV === "production" ? undefined : err.message });
  }
});

app.patch("/api/admin/employers/:id/status", async (req, res) => {
  const { id } = req.params;
  const { status } = req.body || {};
  if (!["pending", "active", "suspended"].includes(status))
    return res.status(400).json({ error: "Status must be pending, active, or suspended." });
  try {
    const result = await pool.query(
      `UPDATE employer_accounts SET status = $1, updated_at = now() WHERE id = $2 RETURNING id, company_name, status`,
      [status, id]
    );
    if (result.rows.length === 0) return res.status(404).json({ error: "Account not found." });
    res.json({ employer: result.rows[0] });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Could not update account status.", detail: process.env.NODE_ENV === "production" ? undefined : err.message });
  }
});

app.delete("/api/admin/employers/:id", async (req, res) => {
  const { id } = req.params;
  try {
    const result = await pool.query(`DELETE FROM employer_accounts WHERE id = $1 RETURNING id`, [id]);
    if (result.rows.length === 0) return res.status(404).json({ error: "Account not found." });
    res.json({ message: "Account permanently deleted." });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Could not delete account.", detail: process.env.NODE_ENV === "production" ? undefined : err.message });
  }
});

app.post("/api/admin/employers/:id/reset-password", async (req, res) => {
  const { id } = req.params;
  try {
    const chars = "ABCDEFGHJKMNPQRSTUVWXYZabcdefghjkmnpqrstuvwxyz23456789";
    let tempPassword = "";
    for (let i = 0; i < 12; i++) tempPassword += chars[Math.floor(Math.random() * chars.length)];
    const hash = await bcrypt.hash(tempPassword, BCRYPT_ROUNDS);
    const result = await pool.query(
      `UPDATE employer_accounts SET password_hash = $1, updated_at = now() WHERE id = $2 RETURNING id, admin_email`,
      [hash, id]
    );
    if (result.rows.length === 0) return res.status(404).json({ error: "Account not found." });
    res.json({ tempPassword, email: result.rows[0].admin_email });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Could not reset password.", detail: process.env.NODE_ENV === "production" ? undefined : err.message });
  }
});

// =============================================================================
// SECTION 6: FILE UPLOAD CONFIGURATION
// =============================================================================
const UPLOAD_DIR = path.join(__dirname, "uploads");
if (!fs.existsSync(UPLOAD_DIR)) fs.mkdirSync(UPLOAD_DIR);

const ALLOWED_EXTENSIONS = [".pdf", ".docx", ".txt"];

const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, UPLOAD_DIR),
  filename: (req, file, cb) => {
    const uid = Date.now() + "-" + Math.round(Math.random() * 1e5);
    cb(null, uid + path.extname(file.originalname).toLowerCase());
  },
});

const upload = multer({
  storage,
  limits: { fileSize: 10 * 1024 * 1024 },
  fileFilter: (req, file, cb) => {
    const ext = path.extname(file.originalname).toLowerCase();
    if (ALLOWED_EXTENSIONS.includes(ext)) return cb(null, true);

    const err = new Error("UNSUPPORTED_TYPE");
    err.filename = file.originalname;
    err.ext      = ext;
    err.accepted = ALLOWED_EXTENSIONS.join(", ");
    cb(err);
  },
});

function uploadMiddleware(req, res, next) {
  const handler = upload.fields([
    { name: "jd", maxCount: 1  },
    { name: "cv", maxCount: 20 },
  ]);
  handler(req, res, (err) => {
    if (!err) return next();

    if (err instanceof multer.MulterError) {
      if (err.code === "LIMIT_FILE_SIZE")
        return res.status(400).json({ error: "File too large.", detail: "Maximum file size is 10 MB. Please compress or split the document." });
      if (err.code === "LIMIT_FILE_COUNT")
        return res.status(400).json({ error: "Too many files.", detail: "You can upload a maximum of 20 CVs at once." });
      return res.status(400).json({ error: `Upload error: ${err.message}` });
    }

    if (err.message === "UNSUPPORTED_TYPE")
      return res.status(400).json({
        error:    `Unsupported file type.`,
        detail:   `"${err.filename}" (${err.ext}) is not supported. Please upload one of: ${err.accepted}.`,
        filename: err.filename,
      });

    return res.status(400).json({ error: err.message || "Upload failed." });
  });
}

// =============================================================================
// SECTION 7: TEXT EXTRACTION
// =============================================================================

async function extractText(filePath, originalName) {
  const ext   = path.extname(filePath).toLowerCase();
  const label = originalName || path.basename(filePath);

  if (ext === ".txt") {
    const text = fs.readFileSync(filePath, "utf-8");
    if (!text || text.trim().length === 0)
      throw new Error(`"${label}" is empty. Please upload a file with content.`);
    console.log(`       [TXT] ${text.length} chars extracted from "${label}"`);
    return text.trim();
  }

  if (ext === ".pdf") {
    let buffer;
    try {
      buffer = fs.readFileSync(filePath);
    } catch (e) {
      throw new Error(`Could not read "${label}" from disk: ${e.message}`);
    }

    const uint8 = new Uint8Array(buffer);

    let parser;
    try {
      parser = new PDFParse({
        data:      uint8,
        verbosity: VerbosityLevel.ERRORS,
      });
      await parser.load();
    } catch (e) {
      throw new Error(
        `"${label}" could not be read as a PDF. ` +
        `It may be password-protected, corrupted, or not a real PDF file. ` +
        `Try opening it in a PDF viewer first, then re-upload. (${e.message})`
      );
    }

    let result;
    try {
      result = await parser.getText();
    } catch (e) {
      throw new Error(`"${label}" failed during text extraction: ${e.message}`);
    } finally {
      try { parser.destroy(); } catch (_) {}
    }

    if (!result?.text || result.text.trim().length === 0) {
      throw new Error(
        `"${label}" appears to be a scanned or image-based PDF with no selectable text. ` +
        `Please use a text-based PDF (one where you can highlight and copy text) ` +
        `or re-export the document as DOCX.`
      );
    }

    console.log(`       [PDF] ${result.text.length} chars extracted from "${label}"`);
    return result.text.trim();
  }

  if (ext === ".docx") {
    let result;
    try {
      result = await mammoth.extractRawText({ path: filePath });
    } catch (e) {
      throw new Error(
        `"${label}" could not be read as a Word document. ` +
        `It may be corrupted or saved in the older .doc format. ` +
        `Please re-save as .docx and re-upload. (${e.message})`
      );
    }

    if (!result.value || result.value.trim().length === 0)
      throw new Error(`"${label}" is an empty Word document. Please check the file has content and re-upload.`);

    console.log(`       [DOCX] ${result.value.length} chars extracted from "${label}"`);
    return result.value.trim();
  }

  throw new Error(
    `"${label}" has an unsupported file type (${ext}). ` +
    `Accepted formats: PDF (.pdf), Word (.docx), plain text (.txt).`
  );
}

// =============================================================================
// SECTION 8: AI PROMPT BUILDERS
// =============================================================================

// --------------------------------------------------------------------------
// buildScoringSystemPrompt(): the persona + standing instructions that don't
// change between candidates. This is everything that used to live at the
// top of the old single-string buildScoringPrompt() -- the "who are you /
// how should you behave" part. It's passed as the SDK's top-level `system`
// field (see callOpenRouterAI below), not as a user message, per Anthropic's
// Messages API:
//
//   const response = await anthropic.messages.create({
//     model: "claude-3-5-sonnet-20241022",
//     max_tokens: 1024,
//     system: "You are a senior software engineer...",   // <- root-level
//     messages: [{ role: "user", content: "..." }]        // <- data only
//   });
//
// Keeping the persona/rules pinned in `system` (rather than re-sending them
// inside the user message every call) is also why buildScoringSystemPrompt()
// takes no arguments -- it's static text, computed once instead of being
// re-interpolated per candidate.
// --------------------------------------------------------------------------
function buildScoringSystemPrompt() {
  return `You are a professional recruitment analyst responsible for objectively 
  
evaluating candidate resumes against job requirements.

<task>
Carefully read the job description and the candidate's CV provided in the 
user message. Evaluate how well the candidate matches the role and return a 
structured scoring report in JSON format.
Think through each scoring category independently before assigning scores 
to ensure accuracy and fairness.
</task>

<scoring_guide>
Overall score interpretation:
- 85 to 100: Exceptional match — candidate exceeds most requirements
- 70 to 84:  Strong match — candidate meets core requirements
- 55 to 69:  Partial match — candidate meets some but not all requirements
- Below 55:  Weak match — candidate lacks critical requirements

Recommendation rules (strictly follow these thresholds):
- 70 and above → "Proceed to Interview"
- 55 to 69     → "Escalate for Review"
- Below 55     → "Reject"
</scoring_guide>

<rules>
- Score each category independently based only on evidence in the CV
- matched_keywords: list skills/tools explicitly found in both the JD and CV
- missing_keywords: list skills/tools required by JD but absent from CV
- recommendation_reason: one concise sentence explaining the recommendation
- strengths: 2 to 3 sentences on the candidate's strongest qualifications
- concerns: 2 to 3 sentences on gaps or red flags relative to the role
- summary: 3 to 4 sentences giving an overall hiring picture
- Do not infer or assume skills that are not explicitly stated in the CV
- Do not include any explanation, markdown, or text outside the JSON object
</rules>

<output_format>
Return ONLY a valid JSON object.
No explanation, no markdown, no extra text before or after.
Start your response with { and end with }

The JSON object MUST match this exact structure and field names
(all four category scores are integers from 0 to 100; overall_score
is an integer from 0 to 100):

{
  "overall_score": 83,
  "categories": {
    "technical_skills": 80,
    "experience": 75,
    "education": 90,
    "soft_skills": 85
  },
  "recommendation": "Proceed to Interview",
  "recommendation_reason": "one concise sentence",
  "matched_keywords": ["skill1", "skill2"],
  "missing_keywords": ["skill3"],
  "strengths": "2 to 3 sentences",
  "concerns": "2 to 3 sentences",
  "summary": "3 to 4 sentences"
}

Do not rename any key. Do not flatten "categories" into the top level.
Do not omit any key, even if a category score is 0.
</output_format>`;
}

// buildScoringUserPrompt(): the per-candidate DATA only -- the part that
// actually changes on every call. This is what goes in the `messages`
// array's { role: "user", content: ... }, strictly separate from the
// persona/rules now living in buildScoringSystemPrompt() above.
function buildScoringUserPrompt(jdText, cvText) {
  return `<job_description>
${jdText}
</job_description>

<candidate_cv>
${cvText}
</candidate_cv>`;
}

function mulberry32(seed) {
  return function() {
    let t = seed += 0x6D2B79F5;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

// Exam Generation//
function build15QuestionExamPrompt(jdText) {
  return `You are a technical hiring specialist who creates skill assessment exams.

<task>
Generate exactly 15 multiple-choice questions to evaluate job readiness based on the job description below.
The test MUST be strictly balanced across 4 difficulty tiers:
- Exactly 4 "easy" questions
- Exactly 4 "medium" questions
- Exactly 4 "hard" questions
- Exactly 3 "expert" questions
</task>

<rules>
- Return EXACTLY 15 questions.
- Each question must have exactly 4 answer options.
- Do NOT use "All of the above" or "None of the above".
- Assign the difficulty string ("easy", "medium", "hard", "expert") to each question.
- Use the job description ONLY to decide which technologies, tools, languages, and concepts are in scope — never write a question about the job description itself.
- Every question must be answerable by someone who has genuine hands-on knowledge of that technology/skill and has NEVER seen this job posting. If the only way to get the answer right is to have read this specific JD text, the question is invalid and must be rewritten.
- FORBIDDEN: any question that references "the job description", "this role", "this posting", or asks the candidate to recall which tool/language/service/database is "listed", "mentioned", or "required" in it (e.g. "Which database is listed in the job description?" is invalid).
- Instead, test real subject-matter competence: how a technology works, when/why to use it over alternatives, what a piece of code or config does, how to diagnose a described bug or failure scenario, trade-offs between approaches, correct syntax/behavior, etc.
</rules>

<output_format>
Return ONLY a valid JSON array of 15 objects.
Start your response with [ and end with ]
No explanation, no markdown, no extra text before or after.

Each object MUST match this exact structure and field names:

{
  "question": "What does the acronym API stand for?",
  "options": ["Application Programming Interface", "Automated Process Integration", "Advanced Protocol Interchange", "Application Process Index"],
  "correct": 0,
  "difficulty": "easy"
}

"correct" must be the 0-based index (an integer from 0 to 3) into "options" pointing to the correct answer. Do not rename "correct". Do not omit any key.

INVALID example (do not write questions like this — it tests JD recall, not skill):
{
  "question": "Which relational database is listed in the job description?",
  "options": ["PostgreSQL", "MongoDB", "Redis", "Cassandra"],
  "correct": 0,
  "difficulty": "easy"
}
If the JD mentions PostgreSQL, ask something a real PostgreSQL user would need to know instead, e.g. "Which SQL clause is used to filter grouped rows after a GROUP BY?"
</output_format>

<job_description>
${jdText}
</job_description>`;
}

app.post("/api/exam-pools/generate", upload.single("jd"), async (req, res) => {
  const filePaths = [];
  if (!req.file)
    return res.status(400).json({ error: "No job description file received. Please upload a JD first." });
  filePaths.push(req.file.path);

  // Hiring is generic/any-position now — there's no managed job posting to
  // scope this to. jobTitle is just a free-text label (typed by the
  // recruiter, or inferred from the JD itself if left blank) purely for
  // display; it no longer ties this exam to a specific posting.
  const requestedJobTitle = req.body.jobTitle || "General Role";

  // Streamed NDJSON response, same shape as /api/upload: real stage/attempt
  // events as they actually happen, then a final "result" line.
  res.setHeader("Content-Type", "application/x-ndjson; charset=utf-8");
  res.setHeader("X-Accel-Buffering", "no");
  res.flushHeaders && res.flushHeaders();
  const sendProgress = (obj) => {
    try { res.write(JSON.stringify({ type: "progress", ...obj }) + "\n"); }
    catch (e) { console.warn("[exam-pools/generate stream] write failed:", e.message); }
  };

  try {
    sendProgress({ step: "reading_jd", percent: 2, message: "Reading job description…" });
    let jdText;
    try {
      jdText = await extractText(req.file.path, req.file.originalname);
    } catch (e) {
      res.write(JSON.stringify({ type: "result", success: false, error: `Job description error: ${e.message}` }) + "\n");
      return res.end();
    }
    if (jdText.length < 50) {
      res.write(JSON.stringify({ type: "result", success: false, error: "The job description is too short (min 50 chars)." }) + "\n");
      return res.end();
    }

    const MAX_JD_CHARS = 4000;
    jdText = jdText.length > MAX_JD_CHARS ? jdText.slice(0, MAX_JD_CHARS) + "\n[JD truncated for length]" : jdText;

    const jobContext = resolveJDJobTitle(jdText, requestedJobTitle);
    const jobTitle = jobContext.jobTitle;

    console.log(`[standalone-exam] Generating & auto-verifying exam for "${jobTitle}"${jobContext.detectedFromJD ? " (resolved from JD)" : ""}...`);
    const { questions, verification } = await generateAndVerifyExam(jdText, sendProgress);

    const draftId = "draft_" + Date.now() + "_" + Math.floor(Math.random() * 10000);
    await pool.query(
      `INSERT INTO exam_drafts (draft_id, job_title, jd_text, questions, verification)
       VALUES ($1, $2, $3, $4, $5)`,
      [draftId, jobTitle || "General Role", jdText, JSON.stringify(questions), JSON.stringify(verification)]
    );

    console.log(`[standalone-exam] ✓ Draft ${draftId} ready for "${jobTitle}" — ${verification.issuesFound}/${questions.length} question(s) still flagged.`);
    res.write(JSON.stringify({
      type: "result",
      payload: {
        success: true,
        draftId,
        questions,
        verification,
        jobTitle,
        detectedFromJD: jobContext.detectedFromJD
      }
    }) + "\n");
    return res.end();

  } catch (err) {
    console.error("[standalone-exam] Error:", err.message);
    try {
      res.write(JSON.stringify({ type: "result", success: false, error: `Failed to generate and verify exam: ${err.message}` }) + "\n");
    } catch (e) {}
    return res.end();
  } finally {
    cleanupFiles(filePaths);
  }
});

app.post("/api/exam-pools/save-draft", async (req, res) => {
  const { draftId } = req.body || {};
  if (!draftId) {
    return res.status(400).json({ error: "No draftId provided." });
  }

  const client = await pool.connect();
  try {
    await client.query("BEGIN");

    // FOR UPDATE locks the row for the rest of this transaction, so a
    // double-click on Save can't race two saves of the same draft.
    const draftRes = await client.query(
      `SELECT draft_id, job_title, jd_text, questions
       FROM exam_drafts WHERE draft_id = $1 FOR UPDATE`,
      [draftId]
    );

    if (draftRes.rows.length === 0) {
      await client.query("ROLLBACK");
      return res.status(404).json({ error: "Exam draft not found or expired. Please regenerate." });
    }

    const draft = draftRes.rows[0];
    const questions = draft.questions; // node-postgres parses JSONB into a JS value automatically

    const poolId = "pool_" + Date.now();
    await client.query(
      `INSERT INTO exam_pools (id, employer_id, job_title, jd_text)
       VALUES ($1, NULL, $2, $3)`,
      [poolId, draft.job_title, draft.jd_text]
    );

    const questionIds = [];
    for (const q of questions) {
      const qRes = await client.query(
        `INSERT INTO exam_questions (pool_id, question, options, correct_index, difficulty)
         VALUES ($1, $2, $3, $4, $5) RETURNING id`,
        [poolId, q.question, JSON.stringify(q.options), q.correct, q.difficulty || "medium"]
      );
      questionIds.push(qRes.rows[0].id);
    }

    await client.query(`DELETE FROM exam_drafts WHERE draft_id = $1`, [draftId]);
    await client.query("COMMIT");

    console.log(`[standalone-exam] ✓ Saved pool ${poolId} ("${draft.job_title}") with ${questionIds.length} questions.`);
    return res.json({ success: true, poolId, totalSaved: questionIds.length });
  } catch (err) {
    await client.query("ROLLBACK");
    console.error("[standalone-exam] save-draft error:", err);
    return res.status(500).json({ error: "Failed to save exam to the library." });
  } finally {
    client.release();
  }
});

// Backs the per-question "🔄 Regenerate" button (both the batch exam modal
// and the standalone draft modal). Looks up the JD context + existing
// questions by batchId (in-memory) or draftId (DB, since drafts aren't kept
// in memory), generates ONE replacement question, and hands it back —
// the client swaps it into its local questions[idx] and marks that
// question as needing re-verification.
app.post("/api/exam-pools/regenerate-question", async (req, res) => {
  const { batchId, draftId, difficulty } = req.body || {};
  if (!batchId && !draftId) {
    return res.status(400).json({ error: "Missing batchId or draftId." });
  }

  // Streamed NDJSON: real per-attempt events from the single AI call, then
  // a final "result" line — no client-side timer faking the wait.
  res.setHeader("Content-Type", "application/x-ndjson; charset=utf-8");
  res.setHeader("X-Accel-Buffering", "no");
  res.flushHeaders && res.flushHeaders();
  const sendProgress = (obj) => {
    try { res.write(JSON.stringify({ type: "progress", ...obj }) + "\n"); }
    catch (e) { console.warn("[regenerate-question stream] write failed:", e.message); }
  };

  try {
    sendProgress({ step: "loading_context", percent: 5, message: "Loading exam context…" });
    let jdText, existingQuestions;

    if (batchId) {
      const batch = global.batchesStore[batchId];
      if (!batch) {
        res.write(JSON.stringify({ type: "result", success: false, error: "Batch not found." }) + "\n");
        return res.end();
      }
      jdText = batch.jdContext;
      existingQuestions = batch.examQuestions || [];
    } else {
      const draftRes = await pool.query(
        `SELECT jd_text, questions FROM exam_drafts WHERE draft_id = $1`,
        [draftId]
      );
      if (draftRes.rows.length === 0) {
        res.write(JSON.stringify({ type: "result", success: false, error: "Exam draft not found or expired. Please regenerate the exam." }) + "\n");
        return res.end();
      }
      jdText = draftRes.rows[0].jd_text;
      existingQuestions = draftRes.rows[0].questions || [];
    }

    if (!jdText) {
      res.write(JSON.stringify({ type: "result", success: false, error: "No job description context available for this exam." }) + "\n");
      return res.end();
    }

    const diff = ["easy", "medium", "hard", "expert"].includes(difficulty) ? difficulty : "medium";

    const raw = await callOpenRouterAI({
      model:        EXAM_MODEL,
      prompt:       buildSingleQuestionPrompt(jdText, diff, existingQuestions),
      maxTokens:    1500,
      expectedJson: "object",
      onAttempt:    makeAttemptProgress(sendProgress, 10, 95, "Regenerating question with AI")
    });

    const question = {
      question:   raw?.question,
      options:    raw?.options,
      correct:    raw?.correct,
      difficulty: raw?.difficulty || diff
    };

    const errors = validateExamQuestion(question, 0);
    if (errors.length > 0) {
      throw new Error(`AI returned a malformed question: ${errors.join("; ")}`);
    }

    // Give the regenerated question its own independent verification pass
    // — a separate, fresh AI call (verifyExamQuestions, the same function
    // used for the full 15-question exam) rather than just assuming it's
    // fine or leaving it permanently marked "needs review". This call
    // never sees the prompt or reasoning that produced the question above,
    // same isolation guarantee as the batch verifier. A failure here
    // (rate limit, timeout) is non-fatal — verifyExamQuestions already
    // falls back to an honest "verification unavailable" result instead
    // of throwing away the newly-generated question.
    sendProgress({ step: "verifying", percent: 90, message: "Verifying regenerated question with AI…" });
    const verification = await verifyExamQuestions([{ ...question, id: 1 }], sendProgress, [90, 99]);
    const verificationResult = verification.results[0] || null;

    sendProgress({ step: "done", percent: 100, message: "Question ready." });
    res.write(JSON.stringify({ type: "result", payload: { success: true, question, verificationResult } }) + "\n");
    return res.end();
  } catch (err) {
    console.error("[regenerate-question] Error:", err.message);
    try {
      res.write(JSON.stringify({ type: "result", success: false, error: `Failed to regenerate question: ${err.message}` }) + "\n");
    } catch (e) {}
    return res.end();
  }
});

// Hiring is generic/any-position now, so this is just one shared library —
// no per-posting scoping/filtering.
app.get("/api/exam-pools", async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT ep.id, ep.job_title, ep.created_at, COUNT(eq.id)::int AS question_count
       FROM exam_pools ep LEFT JOIN exam_questions eq ON eq.pool_id = ep.id
       GROUP BY ep.id ORDER BY ep.created_at DESC`
    );
    res.json({ success: true, pools: result.rows });
  } catch (err) {
    console.error("[exam-pools list error]", err);
    res.status(500).json({ error: "Failed to fetch saved exams." });
  }
});

app.get("/api/exam-pools/:poolId", async (req, res) => {
  try {
    const poolResult = await pool.query(`SELECT * FROM exam_pools WHERE id = $1`, [req.params.poolId]);
    if (poolResult.rows.length === 0) return res.status(404).json({ error: "Saved exam not found." });

    const questionsResult = await pool.query(
      `SELECT id, question, options, correct_index, difficulty FROM exam_questions WHERE pool_id = $1 ORDER BY id ASC`,
      [req.params.poolId]
    );
    res.json({ success: true, pool: poolResult.rows[0], questions: questionsResult.rows });
  } catch (err) {
    console.error("[exam-pools detail error]", err);
    res.status(500).json({ error: "Failed to fetch exam details." });
  }
});

// Lets a recruiter fix a saved exam pool's job-title label after the fact.
// Only job_title is editable; the questions and JD context that were
// actually used to generate this pool are left as-is, since relabeling
// shouldn't rewrite what was actually generated.
app.patch("/api/exam-pools/:poolId", async (req, res) => {
  const { jobTitle } = req.body || {};
  if (typeof jobTitle !== "string" || !jobTitle.trim()) {
    return res.status(400).json({ error: "jobTitle is required and must be a non-empty string." });
  }
  try {
    const result = await pool.query(
      `UPDATE exam_pools SET job_title = $1 WHERE id = $2 RETURNING id, job_title`,
      [jobTitle.trim(), req.params.poolId]
    );
    if (result.rows.length === 0) return res.status(404).json({ error: "Saved exam not found." });
    console.log(`[exam-pools] ✓ Relabeled pool ${req.params.poolId} → "${result.rows[0].job_title}"`);
    res.json({ success: true, pool: result.rows[0] });
  } catch (err) {
    console.error("[exam-pools rename error]", err);
    res.status(500).json({ error: "Failed to update saved exam." });
  }
});

app.delete("/api/exam-pools/:poolId", async (req, res) => {
  try {
    const result = await pool.query(`DELETE FROM exam_pools WHERE id = $1 RETURNING id`, [req.params.poolId]);
    if (result.rows.length === 0) return res.status(404).json({ error: "Saved exam not found." });
    res.json({ success: true });
  } catch (err) {
    console.error("[exam-pools delete error]", err);
    res.status(500).json({ error: "Failed to delete saved exam." });
  }
});

app.post("/api/batches/:batchId/use-pool/:poolId", async (req, res) => {
  const batch = global.batchesStore[req.params.batchId];
  if (!batch) return res.status(404).json({ error: "Batch not found. Run AI Matching for this job posting first." });

  try {
    const questionsResult = await pool.query(
      `SELECT id, question, options, correct_index, difficulty FROM exam_questions WHERE pool_id = $1 ORDER BY id ASC`,
      [req.params.poolId]
    );
    if (questionsResult.rows.length === 0)
      return res.status(404).json({ error: "Saved exam has no questions." });

    const examQuestions = questionsResult.rows.map(r => ({
      id:         r.id,
      question:   r.question,
      options:    r.options,
      correct:    r.correct_index,
      difficulty: r.difficulty
    }));

    batch.examQuestions = examQuestions;
    batch.poolId        = req.params.poolId;
    batch.status        = "generated";
    batch.isVerified    = true;
    batch.verifiedAt    = new Date().toISOString();
    batch.verification  = {
      verifiedAt:  batch.verifiedAt,
      results:     examQuestions.map(q => ({ id: q.id, verified: true, issue: null, suggestedCorrect: null })),
      issuesFound: 0,
      reused:      true
    };

    // Distributing a saved pool to a batch is meant to go live immediately
    // (there's no separate "Approve & Deploy" step in the Saved Exams UI),
    // so mirror what /approve-exam does: mark the batch approved and flip
    // every candidate in it to ready_to_take. Without this, the exam is
    // attached to the batch but stays invisible to applicants forever.
    batch.isApproved = true;
    batch.approvedAt = new Date().toISOString();

    try {
      await pool.query(
        `UPDATE batch_exams SET is_approved = true, updated_at = now() WHERE batch_id = $1`,
        [batch.batchId]
      );
    } catch (dbErr) {
      console.error("[standalone-exam] DB approval update failed:", dbErr.message);
    }

    // MATCH-GATE: same low-match exclusion as /approve-exam — see
    // isRejectedCandidate(). This path skipped it before, which meant
    // reusing a saved exam pool deployed it to rejected candidates too.
    let deployedCount = 0;
    let skippedRejected = 0;
    for (const cand of Object.values(global.candidatesStore)) {
      if (cand.batchId === batch.batchId) {
        if (isRejectedCandidate(cand)) {
          skippedRejected++;
          continue;
        }
        cand.examStatus = "ready_to_take";
        await persistCandidate(cand.id);
        deployedCount++;
      }
    }

    console.log(`[standalone-exam] ✓ Reused saved pool ${req.params.poolId} for batch ${batch.batchId}, deployed to ${deployedCount} candidate(s) (${skippedRejected} low-match candidate(s) skipped)`);
    await persistBatch(batch.batchId);
    res.json({ success: true, questions: examQuestions, verification: batch.verification, status: batch.status, deployedCount, skippedRejected });
  } catch (err) {
    console.error("[use-pool error]", err);
    res.status(500).json({ error: "Failed to load saved exam into batch." });
  }
});

// A single AI model now handles both generation and verification (see
// EXAM_MODEL below). What makes verification an independent check is NOT
// which model answers — it's that generation and verification are always
// two separate API calls with two separate, freshly-built messages[]
// arrays. The verifier is never shown the generator's prompt, reasoning,
// or conversation; it only receives the finished questions, cold, and is
// instructed to work out the correct answer itself before comparing it to
// what was marked correct (see buildExamVerificationPrompt below).

const EXAM_MODEL = "poolside/laguna-s-2.1:free";


// Verification gets its own model, decoupled from EXAM_MODEL above.
// buildExamVerificationPrompt instructs the model to "work out the correct
// answer for yourself first" before comparing — an invitation to reason
// step-by-step — and cohere/north-mini-code:free reliably burns its whole
// token budget on hidden chain-of-thought on that instruction and hits
// finish_reason:"length" instead of returning JSON (regardless of maxTokens
// or the /no_think hint), typically after ~35-50s per attempt x 3 retries.
// EXAM_MODEL's own generation prompt doesn't ask it to reason step-by-step,
// so there's no evidence generation has the same problem — this only
// repoints the verification call.

const EXAM_VERIFY_MODEL = "nvidia/nemotron-3.5-lightning:free";
//poolside/laguna-s-2.1:free

function buildExamVerificationPrompt(questions) {
  const stripped = questions.map(q => ({
    id: q.id,
    question: q.question,
    options: q.options,
    markedCorrect: q.correct
  }));
// Exam evaluator//
  return `You are an independent technical exam quality reviewer. You are checking
someone else's work — you did not write these questions.

<task>
For EACH question below, first work out for yourself which option is
correct, based purely on the question and options — do not assume the
"markedCorrect" index is right. Only after you've decided independently,
compare your answer to "markedCorrect".
</task>

<rules>
- "verified" must be true ONLY if your independently-determined correct
  option matches "markedCorrect" AND the question is clear and has exactly
  one defensible correct answer.
- You are NOT given the job description on purpose — you're only checking
  whether the question stands on its own as a piece of technical knowledge.
  If a question references "the job description", "this role", "this
  posting", or otherwise can't be answered without external context you
  weren't given (e.g. "Which database is listed in the job description?"),
  that itself means the question is invalid: set "verified" to false and
  "issue" to something like "question depends on the job posting text
  rather than testing actual knowledge — rewrite as a real technical
  question about the underlying skill."
- If "verified" is false, set "issue" to a short (1 sentence) explanation
  (e.g. "markedCorrect is wrong, option 2 is actually correct", "question is
  ambiguous — options 1 and 3 are both defensible", "question is unclear").
- If "verified" is false because a specific option should have been marked
  correct instead, set "suggestedCorrect" to that option's zero-based index.
  Otherwise set "suggestedCorrect" to null.
- Return exactly one result object per question, in the SAME ORDER given,
  using the SAME "id" values.
- Do not include any explanation, markdown, or text outside the JSON array.
</rules>

<output_format>
Return ONLY a valid JSON array.
Start your response with [ and end with ]
</output_format>

<questions_to_verify>
${JSON.stringify(stripped, null, 2)}
</questions_to_verify>`;
}

// Takes the evaluator's feedback (the flagged questions + their "issue" /
// "suggestedCorrect") and hands it back to the generator so it can FIX just
// those questions, instead of throwing away and regenerating the whole
// 15-question set. This is a separate, fresh messages[] context from both
// the original generation call and the verification call — the model sees
// only this prompt, not its own prior output as a running conversation.
function buildExamFixPrompt(jdText, flaggedQuestions) {
  const feedback = flaggedQuestions.map(f => ({
    id:               f.id,
    question:         f.question,
    options:          f.options,
    markedCorrect:    f.correct,
    difficulty:       f.difficulty,
    reviewerIssue:    f.issue,
    reviewerSuggestedCorrect: f.suggestedCorrect
  }));
// Exam revision//
  return `You are a technical hiring specialist revising exam questions that an
independent reviewer flagged as having a problem.

<task>
For EACH question below, a reviewer explained what's wrong with it in
"reviewerIssue" (and, when applicable, which option they believe is
actually correct in "reviewerSuggestedCorrect"). Rewrite each question so
the problem is fixed. You may keep the question mostly as-is and just
correct the answer key, or rewrite the question/options entirely if that's
what the issue requires — use your judgment based on "reviewerIssue".
</task>

<rules>
- Return exactly one corrected question per input question, in the SAME
  ORDER, using the SAME "id" values.
- Each corrected question must have exactly 4 answer options.
- Do NOT use "All of the above" or "None of the above".
- Keep the SAME "difficulty" value given for each question.
- Do not omit any key.
- Use the job description ONLY to decide which technologies/skills are in scope — never write a question about the job description itself. If a question asks the candidate to recall what's "listed" or "mentioned" in the posting, rewrite it to test real knowledge of that technology instead.
</rules>

<output_format>
Return ONLY a valid JSON array, one object per flagged question.
Start your response with [ and end with ]
No explanation, no markdown, no extra text before or after.

Each object MUST match this exact structure and field names:

{
  "id": 3,
  "question": "corrected question text",
  "options": ["opt A", "opt B", "opt C", "opt D"],
  "correct": 1,
  "difficulty": "medium"
}
</output_format>

<job_description>
${jdText}
</job_description>

<flagged_questions>
${JSON.stringify(feedback, null, 2)}
</flagged_questions>`;
}

// Takes single-question prompt used by the "Regenerate" button (shared)
// buildSingleQuestionPrompt is referenced elsewhere
function buildSingleQuestionPrompt(jdText, difficulty, existingQuestions) {
  const existingList = (existingQuestions || [])
    .map((q, i) => `${i + 1}. ${q.question}`)
    .join("\n");

  return `You are a technical hiring specialist writing ONE replacement exam question.

<task>
Generate exactly ONE new multiple-choice question at "${difficulty}" difficulty
to assess job readiness, based on the job description below. This question
will replace one question on an existing exam, so it must be clearly
different from the questions already on that exam (not a rephrasing of any
of them) — see <existing_questions> below.
</task>

<rules>
- Exactly 4 answer options.
- Do NOT use "All of the above" or "None of the above".
- The question must be at "${difficulty}" difficulty.
- Use the job description ONLY to decide which technologies, tools, languages, and concepts are in scope — never write a question about the job description itself.
- The question must be answerable by someone with genuine hands-on knowledge of that technology/skill who has NEVER seen this job posting. If the only way to get it right is to have read this specific JD text, it's invalid (e.g. "Which database is listed in the job description?" is invalid — ask a real question about that database instead).
- Do not duplicate or closely rephrase any question in <existing_questions>.
</rules>

<output_format>
Return ONLY a single valid JSON object.
Start your response with { and end with }
No explanation, no markdown, no extra text before or after.

{
  "question": "What does the acronym API stand for?",
  "options": ["Application Programming Interface", "Automated Process Integration", "Advanced Protocol Interchange", "Application Process Index"],
  "correct": 0,
  "difficulty": "${difficulty}"
}

"correct" must be the 0-based index (an integer from 0 to 3) into "options".
Do not rename "correct". Do not omit any key.
</output_format>

<job_description>
${jdText}
</job_description>

<existing_questions>
${existingList || "(none)"}
</existing_questions>`;
}

// =============================================================================
// AI CALL HELPER & ERROR HANDLING
// =============================================================================

const AI_TIMEOUT_MS  = 45000;
const AI_MAX_RETRIES = 3;

function stripReasoningTrace(text) {
  return text.replace(/<think>[\s\S]*?<\/think>/gi, "").trim();
}

function extractBalancedJSON(text, openChar, closeChar) {
  const start = text.indexOf(openChar);
  if (start === -1) return null;

  let depth = 0;
  let inString = false;
  let escapeNext = false;

  for (let i = start; i < text.length; i++) {
    const ch = text[i];
    if (escapeNext) { escapeNext = false; continue; }
    if (ch === "\\") { escapeNext = true; continue; }
    if (ch === '"') { inString = !inString; continue; }
    if (inString) continue;

    if (ch === openChar) depth++;
    else if (ch === closeChar) {
      depth--;
      if (depth === 0) return text.slice(start, i + 1);
    }
  }
  return null;
}

// LLMs frequently emit a trailing comma before a closing } or ] (e.g. in the
// last item of an array/object). That's invalid JSON and JSON.parse rejects
// it outright ("Expected property name or '}' in JSON..."). This walks the
// text respecting string boundaries (so commas inside string values are never
// touched) and drops any comma that's only followed by whitespace and then a
// closing brace/bracket.
function stripTrailingCommas(text) {
  let result = "";
  let inString = false;
  let escapeNext = false;

  for (let i = 0; i < text.length; i++) {
    const ch = text[i];

    if (escapeNext) { result += ch; escapeNext = false; continue; }
    if (ch === "\\") { result += ch; escapeNext = true; continue; }
    if (ch === '"') { inString = !inString; result += ch; continue; }

    if (!inString && ch === ",") {
      let j = i + 1;
      while (j < text.length && /\s/.test(text[j])) j++;
      if (text[j] === "}" || text[j] === "]") {
        continue; // drop this trailing comma
      }
    }

    result += ch;
  }

  return result;
}

// A third common LLM mistake: an unquoted (or bare-identifier) object key,
// e.g. `{ correct: 2, difficulty: "easy" }` instead of `{ "correct": 2, ... }`.
// JSON.parse rejects this with "Expected property name or '}'" — the exact
// error this repair targets. This walks the text respecting string
// boundaries, and whenever it sees an identifier (letters/digits/_/$) in a
// key position (immediately preceded, ignoring whitespace, by "{" or ",",
// and immediately followed, ignoring whitespace, by ":") it wraps that
// identifier in double quotes. Bare words that aren't in key position
// (e.g. the `true`/`false`/`null` in a value, or numbers) are left alone
// because they won't be followed by ":".
function quoteUnquotedKeys(text) {
  let result = "";
  let inString = false;
  let escapeNext = false;
  let i = 0;

  while (i < text.length) {
    const ch = text[i];

    if (inString) {
      result += ch;
      if (escapeNext) { escapeNext = false; i++; continue; }
      if (ch === "\\") { escapeNext = true; i++; continue; }
      if (ch === '"') inString = false;
      i++;
      continue;
    }

    if (ch === '"') { inString = true; result += ch; i++; continue; }

    if (/[A-Za-z_$]/.test(ch)) {
      let k = result.length - 1;
      while (k >= 0 && /\s/.test(result[k])) k--;
      const prevChar = k >= 0 ? result[k] : "";

      let j = i;
      while (j < text.length && /[A-Za-z0-9_$]/.test(text[j])) j++;
      const ident = text.slice(i, j);

      let m = j;
      while (m < text.length && /\s/.test(text[m])) m++;
      const nextChar = text[m];

      result += (prevChar === "{" || prevChar === ",") && nextChar === ":"
        ? `"${ident}"`
        : ident;
      i = j;
      continue;
    }

    result += ch;
    i++;
  }

  return result;
}

// A fourth mistake: multiple consecutive trailing commas (e.g. `"a",,}` or
// `"a", ,}`), which stripTrailingCommas' single-pass lookahead doesn't fully
// collapse (dropping one comma can still leave another sitting directly
// before the closing brace/bracket). This repeats the strip until the text
// stops changing, so any number of stray commas in a row get cleaned up.
function stripTrailingCommasRepeated(text) {
  let prev;
  let current = text;
  do {
    prev = current;
    current = stripTrailingCommas(current);
  } while (current !== prev);
  return current;
}

// A fifth mistake: a duplicated opening brace at the start of an object,
// e.g. `[ ..., {  { "question": ... }, ... ]` instead of a single `{`. Valid
// JSON never has two "{" directly adjacent (only whitespace between) — an
// object's opening brace is always followed by a quoted key or a lone "}",
// never by another "{". So this collapse is safe globally: it walks the
// text respecting string boundaries and merges any run of 2+ consecutive
// "{" (ignoring whitespace between them) down to a single "{".
function collapseDuplicateOpenBraces(text) {
  let result = "";
  let inString = false;
  let escapeNext = false;
  let i = 0;

  while (i < text.length) {
    const ch = text[i];

    if (inString) {
      result += ch;
      if (escapeNext) { escapeNext = false; i++; continue; }
      if (ch === "\\") { escapeNext = true; i++; continue; }
      if (ch === '"') inString = false;
      i++;
      continue;
    }

    if (ch === '"') { inString = true; result += ch; i++; continue; }

    if (ch === "{") {
      let j = i + 1;
      while (j < text.length && /\s/.test(text[j])) j++;
      if (text[j] === "{") {
        // Duplicate found: keep one "{" (and the whitespace before the
        // duplicate, for readability) and skip the redundant brace.
        result += "{" + text.slice(i + 1, j);
        i = j + 1;
        continue;
      }
    }

    result += ch;
    i++;
  }

  return result;
}

// A second common LLM mistake: a raw/literal newline, tab, or carriage
// return sitting inside a JSON string value instead of being escaped as
// \n, \t, \r. JSON.parse rejects raw control characters inside strings.
// This walks the text respecting string boundaries and escapes them in place.
function escapeControlCharsInStrings(text) {
  let result = "";
  let inString = false;
  let escapeNext = false;

  for (let i = 0; i < text.length; i++) {
    const ch = text[i];

    if (escapeNext) { result += ch; escapeNext = false; continue; }
    if (ch === "\\") { result += ch; escapeNext = true; continue; }
    if (ch === '"') { inString = !inString; result += ch; continue; }

    if (inString) {
      if (ch === "\n") { result += "\\n"; continue; }
      if (ch === "\r") { result += "\\r"; continue; }
      if (ch === "\t") { result += "\\t"; continue; }
    }

    result += ch;
  }

  return result;
}

function parseAIJson(raw, expected) {
  let text = stripReasoningTrace(raw);
  text = text.replace(/```json/gi, "").replace(/```/g, "").trim();

  const [openChar, closeChar] = expected === "array" ? ["[", "]"] : ["{", "}"];
  const block = extractBalancedJSON(text, openChar, closeChar);

  if (!block) {
    console.error("[ai-json] No balanced JSON block found. Raw AI output was:\n", raw);
    throw new Error(
      `AI response did not contain a complete, balanced JSON ${expected}. ` +
      `It was likely cut off mid-generation (reasoning trace may have used up the token budget).`
    );
  }

  // Try progressively more aggressive repairs before giving up. Each fixes a
  // distinct, independent LLM mistake, so we chain combinations of all of
  // them rather than just each one alone — real responses often have more
  // than one problem at once (e.g. an unquoted key AND a trailing comma).
  const repairs = [escapeControlCharsInStrings, stripTrailingCommasRepeated, quoteUnquotedKeys, collapseDuplicateOpenBraces];
  const attempts = [block];
  for (let mask = 1; mask < 1 << repairs.length; mask++) {
    let candidate = block;
    for (let bit = 0; bit < repairs.length; bit++) {
      if (mask & (1 << bit)) candidate = repairs[bit](candidate);
    }
    attempts.push(candidate);
  }

  let firstError = null;
  for (const candidate of attempts) {
    try {
      return JSON.parse(candidate);
    } catch (e) {
      if (!firstError) firstError = e;
    }
  }

  // Every repair attempt failed — log the exact neighborhood of the failure
  // so this is debuggable instead of a guessing game (prints server-side).
  const pos = extractErrorPosition(firstError.message);
  if (pos !== null) {
    const start = Math.max(0, pos - 120);
    const end   = Math.min(block.length, pos + 120);
    console.error(
      `[ai-json] Parse failed at position ${pos}. Context (±120 chars):\n` +
      "----- START CONTEXT -----\n" +
      block.slice(start, pos) + "  <<<HERE>>>  " + block.slice(pos, end) +
      "\n----- END CONTEXT -----"
    );
  } else {
    console.error("[ai-json] Parse failed, full block:\n", block);
  }
  throw new Error(`AI returned malformed JSON: ${firstError.message}`);
}

function extractErrorPosition(message) {
  const m = /position (\d+)/.exec(message || "");
  return m ? parseInt(m[1], 10) : null;
}

// Validates that a CV-scoring response matches the exact schema the dashboard
// expects. Different models (esp. fallback models) don't reliably follow a
// schema that's only described in prose, so we check it explicitly here and
// fail loudly with a specific message rather than letting bad shape reach
// the client, where it previously crashed the whole matching run.
function validateScoringSchema(scoring) {
  const errors = [];
  const isNum = v => typeof v === "number" && Number.isFinite(v);

  if (!scoring || typeof scoring !== "object") {
    return ["scoring response is not a JSON object"];
  }
  if (!isNum(scoring.overall_score)) errors.push("missing/invalid 'overall_score' (expected number)");

  if (!scoring.categories || typeof scoring.categories !== "object") {
    errors.push("missing/invalid 'categories' object");
  } else {
    for (const key of ["technical_skills", "experience", "education", "soft_skills"]) {
      if (!isNum(scoring.categories[key])) errors.push(`missing/invalid 'categories.${key}' (expected number)`);
    }
  }

  if (typeof scoring.recommendation !== "string" || !scoring.recommendation.trim()) {
    errors.push("missing/invalid 'recommendation' (expected string)");
  }
  if (typeof scoring.recommendation_reason !== "string") errors.push("missing 'recommendation_reason' (expected string)");
  if (!Array.isArray(scoring.matched_keywords)) errors.push("missing/invalid 'matched_keywords' (expected array)");
  if (!Array.isArray(scoring.missing_keywords)) errors.push("missing/invalid 'missing_keywords' (expected array)");
  if (typeof scoring.strengths !== "string") errors.push("missing 'strengths' (expected string)");
  if (typeof scoring.summary !== "string") errors.push("missing 'summary' (expected string)");

  return errors;
}

// Validates a mapped exam question against the exact constraints the
// database schema enforces (exam_questions table): options must be a JSONB-
// friendly array, correct_index is a NOT NULL integer, difficulty must pass
// the CHECK constraint. Catching this here means a malformed AI response
// fails with a clear message at generation time, not as an opaque Postgres
// constraint error later at save time.
function validateExamQuestion(q, i) {
  const errors = [];
  const label = `Question ${i + 1}`;

  if (typeof q.question !== "string" || !q.question.trim()) {
    errors.push(`${label}: missing/invalid 'question' text`);
  }
  if (!Array.isArray(q.options) || q.options.length !== 4 || q.options.some(o => typeof o !== "string" || !o.trim())) {
    errors.push(`${label}: 'options' must be an array of exactly 4 non-empty strings`);
  }
  if (!Number.isInteger(q.correct) || q.correct < 0 || q.correct > 3) {
    errors.push(`${label}: 'correct' must be an integer 0-3`);
  }
  if (!["easy", "medium", "hard", "expert"].includes(q.difficulty)) {
    errors.push(`${label}: 'difficulty' must be one of easy/medium/hard/expert (got ${JSON.stringify(q.difficulty)})`);
  }

  return errors;
}

function validateExamQuestions(questions) {
  return questions.flatMap((q, i) => validateExamQuestion(q, i));
}

if (process.env.OPENROUTER_API_KEY) {
  process.env.ANTHROPIC_API_KEY  = process.env.OPENROUTER_API_KEY;
  process.env.ANTHROPIC_BASE_URL = "https://openrouter.ai/api";
}

const Client = new Anthropic({
  maxRetries: 0, // we run our own retry/backoff loop below, same as the old fetch() version did
  timeout:    AI_TIMEOUT_MS,
  defaultHeaders: {
    "HTTP-Referer": "http://localhost:4000",
    "X-Title": "AI Recruitment Assistant"
  }
});

async function callOpenRouterAI({ model, fallbackModels = [], system = null, prompt, maxTokens = 4096, expectedJson = null, maxRetries = AI_MAX_RETRIES, disableReasoning = true, ignoreProviders = [], onAttempt = null }) {
  if (!process.env.OPENROUTER_API_KEY || process.env.OPENROUTER_API_KEY === "your_api_key_here") {
    throw new Error("OPENROUTER_API_KEY is not configured on the server (.env).");
  }

  let lastError;

  // OpenRouter supports a `models` fallback array on this endpoint too: if the
  // primary model/provider errors out (e.g. a broken upstream provider like we
  // saw with Nvidia 404s), OpenRouter itself will try the next model in the
  // list before giving up.
  const modelChain = [model, ...fallbackModels];
  if (modelChain.length > 3) {
    throw new Error(`callOpenRouterAI: 'models' fallback chain has ${modelChain.length} entries, but OpenRouter allows 3 max (1 primary + 2 fallbacks). Trim fallbackModels.`);
  }

  for (let attempt = 1; attempt <= maxRetries; attempt++) {
    // Real signal, not a simulated tick: fires once per actual outbound
    // request/retry for this specific AI call, so callers can surface how
    // far the call has really gotten (e.g. "retry 2/3") instead of guessing
    // from elapsed time.
    if (onAttempt) { try { onAttempt(attempt, maxRetries); } catch (_) {} }

    const attemptStart = Date.now(); // wall-clock time for THIS attempt only — logged below whether it succeeds or fails, so slow models/stages show up directly in server logs instead of being guessed at.

    try {
      // Anthropic's Messages API takes `system` as its own top-level field
      // rather than a {role:"system"} message — e.g.:
      //
      //   anthropic.messages.create({
      //     model, max_tokens,
      //     system: "You are a senior software engineer...",
      //     messages: [{ role: "user", content: "..." }]   // user/assistant only
      //   });
      //
      // Callers pass their persona/instructions via the `system` param above
      // (see buildScoringSystemPrompt() for an example); the "/no_think"
      // reasoning-disable trick also lives in `system`, so if a caller
      // supplied their own system prompt AND disableReasoning is on, the two
      // are concatenated rather than one silently overwriting the other.
      const systemParts = [];
      if (system) systemParts.push(system);
      if (disableReasoning) systemParts.push("/no_think");

      const requestBody = {
        model,
        max_tokens: maxTokens,
        messages: [{ role: "user", content: prompt }],
      };
      if (modelChain.length > 1) requestBody.models = modelChain;
      if (systemParts.length > 0) requestBody.system = systemParts.join("\n\n");
      if (ignoreProviders.length > 0) requestBody.provider = { ignore: ignoreProviders };

      const message = await Client.messages.create(requestBody);

      if (message.stop_reason === "max_tokens") {
        // Not treated as fatal below: unlike the isFatal cases (bad model
        // config, daily quota exhausted) a length cutoff isn't guaranteed to
        // repeat — generation length varies between attempts, so it's worth
        // letting the normal retry loop below take another swing before
        // giving up. maxTokens should still be sized generously for the
        // expected output (see the 15-question exam prompt's maxTokens).
        throw new Error(
          "AI response was cut off before finishing (hit the token limit). " +
          "The source document may be too long, or the model's reasoning trace used up the budget."
        );
      }

      const content = (message.content || [])
        .filter(b => b.type === "text")
        .map(b => b.text)
        .join("")
        .trim();

      if (!content) {
        throw new Error("AI returned an empty response body (possibly reasoning-only output with no final answer).");
      }

      // The model that actually answered can differ from `model` (the
      // primary) if OpenRouter failed over to one of fallbackModels — log
      // which one it was, since a slow primary silently swapping to a
      // fallback is itself useful signal.
      const servedBy = message.model || model;
      console.log(`[ai] ${servedBy} responded in ${Date.now() - attemptStart}ms (attempt ${attempt}/${maxRetries})`);

      if (!expectedJson) return content;
      return parseAIJson(content, expectedJson);

    } catch (err) {
      const attemptMs = Date.now() - attemptStart;

      // The Anthropic SDK throws its own timeout error class instead of a
      // fetch AbortController firing — same "give up after AI_TIMEOUT_MS"
      // behavior, different signal to catch.
      if (err instanceof Anthropic.APIConnectionTimeoutError || err.name === "AbortError") {
        lastError = new Error(`AI request timed out after ${AI_TIMEOUT_MS / 1000}s (attempt ${attempt}/${maxRetries}).`);
        console.warn(`[ai] ${lastError.message}`);
        if (attempt < maxRetries) continue;
        break;
      }

      // The SDK throws Anthropic.APIError (or a subclass) for non-2xx
      // responses, with `.status` (HTTP status) and `.error` (parsed JSON
      // body) — this mirrors the old response.ok / data.error checks.
      const status    = err.status;
      const errorObj  = (err.error && (err.error.error || err.error)) || { message: err.message };
      const errorString = JSON.stringify(errorObj).toLowerCase();

      if (errorString.includes("embedding model") || errorString.includes("generate text")) {
        lastError = new Error("Configured model is an embedding model, not a text generation model. Please update model identifier in server.js.");
        console.error(`[ai] Fatal Error after ${attemptMs}ms: ${lastError.message}`);
        break;
      }

      if (status === 429 && (errorString.includes("free-models-per-day") || errorString.includes("daily reset"))) {
        lastError = new Error("Daily free-tier limit reached for this model. Add OpenRouter credits or wait for the daily reset.");
        console.error(`[ai] Fatal Error after ${attemptMs}ms: ${lastError.message}`);
        break;
      }

      if (status === 429 && attempt < maxRetries) {
        const wait = (errorObj?.metadata?.retry_after_seconds || 10) * 1000;
        console.warn(`[ai] 429 rate limited (attempt ${attempt}/${maxRetries}) — waiting ${wait / 1000}s…`);
        await new Promise(r => setTimeout(r, wait));
        continue;
      }

      if (status >= 500 && attempt < maxRetries) {
        const wait = attempt * 2000;
        console.warn(`[ai] ${status} server error (attempt ${attempt}/${maxRetries}) — retrying in ${wait / 1000}s…`);
        await new Promise(r => setTimeout(r, wait));
        continue;
      }

      lastError = status
        ? new Error(`AI API error (HTTP ${status}): ${JSON.stringify(errorObj)}`)
        : err;

      const retryable = attempt < maxRetries;
      console.warn(`[ai] ${model} attempt ${attempt}/${maxRetries} failed after ${attemptMs}ms: ${lastError.message}${retryable ? " — retrying…" : ""}`);
      if (retryable) {
        await new Promise(r => setTimeout(r, attempt * 1500));
        continue;
      }
      break;
    }
  }

  throw lastError || new Error("AI call failed after all retry attempts.");
}

function cleanupFiles(paths) {
  paths.forEach(p => {
    try { if (fs.existsSync(p)) fs.unlinkSync(p); }
    catch (e) { console.warn("Could not delete temp file:", p); }
  });
}

// =============================================================================
// SECTION 9: RESUME UPLOAD & AI SCORING ROUTE
// =============================================================================

// Replace the existing /api/upload handler with this streaming-capable implementation
app.post("/api/upload", uploadMiddleware, async (req, res) => {
  const filePaths = [];
  try {
    const jdFiles = req.files?.["jd"] || [];
    const cvFiles = req.files?.["cv"] || [];

    console.log(`\n[upload] JD: ${jdFiles.length} | CVs: ${cvFiles.length}`);

    if (jdFiles.length === 0)
      return res.status(400).json({ error: "No job description file received. Please upload a JD first." });
    if (cvFiles.length === 0)
      return res.status(400).json({ error: "No CV files received. Please upload at least one resume." });

    [...jdFiles, ...cvFiles].forEach(f => filePaths.push(f.path));

    // Streamed NDJSON response (one JSON object per line).
    res.setHeader("Content-Type", "application/x-ndjson; charset=utf-8");
    res.setHeader("X-Accel-Buffering", "no"); // for nginx buffering settings (if present)
    res.flushHeaders && res.flushHeaders(); // ensure headers are sent immediately

    const sendProgress = (obj) => {
      try {
        res.write(JSON.stringify({ type: "progress", ...obj }) + "\n");
      } catch (e) {
        console.warn("[upload stream] write failed:", e.message);
      }
    };

    sendProgress({ step: "starting", percent: 1, message: `Starting processing (${cvFiles.length} CV(s))` });

    console.log(`[1/3] Extracting JD: "${jdFiles[0].originalname}"`);
    let jdText;
    try {
      jdText = await extractText(jdFiles[0].path, jdFiles[0].originalname);
    } catch (e) {
      // send final error as result event then end
      res.write(JSON.stringify({ type: "result", success: false, error: `Job description error: ${e.message}` }) + "\n");
      return res.end();
    }

    if (jdText.length < 50) {
      res.write(JSON.stringify({ type: "result", success: false, error: "The job description is too short (min 50 chars). Please upload a complete JD." }) + "\n");
      return res.end();
    }

    const MAX_JD_CHARS = 4000;
    const truncatedJD  = jdText.length > MAX_JD_CHARS
      ? jdText.slice(0, MAX_JD_CHARS) + "\n[JD truncated for length]"
      : jdText;

    sendProgress({ step: "jd_extracted", percent: 5, message: `JD extracted (${truncatedJD.length} chars)` });
    console.log(`[2/3] Processing ${cvFiles.length} CV(s)…`);

    const results = [];
    const total = cvFiles.length;

    for (let i = 0; i < cvFiles.length; i++) {
      const cvFile = cvFiles[i];
      const idx = i + 1;

      sendProgress({ step: "extracting_cv", percent: Math.round(5 + (idx - 1) / total * 15), message: `Extracting CV ${idx}/${total}: ${cvFile.originalname}` });
      console.log(`\n      [CV ${idx}/${total}] "${cvFile.originalname}"`);

      let rawCV;
      try {
        rawCV = await extractText(cvFile.path, cvFile.originalname);
      } catch (e) {
        console.error(`      → Extraction failed: ${e.message}`);
        results.push({ filename: cvFile.originalname, error: e.message });
        // update progress and continue
        sendProgress({ step: "cv_error", percent: Math.round(5 + (idx) / total * 15), message: `Extraction error for ${cvFile.originalname}` });
        continue;
      }

      if (rawCV.length < 15) {
        const msg = `"${cvFile.originalname}" has too little text (min 30 chars).`;
        results.push({ filename: cvFile.originalname, error: msg });
        sendProgress({ step: "cv_error", percent: Math.round(5 + (idx) / total * 15), message: `${cvFile.originalname} too short` });
        continue;
      }

      const MAX_CV_CHARS = 5000;
      const truncatedCV  = rawCV.length > MAX_CV_CHARS
        ? rawCV.slice(0, MAX_CV_CHARS) + "\n[CV truncated for length]"
        : rawCV;

      if (rawCV.length > MAX_CV_CHARS)
        console.log(`      → CV truncated from ${rawCV.length} to ${MAX_CV_CHARS} chars`);

      const cvStartPct = Math.round(35 + (idx - 1) / total * 40);
      const cvEndPct   = Math.round(35 + idx / total * 40);
      sendProgress({ step: "sending_ai", percent: cvStartPct, message: `Sending CV ${idx}/${total} to AI scoring…` });
      console.log(`[3/3] Sending "${cvFile.originalname}" to AI…`);
      try {
      
        const scoring = await callOpenRouterAI({
          model:        "thinkingmachines/inkling-small:free",
          fallbackModels: [
            "poolside/laguna-s-2.1:free",
            "nvidia/nemotron-3.5-lightning:free"
          ],
          system:       buildScoringSystemPrompt(),
          prompt:       buildScoringUserPrompt(truncatedJD, truncatedCV),
          maxTokens:    7000,
          expectedJson: "object",
          onAttempt:    makeAttemptProgress(sendProgress, cvStartPct, cvEndPct, `Scoring CV ${idx}/${total} (${cvFile.originalname})`)
        });

        const schemaErrors = validateScoringSchema(scoring);
        if (schemaErrors.length > 0) {
          throw new Error(`AI returned an unexpected scoring format: ${schemaErrors.join("; ")}`);
        }

        const candidateId   = `cand-${Date.now()}-${Math.floor(Math.random() * 10000)}`;
        const applicationId = `APP-${Math.floor(100000 + Math.random() * 900000)}`;

        global.candidatesStore[candidateId] = {
            id: candidateId,
            applicationId: applicationId,
            name: cvFile.originalname.replace(/\.[^.]+$/, ""),
            score: scoring.overall_score,
            scoringData: scoring,
            jdContext: truncatedJD,
            examStatus: "pending",
            examScore: null,
            examQuestions: null,
            examAnswers: null,
            examDetails: null,
            // HR-INTERVIEW-STATUS: explicit flag HR sets once the live/HR
            // interview itself has actually happened, independent of
            // examStatus. Drives both the recruiter dashboard's status pill
            // ("Proceed to Interview" -> "For Final Assessment") and the
            // applicant portal's tracker ("HR interview" -> "Final interview").
            hrInterviewCompleted: false,
            createdAt: new Date().toISOString()
        };
        await persistCandidate(candidateId);

        results.push({
            filename: cvFile.originalname,
            success: true,
            candidateId,
            applicationId,
            scoring
        });

        sendProgress({ step: "ai_response", percent: cvEndPct, message: `Received AI score for ${cvFile.originalname}` });
        console.log(`✓ Candidate Created | Candidate ID: ${candidateId} | Application ID: ${applicationId}`);
        console.log(`✓ Score: ${scoring.overall_score}% | Rec: ${scoring.recommendation}`);

      } catch (e) {
        console.error(`      → AI error for "${cvFile.originalname}":`, e.message);
        results.push({ filename: cvFile.originalname, error: e.message });
        sendProgress({ step: "ai_error", percent: cvEndPct, message: `AI error for ${cvFile.originalname}: ${e.message}` });
      }
    }

    // Create batch
    const successfulIds = results.filter(r => r.success).map(r => r.candidateId);
    sendProgress({ step: "creating_batch", percent: 80, message: `Creating candidate batch...` });
    const newBatchId    = await createCandidateBatch(truncatedJD);

    let assigned = 0;
    for (const id of successfulIds) {
      if (global.candidatesStore[id]) {
        global.candidatesStore[id].batchId = newBatchId;
        global.batchesStore[newBatchId].candidateIds.push(id);
        await persistCandidate(id);
        assigned++;
        // partial progress while assigning
        const assignPct = 80 + Math.round((assigned / successfulIds.length) * 15);
        sendProgress({ step: "assigning_candidate", percent: assignPct, message: `Assigned ${assigned}/${successfulIds.length} candidate(s) to batch` });
      }
    }
    await persistBatch(newBatchId);

    // Finalize & emit final result object
    const finalPayload = {
      success: true,
      jd_title: jdFiles[0].originalname,
      count: results.length,
      batchId: newBatchId,
      results
    };

    sendProgress({ step: "done", percent: 100, message: `Processing complete. ${successfulIds.length} candidate(s) processed.` });
    // Final payload sent as a 'result' event. Client will parse this to finish.
    res.write(JSON.stringify({ type: "result", payload: finalPayload }) + "\n");
    return res.end();

  } catch (err) {
    console.error("[upload] Unhandled error:", err.message);
    try {
      if (!res.headersSent) {
        res.write(JSON.stringify({ type: "result", success: false, error: err.message || "Unexpected server error." }) + "\n");
      } else {
        res.write(JSON.stringify({ type: "progress", step: "fatal", percent: 100, message: "Unexpected server error." }) + "\n");
      }
    } catch (e) {}
    return res.end();
  } finally {
    cleanupFiles(filePaths);
  }
});

// =============================================================================
// SECTION 10: CANDIDATE ROUTES
// =============================================================================

app.get("/api/candidates", (req, res) => {
  res.json({ success: true, candidates: Object.values(global.candidatesStore) });
});

app.get("/api/candidates/:id", (req, res) => {
  const candidate = global.candidatesStore[req.params.id];
  if (!candidate) return res.status(404).json({ error: "Candidate not found." });
  res.json({ success: true, candidate });
});

// =============================================================================
// SECTION: SAVED APPLICANTS DATABASE INTEGRATION
// =============================================================================

app.post("/api/applicants/save", async (req, res) => {
  const { applicationId, name, jobTitle, score, recommendation, examScore, content } = req.body || {};
  
  if (!applicationId || !name) return res.status(400).json({ error: "Missing required candidate data." });

  try {
    const result = await pool.query(
      `INSERT INTO saved_applicants 
        (application_id, candidate_name, job_title, match_score, recommendation, exam_score, content)
       VALUES ($1, $2, $3, $4, $5, $6, $7)
       ON CONFLICT (application_id) 
       DO UPDATE SET 
        match_score = EXCLUDED.match_score,
        recommendation = EXCLUDED.recommendation,
        exam_score = EXCLUDED.exam_score,
        content = EXCLUDED.content,
        updated_at = now()
       RETURNING id, application_id`,
      [applicationId, name, jobTitle, score, recommendation, examScore, content]
    );
    res.json({ success: true, saved: result.rows[0] });
  } catch (err) {
    console.error("[save-applicant error]", err);
    res.status(500).json({ error: "Failed to save applicant to database." });
  }
});

app.get("/api/applicants/saved", async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT id, application_id, candidate_name, job_title, match_score, recommendation, exam_score, content, created_at 
       FROM saved_applicants 
       ORDER BY created_at DESC`
    );
    res.json({ success: true, candidates: result.rows });
  } catch (err) {
    console.error("[get-saved error]", err);
    res.status(500).json({ error: "Failed to fetch saved applicants." });
  }
});

app.delete("/api/applicants/saved/:appId", async (req, res) => {
  try {
    const result = await pool.query(
      `DELETE FROM saved_applicants WHERE application_id = $1 RETURNING application_id`, 
      [req.params.appId]
    );
    if (result.rows.length === 0) return res.status(404).json({ error: "Applicant not found in database." });
    res.json({ success: true, message: "Applicant deleted." });
  } catch (err) {
    console.error("[delete-saved error]", err);
    res.status(500).json({ error: "Failed to delete applicant." });
  }
});

// =============================================================================
// SECTION 12: HEALTH CHECK
// =============================================================================
app.get("/api/health", (req, res) => {
  const hasKey = !!(process.env.OPENROUTER_API_KEY && process.env.OPENROUTER_API_KEY !== "your_api_key_here");
  res.json({
    status:     "ok",
    ai:         "OpenRouter",
    model:      "nvidia/nemotron-3.5-lightning:free",
    api_key:    hasKey ? "configured" : "MISSING — add OPENROUTER_API_KEY to .env",
    pdf_parser: "pdf-parse v2 (PDFParse class API)",
    db:         `${pool.options.user}@${pool.options.host}:${pool.options.port}/${pool.options.database}`,
    candidates: Object.keys(global.candidatesStore).length,
    port:       PORT,
  });
});

// =============================================================================
// INTERVIEW QUESTIONS & HR NOTES ENDPOINTS
// =============================================================================
// Interview question generation now lives at the job-posting level, exactly
// mirroring the [STANDALONE-EXAM-HANDLER] flow above: generate from the
// staged JD -> review a draft (interview_drafts, so a restart doesn't wipe
// an in-progress draft) -> explicitly "Save to Interview Library". Nothing
// here is tied to any one candidate's exam results anymore — a saved set is
// generic to the role and gets applied to individual candidates via
// /api/candidates/:candidateId/use-interview-pool/:poolId.

function buildInterviewPrompt(jdText, jobTitle) {
  return `You are an expert HR and technical recruiter designing a structured follow-up interview.

Job Title: ${jobTitle}

Job Description:
${jdText}

Task:
Generate exactly 5 open-ended interview questions to evaluate ANY candidate applying to this role — a mix of role-specific technical/functional depth and general job-readiness. These questions are not tied to any single candidate's exam results; they should work as a general interview question POOL for this job posting, from which a smaller set is later drawn per candidate.

The 5 questions MUST be strictly balanced across difficulty:
- Exactly 3 "easy" questions
- Exactly 1 "medium" question
- Exactly 1 "hard" question

Output Format:
Return ONLY a valid JSON array of 5 objects. No markdown backticks, no introduction, no extra text.
Each object must contain exactly three keys: "question" (the interview question), "answer" (a suggested reference answer for the interviewer), and "difficulty" (one of "easy", "medium", "hard").

Example shape (content is illustrative only):
[
  { "question": "...", "answer": "...", "difficulty": "easy" },
  { "question": "...", "answer": "...", "difficulty": "easy" },
  { "question": "...", "answer": "...", "difficulty": "easy" },
  { "question": "...", "answer": "...", "difficulty": "medium" },
  { "question": "...", "answer": "...", "difficulty": "hard" }
]`;
}

// Single-question prompt used by the per-question "Regenerate" button on
// the interview question draft — mirrors buildSingleQuestionPrompt above,
// but for an open-ended interview question + reference answer pair instead
// of a multiple-choice exam question. Existing questions are passed in so
// the replacement isn't a rephrasing of one already in the set.
function buildSingleInterviewQuestionPrompt(jdText, jobTitle, existingQuestions, difficulty) {
  const existingList = (existingQuestions || [])
    .map((q, i) => `${i + 1}. ${q.question}`)
    .join("\n");

  return `You are an expert HR and technical recruiter writing ONE replacement interview question.

Job Title: ${jobTitle}

Job Description:
${jdText}

<task>
Generate exactly ONE new open-ended interview question, plus a suggested
reference answer for the interviewer, to evaluate ANY candidate applying to
this role. It will replace one question in an existing interview question
pool, so it must be clearly different from the questions already in that
pool (not a rephrasing of any of them) — see <existing_questions> below.

The question must be at "${difficulty}" difficulty.
</task>

<existing_questions>
${existingList || "(none)"}
</existing_questions>

<output_format>
Return ONLY a single valid JSON object.
Start your response with { and end with }
No explanation, no markdown, no extra text before or after.

{
  "question": "the interview question",
  "answer": "a suggested reference answer for the interviewer",
  "difficulty": "${difficulty}"
}

Do not rename these keys. Do not omit any key.
</output_format>`;
}

app.post("/api/interview-pools/regenerate-question", async (req, res) => {
  const { draftId, difficulty } = req.body || {};
  if (!draftId) {
    return res.status(400).json({ error: "Missing draftId." });
  }
  const diff = ["easy", "medium", "hard"].includes(difficulty) ? difficulty : "medium";

  // Streamed NDJSON: real per-attempt events from the single AI call, then
  // a final "result" line — no client-side timer faking the wait.
  res.setHeader("Content-Type", "application/x-ndjson; charset=utf-8");
  res.setHeader("X-Accel-Buffering", "no");
  res.flushHeaders && res.flushHeaders();
  const sendProgress = (obj) => {
    try { res.write(JSON.stringify({ type: "progress", ...obj }) + "\n"); }
    catch (e) { console.warn("[interview regenerate-question stream] write failed:", e.message); }
  };

  try {
    sendProgress({ step: "loading_context", percent: 5, message: "Loading interview context…" });
    const draftRes = await pool.query(
      `SELECT jd_text, job_title, questions FROM interview_drafts WHERE draft_id = $1`,
      [draftId]
    );
    if (draftRes.rows.length === 0) {
      res.write(JSON.stringify({ type: "result", success: false, error: "Interview question draft not found or expired. Please regenerate the set." }) + "\n");
      return res.end();
    }

    const { jd_text: jdText, job_title: jobTitle, questions: existingQuestions } = draftRes.rows[0];
    if (!jdText) {
      res.write(JSON.stringify({ type: "result", success: false, error: "No job description context available for this draft." }) + "\n");
      return res.end();
    }

    const raw = await callOpenRouterAI({
      model:        "nvidia/nemotron-3.5-lightning:free",
      prompt:       buildSingleInterviewQuestionPrompt(jdText, jobTitle || "General Role", existingQuestions || [], diff),
      maxTokens:    1500,
      expectedJson: "object",
      onAttempt:    makeAttemptProgress(sendProgress, 10, 80, "Regenerating question with AI")
    });

    const question = {
      question:   raw?.question,
      answer:     raw?.answer,
      difficulty: diff
    };

    if (typeof question.question !== "string" || !question.question.trim()) {
      throw new Error("AI returned a malformed question (missing question text).");
    }
    if (typeof question.answer !== "string" || !question.answer.trim()) {
      throw new Error("AI returned a malformed question (missing reference answer).");
    }

    // Give the regenerated question its own independent verification pass
    // — a separate, fresh AI call (verifyInterviewQuestions, the same
    // function used for the full 5-question pool) rather than just
    // assuming it's fine. This call never sees the prompt or reasoning
    // that produced the question above. A failure here (rate limit,
    // timeout) is non-fatal — verifyInterviewQuestions already falls back
    // to an honest "verification unavailable" result instead of throwing
    // away the newly-generated question.
    sendProgress({ step: "verifying", percent: 85, message: "Verifying regenerated question with AI…" });
    const verification = await verifyInterviewQuestions([{ ...question, id: 1 }], sendProgress, [85, 99]);
    const verificationResult = verification.results[0] || null;

    sendProgress({ step: "done", percent: 100, message: "Question ready." });
    res.write(JSON.stringify({ type: "result", payload: { success: true, question, verificationResult } }) + "\n");
    return res.end();
  } catch (err) {
    console.error("[interview-pools regenerate-question] Error:", err.message);
    try {
      res.write(JSON.stringify({ type: "result", success: false, error: `Failed to regenerate question: ${err.message}` }) + "\n");
    } catch (e) {}
    return res.end();
  }
});

// Validates a single generated interview question against the shape the
// interview_questions table expects: non-empty question text, non-empty
// reference answer, and a difficulty tag drawn from the easy/medium/hard
// set used for per-candidate sampling below.
function validateInterviewQuestion(q, i) {
  const errors = [];
  const label = `Question ${i + 1}`;

  if (typeof q.question !== "string" || !q.question.trim()) {
    errors.push(`${label}: missing/invalid 'question' text`);
  }
  if (typeof q.answer !== "string" || !q.answer.trim()) {
    errors.push(`${label}: missing/invalid 'answer' text`);
  }
  if (!["easy", "medium", "hard"].includes(q.difficulty)) {
    errors.push(`${label}: 'difficulty' must be one of easy/medium/hard (got ${JSON.stringify(q.difficulty)})`);
  }

  return errors;
}

function validateInterviewQuestions(questions) {
  return questions.flatMap((q, i) => validateInterviewQuestion(q, i));
}

// Retries the whole generation call (same rationale as
// EXAM_GENERATION_ATTEMPTS above) when the model's output fails
// application-level validation — e.g. wrong question count, or a
// difficulty tag outside easy/medium/hard.
const INTERVIEW_GENERATION_ATTEMPTS = 3;

async function generateInterviewQuestionPool(jdText, jobTitle, sendProgress = null) {
  let lastError;

  for (let genAttempt = 1; genAttempt <= INTERVIEW_GENERATION_ATTEMPTS; genAttempt++) {
    try {
      const rawQuestions = await callOpenRouterAI({
        model:        "nvidia/nemotron-3.5-lightning:free",
        prompt:       buildInterviewPrompt(jdText, jobTitle),
        maxTokens:    3000,
        expectedJson: "array",
        onAttempt:    makeAttemptProgress(
          sendProgress, 8, 55,
          genAttempt > 1 ? `Drafting open-ended questions from the JD (retry ${genAttempt}/${INTERVIEW_GENERATION_ATTEMPTS})` : "Drafting open-ended questions from the JD"
        )
      });

      if (!Array.isArray(rawQuestions) || rawQuestions.length === 0) {
        throw new Error("The AI response was completed, but returned an empty or invalid format.");
      }

      if (rawQuestions.length !== 5) {
        throw new Error(`AI returned ${rawQuestions.length} questions; expected exactly 5.`);
      }

      // ids let verifyInterviewQuestions()/fixFlaggedInterviewQuestions()
      // match a verification verdict (or a fix) back to the question it's
      // about — same role "id" plays for exam questions.
      const generatedQuestions = rawQuestions.map((q, i) => ({
        id:         i + 1,
        question:   q.question,
        answer:     q.answer,
        difficulty: (q.difficulty || "medium").toLowerCase()
      }));

      const questionErrors = validateInterviewQuestions(generatedQuestions);
      if (questionErrors.length > 0) {
        throw new Error(`AI returned malformed interview questions: ${questionErrors.join("; ")}`);
      }

      return generatedQuestions;

    } catch (error) {
      lastError = error;

      if (error.isFatal || genAttempt === INTERVIEW_GENERATION_ATTEMPTS) break;

      console.warn(`[interview-ai] Generation attempt ${genAttempt}/${INTERVIEW_GENERATION_ATTEMPTS} failed (${error.message}) — retrying…`);
      if (sendProgress) {
        sendProgress({ step: "ai_retry", percent: 8, message: `Attempt ${genAttempt} didn't produce a valid question pool — retrying…` });
      }
    }
  }

  let detailedMessage = lastError.message;

  if (lastError.isFatal) {
    // Daily-quota / model-config errors already carry precise, user-facing
    // text from callOpenRouterAI — leave them alone.
  } else if (/rate-limited upstream|provider returned error|upstream_provider_shared_pool/i.test(lastError.message)) {
    // Keep the specific "temporarily overloaded upstream" text intact.
  } else if (lastError.message.includes("Failed to fetch")) {
    detailedMessage = "Network Error / Timeout: the AI model dropped the connection or took too long.";
  } else if (lastError.message.includes("429")) {
    detailedMessage = "Rate Limit Exceeded: You've hit the free tier request limit. Try again in 1-2 minutes.";
  } else if (lastError.message.includes("context_length") || lastError.message.includes("token")) {
    detailedMessage = "Token Limit Exceeded: The Job Description context is too long.";
  }

  const err = new Error(detailedMessage);
  if (lastError.isFatal) err.isFatal = true;
  throw err;
}

// A second, independent AI pass over the generated interview questions —
// same discipline as the exam pipeline (see EXAM_MODEL / verifyExamQuestions
// above): generation and verification are always two separate API calls
// with two separate, freshly-built messages[] arrays — that's what makes
// verification independent, NOT which model answers (see the comment above
// EXAM_MODEL). The verifier is never shown the generator's prompt or
// reasoning, and — like the exam verifier — is deliberately NOT given the
// job description, so it's checking whether each question stands on its
// own as a real interview question rather than something that only makes
// sense next to this specific JD.
//
// This was originally "cohere/north-mini-code:free". In practice that
// model reliably hits finish_reason:"length" on this prompt — the prompt
// asks it to "work out the correct answer for yourself first," which is an
// invitation to reason step-by-step, and this model appears to burn its
// whole token budget on hidden chain-of-thought instead of respecting the
// /no_think hint, regardless of how large maxTokens is set. Since the
// codebase's own stated design is that independence comes from separate
// calls/context rather than a different model, reusing the generation
// model here is architecturally fine, and it's already proven fast and
// /no_think-compliant on this exact JD in production logs.
const INTERVIEW_VERIFY_MODEL = "poolside/laguna-s-2.1:free";

function buildInterviewVerificationPrompt(questions) {
  const stripped = questions.map(q => ({
    id:         q.id,
    question:   q.question,
    answer:     q.answer,
    difficulty: q.difficulty
  }));
// Interview evaluator//
  return `You are an independent HR and technical interview quality reviewer.
You are checking someone else's work — you did not write these questions.

<task>
For EACH question + reference-answer pair below, judge whether it is a
good open-ended interview question:
1. The question is genuinely open-ended (not a yes/no or trivia-recall
   question) and gives a real candidate room to speak from their own
   knowledge or experience.
2. The reference answer actually responds to the question — it is
   substantive and on-topic, not vague filler and not just a restatement
   of the question.
3. The question does not depend on having read this specific job
   posting's text (e.g. it must not ask what "this role" requires, or
   which tool/technology is "listed" or "mentioned" in the posting) — it
   should test real knowledge or experience a candidate could speak to
   regardless of this exact posting.
4. The "difficulty" tag roughly matches how deep/advanced the question
   actually is.
</task>

<rules>
- "verified" must be true ONLY if all four checks above hold.
- If "verified" is false, set "issue" to a short (1 sentence) explanation
  (e.g. "reference answer just repeats the question back", "question asks
  the candidate to recall what's mentioned in the job posting rather than
  testing real knowledge").
- If you can suggest a concrete fix, set "suggestedFix" to a short (1
  sentence) note on what should change. Otherwise set "suggestedFix" to
  null.
- Return exactly one result object per question, in the SAME ORDER given,
  using the SAME "id" values.
- Do not include any explanation, markdown, or text outside the JSON array.
</rules>

<output_format>
Return ONLY a valid JSON array.
Start your response with [ and end with ]
No explanation, no markdown, no extra text before or after.

Each object MUST match this exact structure and field names:
{
  "id": 1,
  "verified": true,
  "issue": null,
  "suggestedFix": null
}
</output_format>

<questions_to_verify>
${JSON.stringify(stripped, null, 2)}
</questions_to_verify>`;
}

async function verifyInterviewQuestions(questions, sendProgress = null, pctRange = [55, 90]) {
  let verdicts = [];
  try {
    verdicts = await callOpenRouterAI({
      model:        INTERVIEW_VERIFY_MODEL,
      // If the primary verifier model is congested, OpenRouter fails over
      // to the next one in this list in milliseconds — far cheaper than
      // us hitting a 429/5xx and sleeping through our own retry backoff
      // (see callOpenRouterAI) on a model that was just slow to begin
      // with. Reuses the same fallback pair already proven out for CV
      // scoring above.
      fallbackModels: [
        "poolside/laguna-xs-2.1:free",
        "nvidia/nemotron-3.5-lightning:free"
      ],
      prompt:       buildInterviewVerificationPrompt(questions),
      maxTokens:    1200, // 5 small {id,verified,issue,suggestedFix} objects — 3000 was way more headroom than this output needs, which just widens the window for a rambling response to eat the clock
      expectedJson: "array",
      onAttempt:    makeAttemptProgress(sendProgress, pctRange[0], pctRange[1], "Auto-verifying interview questions")
    });
  } catch (err) {
    // Verification is a nice-to-have second pass, not the deliverable — the
    // 5 questions from generateInterviewQuestionPool() already succeeded.
    // If verification itself gets rate-limited or times out, don't throw
    // that away: fall through with no verdicts, which naturally hits the
    // "did not return a result" branch below for every question.
    console.warn("[interview-ai] Verification call failed — interview set will be returned unverified:", err.message);
  }

  const verdictById = {};
  (Array.isArray(verdicts) ? verdicts : []).forEach(v => {
    if (v && v.id !== undefined) verdictById[v.id] = v;
  });

  const results = questions.map(q => {
    const v = verdictById[q.id];
    if (!v) {
      return { id: q.id, verified: false, issue: "AI verification did not return a result for this question — please review it manually.", suggestedFix: null };
    }
    return {
      id: q.id,
      verified: v.verified === true,
      issue: v.verified === true ? null : (v.issue || "AI flagged a possible issue but did not explain why."),
      suggestedFix: typeof v.suggestedFix === "string" && v.suggestedFix.trim() ? v.suggestedFix.trim() : null
    };
  });

  const issuesFound = results.filter(r => !r.verified).length;
  return { verifiedAt: new Date().toISOString(), results, issuesFound };
}

// Feeds the evaluator's feedback for the flagged questions back into the
// generator so it can repair just those questions in place, instead of
// throwing away and regenerating the whole 5-question pool.
function buildInterviewFixPrompt(jdText, jobTitle, flaggedQuestions) {
  const feedback = flaggedQuestions.map(f => ({
    id:                   f.id,
    question:             f.question,
    answer:               f.answer,
    difficulty:           f.difficulty,
    reviewerIssue:        f.issue,
    reviewerSuggestedFix: f.suggestedFix
  }));
// Interview revision//
  return `You are an expert HR and technical recruiter revising interview
questions that an independent reviewer flagged as having a problem.

Job Title: ${jobTitle}

Job Description:
${jdText}

<task>
For EACH question below, a reviewer explained what's wrong with it in
"reviewerIssue" (and, when applicable, a suggested direction in
"reviewerSuggestedFix"). Rewrite the question and/or its reference answer
so the problem is fixed. You may keep the question mostly as-is and just
improve the reference answer, or rewrite the question entirely if that's
what the issue requires — use your judgment based on "reviewerIssue".
</task>

<rules>
- Return exactly one corrected question per input question, in the SAME
  ORDER, using the SAME "id" values.
- Keep the SAME "difficulty" value given for each question.
- Do not omit any key.
- Use the job description ONLY to decide which technologies/skills are in
  scope — never write a question that depends on having read this specific
  posting (e.g. "what does this role require", "which tool is listed
  above"). Rewrite any such question to test real knowledge/experience
  instead.
</rules>

<output_format>
Return ONLY a valid JSON array, one object per flagged question.
Start your response with [ and end with ]
No explanation, no markdown, no extra text before or after.

Each object MUST match this exact structure and field names:
{
  "id": 2,
  "question": "corrected question text",
  "answer": "corrected reference answer",
  "difficulty": "medium"
}
</output_format>

<flagged_questions>
${JSON.stringify(feedback, null, 2)}
</flagged_questions>`;
}

async function fixFlaggedInterviewQuestions(jdText, jobTitle, questions, verification, sendProgress = null) {
  const resultById = {};
  (verification.results || []).forEach(r => { resultById[r.id] = r; });

  const flagged = questions
    .filter(q => resultById[q.id] && !resultById[q.id].verified)
    .map(q => ({ ...q, issue: resultById[q.id].issue, suggestedFix: resultById[q.id].suggestedFix }));

  if (flagged.length === 0) return questions;

  const fixed = await callOpenRouterAI({
    model:        "nvidia/nemotron-3.5-lightning:free",
    prompt:       buildInterviewFixPrompt(jdText, jobTitle, flagged),
    maxTokens:    2500,
    expectedJson: "array",
    onAttempt:    makeAttemptProgress(sendProgress, 90, 96, `Fixing ${flagged.length} flagged question(s)`)
  });

  const fixedById = {};
  (Array.isArray(fixed) ? fixed : []).forEach(f => { if (f && f.id !== undefined) fixedById[f.id] = f; });

  return questions.map(q => {
    const f = fixedById[q.id];
    if (!f) return q; // fix call didn't return this one — leave as-is, still flagged
    return {
      id:         q.id,
      question:   f.question,
      answer:     f.answer,
      difficulty: f.difficulty || q.difficulty
    };
  });
}

// Full pipeline: generate → verify → (if issues) fix flagged questions with
// the evaluator's feedback → re-verify only those fixed questions. Capped
// at one fix round so a stubborn question can't loop forever; anything
// still flagged after that is left visible for a human to review/edit —
// exactly the same shape as generateAndVerifyExam() above.
async function generateAndVerifyInterviewQuestions(jdText, jobTitle, sendProgress = null) {
  const pipelineStart = Date.now();
  const genStart = Date.now();
  let questions = await generateInterviewQuestionPool(jdText, jobTitle, sendProgress);
  const genMs = Date.now() - genStart;

  if (sendProgress) sendProgress({ step: "verifying", percent: 55, message: "Auto-verifying interview questions…" });
  const verifyStart = Date.now();
  let verification = await verifyInterviewQuestions(questions, sendProgress, [55, 90]);
  const verifyMs = Date.now() - verifyStart;
  let fixMs = 0, reverifyMs = 0;

  if (verification.issuesFound > 0) {
    console.log(`[interview-ai] ${verification.issuesFound} question(s) flagged — sending evaluator feedback back to the generator for a fix pass...`);
    if (sendProgress) sendProgress({ step: "fixing", percent: 90, message: `Fixing ${verification.issuesFound} flagged question(s)…` });
    try {
      const fixStart = Date.now();
      const fixedQuestions = await fixFlaggedInterviewQuestions(jdText, jobTitle, questions, verification, sendProgress);
      fixMs = Date.now() - fixStart;

      const questionErrors = validateInterviewQuestions(fixedQuestions);
      if (questionErrors.length === 0) {
        questions = fixedQuestions;
        if (sendProgress) sendProgress({ step: "reverifying", percent: 96, message: "Re-verifying fixed questions…" });
        const reverifyStart = Date.now();
        verification = await verifyInterviewQuestions(questions, sendProgress, [96, 99]);
        reverifyMs = Date.now() - reverifyStart;
      }
      // If the fix pass produced malformed questions, keep the original
      // (still-flagged) set rather than corrupting the pool.
    } catch (err) {
      // The fix pass is also a nice-to-have on top of an already-usable
      // question pool. If it fails (rate limit, timeout, etc.), keep the
      // originally-generated questions with their existing flags rather
      // than losing the whole pool — the recruiter can still edit or
      // regenerate individual flagged questions from the review screen.
      console.warn("[interview-ai] Fix pass failed — keeping original flagged questions:", err.message);
    }
  }

  console.log(`[interview-ai] Stage timings — generate: ${genMs}ms, verify: ${verifyMs}ms, fix: ${fixMs}ms, reverify: ${reverifyMs}ms, total: ${Date.now() - pipelineStart}ms`);

  if (sendProgress) sendProgress({ step: "done", percent: 100, message: "Interview questions ready." });
  return { questions, verification };
}


// Resolve the metadata for a JD from the JD itself before saving any generated
// exam/interview pool.  The AI content is already generated from jdText, so the
// library label must use the same source of truth rather than whichever posting
// happens to be selected in the dashboard at save time.
//
// Priority:
//   1) Explicit "Job Title / Position / Role" line in the uploaded JD.
//   2) A strong role heading near the beginning of the JD.
//   3) The recruiter-selected posting as a safe fallback.
//
// If the detected title matches an existing posting (exactly or closely), link
// the saved pool to that posting.  If it does not, keep the detected title but
// leave the posting key null rather than incorrectly attaching an Accounting JD
// to (for example) a Software Engineer posting.
function inferJDTitle(jdText, fallbackTitle) {
  const text = String(jdText || "").replace(/\r/g, "");
  const lines = text.split("\n").map(x => x.trim()).filter(Boolean).slice(0, 80);

  const titlePatterns = [
    /^(?:job\s*title|position\s*title|position|role|job\s*role|title)\s*[:\-]\s*(.+)$/i,
    /^(?:opening|vacancy)\s*[:\-]\s*(.+)$/i
  ];

  for (const line of lines) {
    for (const pattern of titlePatterns) {
      const m = line.match(pattern);
      if (m && m[1]) {
        const candidate = m[1].replace(/\s+/g, " ").trim();
        if (candidate.length >= 3 && candidate.length <= 120) return candidate;
      }
    }
  }

  // Common JD layouts put the role as the first meaningful heading.
  for (const line of lines.slice(0, 15)) {
    let cleaned = line.replace(/^#+\s*/, "").replace(/^[•\-*]\s*/, "").trim();
    // Some JD templates label this heading line "Job Description:" /
    // "Description:" rather than "Job Title:" (which the stricter
    // titlePatterns above already handles) — strip that label here too,
    // so the detected title doesn't come back with it still attached (it
    // would otherwise end up duplicated once callers add their own
    // "JOB DESCRIPTION:" label on top, e.g. "JOB DESCRIPTION: JOB
    // DESCRIPTION: Software Engineer (Full-Stack)").
    cleaned = cleaned.replace(/^(?:job\s*)?description\s*[:\-]\s*/i, "").trim();
    if (!cleaned || cleaned.length < 3 || cleaned.length > 100) continue;
    if (/^(about|summary|description|responsibilities|requirements|qualifications|education|experience|skills|location|department|salary|benefits|overview)$/i.test(cleaned)) continue;
    if (/\b(accountant|accounting|finance|financial|bookkeeper|auditor|payroll|software engineer|developer|qa engineer|quality assurance|human resources|hr specialist|recruiter|sales|marketing)\b/i.test(cleaned)) {
      return cleaned;
    }
  }

  return (fallbackTitle || "General Role").trim();
}

// Hiring is generic/any-position now — there's no managed job posting for
// a generated exam/interview set to be scoped or tagged to. This just picks
// a display label: whatever the recruiter typed, or if they left it blank,
// whatever title inferJDTitle can find in the JD text itself, so the saved
// pool isn't left with a blank/unhelpful name.
function resolveJDJobTitle(jdText, requestedTitle) {
  const requested = String(requestedTitle || "").trim();
  if (requested && requested !== "General Role") {
    return { jobTitle: requested, detectedFromJD: false };
  }
  const detectedTitle = inferJDTitle(jdText, requestedTitle);
  return { jobTitle: detectedTitle || requested || "General Role", detectedFromJD: !!detectedTitle };
}

app.post("/api/interview-pools/generate", upload.single("jd"), async (req, res) => {
  const filePaths = [];
  if (!req.file)
    return res.status(400).json({ error: "No job description file received. Please upload a JD first." });
  filePaths.push(req.file.path);

  // Hiring is generic/any-position now — jobTitle is just a free-text
  // display label (typed by the recruiter, or inferred from the JD if left
  // blank); it no longer ties this interview set to a specific posting.
  const requestedJobTitle = req.body.jobTitle || "General Role";

  // Streamed NDJSON: real per-attempt events from the single AI call, then
  // a final "result" line — no client-side timer faking the wait.
  res.setHeader("Content-Type", "application/x-ndjson; charset=utf-8");
  res.setHeader("X-Accel-Buffering", "no");
  res.flushHeaders && res.flushHeaders();
  const sendProgress = (obj) => {
    try { res.write(JSON.stringify({ type: "progress", ...obj }) + "\n"); }
    catch (e) { console.warn("[interview-pools/generate stream] write failed:", e.message); }
  };

  try {
    sendProgress({ step: "reading_jd", percent: 3, message: "Reading job description…" });
    let jdText;
    try {
      jdText = await extractText(req.file.path, req.file.originalname);
    } catch (e) {
      res.write(JSON.stringify({ type: "result", success: false, error: `Job description error: ${e.message}` }) + "\n");
      return res.end();
    }
    if (jdText.length < 50) {
      res.write(JSON.stringify({ type: "result", success: false, error: "The job description is too short (min 50 chars)." }) + "\n");
      return res.end();
    }

    const MAX_JD_CHARS = 4000;
    jdText = jdText.length > MAX_JD_CHARS ? jdText.slice(0, MAX_JD_CHARS) + "\n[JD truncated for length]" : jdText;

    const jobContext = resolveJDJobTitle(jdText, requestedJobTitle);
    const jobTitle = jobContext.jobTitle;

    console.log(`[interview-pools] Generating & auto-verifying interview question pool for "${jobTitle}"${jobContext.detectedFromJD ? " (resolved from JD)" : ""}...`);
    const { questions, verification } = await generateAndVerifyInterviewQuestions(jdText, jobTitle, sendProgress);

    const draftId = "idraft_" + Date.now() + "_" + Math.floor(Math.random() * 10000);
    await pool.query(
      `INSERT INTO interview_drafts (draft_id, job_title, jd_text, questions, verification)
       VALUES ($1, $2, $3, $4, $5)`,
      [draftId, jobTitle || "General Role", jdText, JSON.stringify(questions), JSON.stringify(verification)]
    );

    console.log(`[interview-pools] ✓ Draft ${draftId} ready for "${jobTitle}" — ${verification.issuesFound}/${questions.length} question(s) still flagged.`);
    res.write(JSON.stringify({
      type: "result",
      payload: {
        success: true,
        draftId,
        questions,
        verification,
        jobTitle,
        detectedFromJD: jobContext.detectedFromJD
      }
    }) + "\n");
    return res.end();

  } catch (err) {
    console.error("[interview-pools] Error:", err.message);
    try {
      res.write(JSON.stringify({ type: "result", success: false, error: `Failed to generate interview questions: ${err.message}` }) + "\n");
    } catch (e) {}
    return res.end();
  } finally {
    cleanupFiles(filePaths);
  }
});

app.post("/api/interview-pools/save-draft", async (req, res) => {
  const { draftId, questions: editedQuestions } = req.body || {};
  if (!draftId) {
    return res.status(400).json({ error: "No draftId provided." });
  }

  // If the recruiter edited any questions client-side before saving, those
  // edits arrive here as `questions`. Validate them and use them in place
  // of the originally-generated draft so edits actually persist.
  let overrideQuestions = null;
  if (editedQuestions !== undefined) {
    if (!Array.isArray(editedQuestions) || editedQuestions.length === 0) {
      return res.status(400).json({ error: "Edited questions must be a non-empty array." });
    }
    for (const q of editedQuestions) {
      if (!q || typeof q.question !== "string" || !q.question.trim()) {
        return res.status(400).json({ error: "Every question must have non-empty question text." });
      }
      if (q.answer !== undefined && typeof q.answer !== "string") {
        return res.status(400).json({ error: "Question answer must be a string." });
      }
      if (q.difficulty !== undefined && !["easy", "medium", "hard"].includes(q.difficulty)) {
        return res.status(400).json({ error: "Question difficulty must be one of easy/medium/hard." });
      }
    }
    overrideQuestions = editedQuestions;
  }

  const client = await pool.connect();
  try {
    await client.query("BEGIN");

    // FOR UPDATE locks the row for the rest of this transaction, so a
    // double-click on Save can't race two saves of the same draft.
    const draftRes = await client.query(
      `SELECT draft_id, job_title, jd_text, questions
       FROM interview_drafts WHERE draft_id = $1 FOR UPDATE`,
      [draftId]
    );

    if (draftRes.rows.length === 0) {
      await client.query("ROLLBACK");
      return res.status(404).json({ error: "Interview question draft not found or expired. Please regenerate." });
    }

    const draft = draftRes.rows[0];
    const questions = overrideQuestions || draft.questions; // node-postgres parses JSONB into a JS value automatically

    const poolId = "ipool_" + Date.now();
    await client.query(
      `INSERT INTO interview_question_pools (id, employer_id, job_title, jd_text, gap_category)
       VALUES ($1, NULL, $2, $3, 'general')`,
      [poolId, draft.job_title, draft.jd_text]
    );

    for (const q of questions) {
      await client.query(
        `INSERT INTO interview_questions (pool_id, question, answer, difficulty) VALUES ($1, $2, $3, $4)`,
        [poolId, q.question, q.answer || "", (q.difficulty || "medium").toLowerCase()]
      );
    }

    await client.query(`DELETE FROM interview_drafts WHERE draft_id = $1`, [draftId]);
    await client.query("COMMIT");

    console.log(`[interview-pools] ✓ Saved pool ${poolId} ("${draft.job_title}") with ${questions.length} questions.`);
    return res.json({ success: true, poolId, totalSaved: questions.length });
  } catch (err) {
    await client.query("ROLLBACK");
    console.error("[interview-pools] save-draft error:", err);
    return res.status(500).json({ error: "Failed to save interview questions to the library." });
  } finally {
    client.release();
  }
});

// View-only: returns whatever interview question set (if any) is currently
// applied to this candidate. Generation no longer happens here — HR applies
// a saved set from the library via use-interview-pool below.
app.get("/api/candidates/:candidateId/interview-questions", (req, res) => {
  const candidate = global.candidatesStore[req.params.candidateId];
  if (!candidate) return res.status(404).json({ error: "Candidate not found." });

  res.json({
    success:  true,
    questions: candidate.aiInterviewQuestions || null,
    poolId:    candidate.interviewPoolId || null,
    notes:     candidate.hrNotes || ""
  });
});

// Hiring is generic/any-position now, so this is just one shared library —
// no per-posting scoping/filtering.
app.get("/api/interview-pools", async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT ip.id, ip.job_title, ip.gap_category, ip.created_at, COUNT(iq.id)::int AS question_count
       FROM interview_question_pools ip LEFT JOIN interview_questions iq ON iq.pool_id = ip.id
       GROUP BY ip.id ORDER BY ip.created_at DESC`
    );
    res.json({ success: true, pools: result.rows });
  } catch (err) {
    console.error("[interview-pools list error]", err);
    res.status(500).json({ error: "Failed to fetch saved interview questions." });
  }
});

app.get("/api/interview-pools/:poolId", async (req, res) => {
  try {
    const poolResult = await pool.query(`SELECT * FROM interview_question_pools WHERE id = $1`, [req.params.poolId]);
    if (poolResult.rows.length === 0) return res.status(404).json({ error: "Saved interview question set not found." });

    const questionsResult = await pool.query(
      `SELECT id, question, answer, difficulty FROM interview_questions WHERE pool_id = $1 ORDER BY id ASC`,
      [req.params.poolId]
    );
    res.json({ success: true, pool: poolResult.rows[0], questions: questionsResult.rows });
  } catch (err) {
    console.error("[interview-pools detail error]", err);
    res.status(500).json({ error: "Failed to fetch interview question set details." });
  }
});

// Same rationale as PATCH /api/exam-pools/:poolId above — lets a
// mislabeled saved interview question set be relabeled without touching
// the actual generated questions/JD context.
app.patch("/api/interview-pools/:poolId", async (req, res) => {
  const { jobTitle } = req.body || {};
  if (typeof jobTitle !== "string" || !jobTitle.trim()) {
    return res.status(400).json({ error: "jobTitle is required and must be a non-empty string." });
  }
  try {
    const result = await pool.query(
      `UPDATE interview_question_pools SET job_title = $1 WHERE id = $2 RETURNING id, job_title`,
      [jobTitle.trim(), req.params.poolId]
    );
    if (result.rows.length === 0) return res.status(404).json({ error: "Saved interview question set not found." });
    console.log(`[interview-pools] ✓ Relabeled pool ${req.params.poolId} → "${result.rows[0].job_title}"`);
    res.json({ success: true, pool: result.rows[0] });
  } catch (err) {
    console.error("[interview-pools rename error]", err);
    res.status(500).json({ error: "Failed to update saved interview question set." });
  }
});

app.delete("/api/interview-pools/:poolId", async (req, res) => {
  try {
    const result = await pool.query(`DELETE FROM interview_question_pools WHERE id = $1 RETURNING id`, [req.params.poolId]);
    if (result.rows.length === 0) return res.status(404).json({ error: "Saved interview question set not found." });
    res.json({ success: true });
  } catch (err) {
    console.error("[interview-pools delete error]", err);
    res.status(500).json({ error: "Failed to delete saved interview question set." });
  }
});

// Manually apply a saved interview question set to a specific candidate —
// mirrors /api/batches/:batchId/use-pool/:poolId for exams.
//
// :candidateId accepts either the internal candidate ID (cand-...) or the
// Application ID (APP-...) — the latter is what the dashboard actually
// displays to HR on each candidate card, so that's what they'll have on
// hand when using this from the Saved Interview Qs library.
// Draws the 3-question set an individual applicant actually sees (1 easy,
// 1 medium, 1 hard) out of the 5-question pool saved for the job posting —
// same idea sampleQuestionsForCandidate() used to apply for its old
// 30→20 exam design, just scaled down to 5→3. Seeded off the candidateId so the same
// candidate always gets the same 3 questions if this is re-applied.
function sampleInterviewQuestionsForCandidate(poolQuestions, candidateId) {
  const target = { easy: 1, medium: 1, hard: 1 };

  const buckets = { easy: [], medium: [], hard: [] };
  for (const q of poolQuestions) {
    const d = (q.difficulty || "medium").toLowerCase();
    if (!buckets[d]) buckets[d] = [];
    buckets[d].push(q);
  }

  let seed = 0;
  for (let i = 0; i < String(candidateId).length; i++) seed = (seed * 31 + String(candidateId).charCodeAt(i)) >>> 0;
  const rnd = mulberry32(seed || Date.now());

  function pickFromBucket(bucket, count) {
    const available = [...bucket];
    const chosen = [];
    for (let i = 0; i < count && available.length > 0; i++) {
      const idx = Math.floor(rnd() * available.length);
      chosen.push(available.splice(idx, 1)[0]);
    }
    return chosen;
  }

  const selected = [];
  const shortages = [];

  for (const diff of ["easy", "medium", "hard"]) {
    const need = target[diff];
    const have = (buckets[diff] || []).length;
    const take = Math.min(need, have);
    selected.push(...pickFromBucket(buckets[diff], take));
    if (take < need) shortages.push({ diff, missing: need - take });
  }

  // Fill any shortage (e.g. the pool didn't have a hard question) from
  // whatever's left over, so the candidate still gets 3 questions.
  const remaining = poolQuestions.filter(q => !selected.includes(q));

  for (const s of shortages) {
    for (let i = 0; i < s.missing && remaining.length > 0; i++) {
      const idx = Math.floor(rnd() * remaining.length);
      selected.push(remaining.splice(idx, 1)[0]);
    }
  }

  while (selected.length < 3 && remaining.length > 0) {
    const idx = Math.floor(rnd() * remaining.length);
    selected.push(remaining.splice(idx, 1)[0]);
  }

  return selected.slice(0, 3);
}

app.post("/api/candidates/:candidateId/use-interview-pool/:poolId", async (req, res) => {
  const param = req.params.candidateId;
  const candidate = global.candidatesStore[param]
    || Object.values(global.candidatesStore).find(c => c.applicationId === param);
  if (!candidate) return res.status(404).json({ error: "Candidate not found. Check the candidate or application ID and try again." });

  try {
    const questionsResult = await pool.query(
      `SELECT question, answer, difficulty FROM interview_questions WHERE pool_id = $1 ORDER BY id ASC`,
      [req.params.poolId]
    );
    if (questionsResult.rows.length === 0)
      return res.status(404).json({ error: "Saved interview question set has no questions." });

    // The pool holds up to 5 questions (3 easy / 1 medium / 1 hard); each
    // applicant only sees 3 — 1 easy, 1 medium, 1 hard — drawn from it.
    const selectedQuestions = sampleInterviewQuestionsForCandidate(questionsResult.rows, candidate.id);

    candidate.aiInterviewQuestions = selectedQuestions;
    candidate.interviewPoolId      = req.params.poolId;
    await persistCandidate(candidate.id);

    console.log(`[interview-questions] ✓ Applied saved interview pool ${req.params.poolId} to candidate ${candidate.id} (${selectedQuestions.length} of ${questionsResult.rows.length} pooled questions selected)`);
    res.json({ success: true, questions: candidate.aiInterviewQuestions, notes: candidate.hrNotes || "" });
  } catch (err) {
    console.error("[use-interview-pool error]", err);
    res.status(500).json({ error: "Failed to apply saved interview questions." });
  }
});

app.post("/api/candidates/:candidateId/notes", async (req, res) => {
  const candidate = global.candidatesStore[req.params.candidateId];
  if (!candidate) return res.status(404).json({ error: "Candidate not found." });
  
  candidate.hrNotes = req.body.notes || "";
  await persistCandidate(req.params.candidateId);
  console.log(`[notes] Saved custom interview evaluation notes for ${candidate.name}`);
  return res.json({ success: true, message: "Interview notes logged successfully." });
});

// HR-INTERVIEW-STATUS: explicit toggle for "the HR/live interview actually
// happened," set by a recruiter from the AI Interview Questions panel. Kept
// separate from hrNotes (which can be blank even after a real interview,
// and previously had to be used as an unreliable completion proxy — see
// the "HR interview already completed" heuristic in openEmailLog) and from
// examStatus (which only tracks the skills exam, not the human interview).
app.post("/api/candidates/:candidateId/hr-interview-status", async (req, res) => {
  const candidate = global.candidatesStore[req.params.candidateId];
  if (!candidate) return res.status(404).json({ error: "Candidate not found." });

  candidate.hrInterviewCompleted = !!req.body.completed;
  await persistCandidate(req.params.candidateId);
  console.log(`[hr-interview-status] ${candidate.name}: hrInterviewCompleted = ${candidate.hrInterviewCompleted}`);
  return res.json({ success: true, hrInterviewCompleted: candidate.hrInterviewCompleted });
});

app.get("/api/candidates/lookup/:appId", (req, res) => {
  const targetAppId = req.params.appId.toUpperCase();
  
  const candidateRecord = Object.values(global.candidatesStore).find(
    c => c.applicationId === targetAppId
  );
  
  if (!candidateRecord) {
    return res.status(404).json({ success: false, error: "Application ID not recognized." });
  }
  
  return res.json({ success: true, candidate: candidateRecord });
});

// =============================================================================
// BATCH-LEVEL EXAM GENERATION & DELIVERY
// =============================================================================

// MATCH-GATE: single source of truth for "is this candidate a low match
// that should be rejected instead of advanced." Batches are created from
// EVERY successfully-scored CV (see the /api/... upload handler above), so
// a batch always contains a mix of strong and weak matches — batch
// membership alone is never a valid proxy for "eligible to take the exam."
// Ground truth is the AI's own recommendation bucket (see the scoring
// prompt's <scoring_guide>: below 55 -> "Reject"), with a numeric-score
// fallback in case recommendation is ever missing/malformed.
function isRejectedCandidate(cand) {
  const recommendation = cand?.scoringData?.recommendation;
  if (typeof recommendation === "string") {
    return recommendation.trim().toLowerCase() === "reject";
  }
  return typeof cand?.score === "number" && cand.score < 55;
}

async function createCandidateBatch(jdContext) {
  const batchId = "batch_" + Date.now();
  global.batchesStore[batchId] = {
    batchId,
    jdContext,
    candidateIds: [],
    examQuestions: null,
    verification: null,
    isApproved:   false,
    createdAt:    new Date().toISOString(),
    approvedAt:   null
  };
  await persistBatch(batchId);
  return batchId;
}

// ---------------------------------------------------------------------------
// Generate → Verify → (if needed) Fix-with-feedback, all on ONE model
// (EXAM_MODEL), each step its own fresh messages[] context. This replaces
// the old "Model 1 generates / Model 2 verifies" split:
//   - One model is enough; independence comes from separate contexts, not
//     separate models (the verifier never sees the generator's prompt).
//   - When the evaluator flags questions, that feedback (issue +
//     suggestedCorrect) is fed back INTO the generator to fix just those
//     questions — not used as a signal to throw everything away and
//     regenerate all 20 from scratch.
//   - This whole thing runs automatically as part of generation; there is
//     no separate user-invoked "verify" step in the normal flow.
// ---------------------------------------------------------------------------

// makeAttemptProgress: wraps a sendProgress() emitter into an onAttempt
// callback for callOpenRouterAI, scaling real retry-attempt numbers (1..N)
// into a percent range so a call that needs a couple of retries still shows
// forward motion tied to actual network attempts rather than a fake timer.
function makeAttemptProgress(sendProgress, startPct, endPct, label) {
  if (!sendProgress) return null;
  return (attempt, maxRetries) => {
    const pct = Math.round(startPct + ((attempt - 1) / Math.max(1, maxRetries)) * (endPct - startPct));
    sendProgress({
      step: "ai_call",
      percent: pct,
      message: attempt > 1 ? `${label} — retry ${attempt}/${maxRetries}…` : `${label}…`
    });
  };
}

// Retries the whole generation call (not just network retries — those
// already happen inside callOpenRouterAI) when the model's output fails
// application-level validation: wrong question count, or a response that
// got cut off mid-JSON. Free-tier models miss "exactly 30" fairly often,
// and previously a single miss discarded the whole attempt with no
// second chance. GENERATION_ATTEMPTS bounds how many full generate
// attempts we'll make before giving up, separate from callOpenRouterAI's
// own per-request retry count.
const EXAM_GENERATION_ATTEMPTS = 3;

async function generateExamQuestions(jdText, sendProgress = null) {
  let lastError;

  for (let genAttempt = 1; genAttempt <= EXAM_GENERATION_ATTEMPTS; genAttempt++) {
    try {
      const rawQuestions = await callOpenRouterAI({
        model:        EXAM_MODEL,
        prompt:       build15QuestionExamPrompt(jdText),
        maxTokens:    16000, // generous headroom for 30 full question objects, well above what a /no_think completion needs, to avoid finish_reason:"length" cutoffs
        expectedJson: "array",
        onAttempt:    makeAttemptProgress(
          sendProgress, 5, 50,
          genAttempt > 1 ? `Generating questions with AI (retry ${genAttempt}/${EXAM_GENERATION_ATTEMPTS})` : "Generating questions with AI"
        )
      });

      if (!Array.isArray(rawQuestions) || rawQuestions.length === 0) {
        throw new Error("The AI response was completed, but returned an empty or invalid format.");
      }

      if (rawQuestions.length !== 15) {
        throw new Error(`AI returned ${rawQuestions.length} questions; expected exactly 15.`);
      }

      const generatedQuestions = rawQuestions.map((q, i) => ({
        id:         i + 1,
        question:   q.question,
        options:    q.options,
        correct:    q.correct,
        difficulty: q.difficulty || "medium"
      }));

      const questionErrors = validateExamQuestions(generatedQuestions);
      if (questionErrors.length > 0) {
        throw new Error(`AI returned malformed exam questions: ${questionErrors.join("; ")}`);
      }

      return generatedQuestions;

    } catch (error) {
      lastError = error;

      // Fatal errors (daily quota exhausted, wrong model type) won't be
      // fixed by trying again — stop immediately instead of burning
      // through the remaining attempts (and more of the daily quota).
      if (error.isFatal || genAttempt === EXAM_GENERATION_ATTEMPTS) break;

      console.warn(`[exam-ai] Generation attempt ${genAttempt}/${EXAM_GENERATION_ATTEMPTS} failed (${error.message}) — retrying…`);
      if (sendProgress) {
        sendProgress({ step: "ai_retry", percent: 5, message: `Attempt ${genAttempt} didn't produce a valid exam — retrying…` });
      }
    }
  }

  let detailedMessage = lastError.message;

  if (lastError.isFatal) {
    // Daily-quota / model-config errors already carry precise, user-facing
    // text from callOpenRouterAI — leave them alone.
  } else if (/rate-limited upstream|provider returned error|upstream_provider_shared_pool/i.test(lastError.message)) {
    // Same idea: keep the specific "temporarily overloaded upstream" text
    // intact instead of collapsing it into the generic rate-limit message
    // below, so the client can show its dedicated "AI Service Busy" pop-up.
  } else if (lastError.message.includes("Failed to fetch")) {
    detailedMessage = "Network Error / Timeout: the AI model dropped the connection or took too long.";
  } else if (lastError.message.includes("429")) {
    detailedMessage = "Rate Limit Exceeded: You've hit the free tier request limit. Try again in 1-2 minutes.";
  } else if (lastError.message.includes("context_length") || lastError.message.includes("token")) {
    detailedMessage = "Token Limit Exceeded: The Job Description context is too long.";
  }

  const err = new Error(detailedMessage);
  if (lastError.isFatal) err.isFatal = true;
  throw err;
}

async function verifyExamQuestions(questions, sendProgress = null, pctRange = [55, 90]) {
  let verdicts = [];
  try {
    verdicts = await callOpenRouterAI({
      model:        EXAM_VERIFY_MODEL,
      fallbackModels: [
        "poolside/laguna-s-2.1:free",
        "nvidia/nemotron-3.5-lightning:free"
      ],
      prompt:       buildExamVerificationPrompt(questions),
      maxTokens:    3500, // 15 small {id,verified,issue,suggestedCorrect} objects — trimmed down from 7000, which was ~2x more headroom than this output needs
      expectedJson: "array",
      onAttempt:    makeAttemptProgress(sendProgress, pctRange[0], pctRange[1], "Auto-verifying the answer key")
    });
  } catch (err) {
    // Verification is a nice-to-have second pass, not the deliverable —
    // the 30 questions from generateExamQuestions() already succeeded.
    // If verification itself gets rate-limited or times out, don't throw
    // that away: fall through with no verdicts, which naturally hits the
    // "did not return a result" branch below for every question. The
    // client already renders that as an amber "auto-verification
    // couldn't complete, please review manually" banner.
    console.warn("[exam-ai] Verification call failed — exam will be returned unverified:", err.message);
  }

  const verdictById = {};
  (Array.isArray(verdicts) ? verdicts : []).forEach(v => {
    if (v && v.id !== undefined) verdictById[v.id] = v;
  });

  const results = questions.map(q => {
    const v = verdictById[q.id];
    if (!v) {
      return { id: q.id, verified: false, issue: "AI verification did not return a result for this question — please review it manually.", suggestedCorrect: null };
    }
    return {
      id: q.id,
      verified: v.verified === true,
      issue: v.verified === true ? null : (v.issue || "AI flagged a possible issue but did not explain why."),
      suggestedCorrect: typeof v.suggestedCorrect === "number" ? v.suggestedCorrect : null
    };
  });

  const issuesFound = results.filter(r => !r.verified).length;
  return { verifiedAt: new Date().toISOString(), results, issuesFound };
}

// Feeds the evaluator's feedback for the flagged questions back into the
// generator so it can repair just those questions in place.
async function fixFlaggedQuestions(jdText, questions, verification, sendProgress = null) {
  const resultById = {};
  (verification.results || []).forEach(r => { resultById[r.id] = r; });

  const flagged = questions
    .filter(q => resultById[q.id] && !resultById[q.id].verified)
    .map(q => ({ ...q, issue: resultById[q.id].issue, suggestedCorrect: resultById[q.id].suggestedCorrect }));

  if (flagged.length === 0) return questions;

  const fixed = await callOpenRouterAI({
    model:        EXAM_MODEL,
    prompt:       buildExamFixPrompt(jdText, flagged),
    maxTokens:    4000,
    expectedJson: "array",
    onAttempt:    makeAttemptProgress(sendProgress, 90, 96, `Fixing ${flagged.length} flagged question(s)`)
  });

  const fixedById = {};
  (Array.isArray(fixed) ? fixed : []).forEach(f => { if (f && f.id !== undefined) fixedById[f.id] = f; });

  return questions.map(q => {
    const f = fixedById[q.id];
    if (!f) return q; // fix call didn't return this one — leave as-is, still flagged
    return {
      id:         q.id,
      question:   f.question,
      options:    f.options,
      correct:    f.correct,
      difficulty: f.difficulty || q.difficulty
    };
  });
}

// Full pipeline: generate → verify → (if issues) fix flagged questions with
// the evaluator's feedback → re-verify only those fixed questions. Capped
// at one fix round so a stubborn question can't loop forever; anything
// still flagged after that is left visible for a human to review/edit.
// sendProgress (optional) receives real stage-boundary events as the
// pipeline actually moves through it — generate → verify → (fix →
// re-verify, only if issues were found) — plus real retry-attempt ticks
// from callOpenRouterAI within each stage. Nothing here is time-based or
// interpolated: every event corresponds to an AI request actually starting
// or actually resolving.
async function generateAndVerifyExam(jdText, sendProgress = null) {
  const pipelineStart = Date.now();
  const genStart = Date.now();
  let questions = await generateExamQuestions(jdText, sendProgress);
  const genMs = Date.now() - genStart;

  if (sendProgress) sendProgress({ step: "verifying", percent: 55, message: "Auto-verifying the answer key…" });
  const verifyStart = Date.now();
  let verification = await verifyExamQuestions(questions, sendProgress, [55, 90]);
  const verifyMs = Date.now() - verifyStart;
  let fixMs = 0, reverifyMs = 0;

  if (verification.issuesFound > 0) {
    console.log(`[exam-ai] ${verification.issuesFound} question(s) flagged — sending evaluator feedback back to the generator for a fix pass...`);
    if (sendProgress) sendProgress({ step: "fixing", percent: 90, message: `Fixing ${verification.issuesFound} flagged question(s)…` });
    try {
      const fixStart = Date.now();
      const fixedQuestions = await fixFlaggedQuestions(jdText, questions, verification, sendProgress);
      fixMs = Date.now() - fixStart;

      const questionErrors = validateExamQuestions(fixedQuestions);
      if (questionErrors.length === 0) {
        questions = fixedQuestions;
        if (sendProgress) sendProgress({ step: "reverifying", percent: 96, message: "Re-verifying fixed questions…" });
        const reverifyStart = Date.now();
        verification = await verifyExamQuestions(questions, sendProgress, [96, 99]);
        reverifyMs = Date.now() - reverifyStart;
      }
      // If the fix pass produced malformed questions, keep the original
      // (still-flagged) set rather than corrupting the exam.
    } catch (err) {
      // The fix pass is also a nice-to-have on top of an already-usable
      // exam. If it fails (rate limit, timeout, etc.), keep the
      // originally-generated questions with their existing flags rather
      // than losing the whole exam — the recruiter can still edit or
      // regenerate individual flagged questions from the review screen.
      console.warn("[exam-ai] Fix pass failed — keeping original flagged questions:", err.message);
    }
  }

  console.log(`[exam-ai] Stage timings — generate: ${genMs}ms, verify: ${verifyMs}ms, fix: ${fixMs}ms, reverify: ${reverifyMs}ms, total: ${Date.now() - pipelineStart}ms`);

  if (sendProgress) sendProgress({ step: "done", percent: 100, message: "Exam ready." });
  return { questions, verification };
}

async function persistExamPool(batch, jobTitle) {
  const poolId = "pool_" + Date.now();

  await pool.query(
    `INSERT INTO exam_pools (id, employer_id, job_title, jd_text) VALUES ($1, $2, $3, $4)`,
    [poolId, batch.employerId || null, jobTitle || "General Role", batch.jdContext]
  );

  const dbIds = [];
  for (const q of batch.examQuestions) {
    const qRes = await pool.query(
      `INSERT INTO exam_questions (pool_id, question, options, correct_index, difficulty)
       VALUES ($1, $2, $3, $4, $5) RETURNING id`,
      [poolId, q.question, JSON.stringify(q.options), q.correct, q.difficulty || "medium"]
    );
    dbIds.push(qRes.rows[0].id);
  }

  batch.examQuestions.forEach((q, i) => { q.id = dbIds[i]; });
  if (batch.verification?.results) {
    batch.verification.results.forEach((r, i) => { r.id = dbIds[i]; });
  }

  await pool.query(
    `INSERT INTO batch_exams (batch_id, pool_id, selected_question_ids, is_approved)
     VALUES ($1, $2, $3, false)
     ON CONFLICT (batch_id) DO UPDATE
     SET pool_id = EXCLUDED.pool_id, selected_question_ids = EXCLUDED.selected_question_ids, updated_at = now()`,
    [batch.batchId, poolId, JSON.stringify(dbIds)]
  );

  batch.poolId = poolId;
  return poolId;
}

async function findReusableExamPool(batch) {
  const poolRes = await pool.query(
    `SELECT p.id 
     FROM exam_pools p
     JOIN batch_exams b ON p.id = b.pool_id
     WHERE p.jd_text = $1 AND b.is_approved = true 
     ORDER BY p.created_at DESC LIMIT 1`,
    [batch.jdContext]
  );
  if (poolRes.rows.length === 0) return null;

  const poolId = poolRes.rows[0].id;
  const qRes = await pool.query(
    `SELECT id, question, options, correct_index, difficulty
     FROM exam_questions WHERE pool_id = $1 ORDER BY id ASC`,
    [poolId]
  );
  // require exactly 15 — this must match the count generateExamQuestions()
  // actually enforces (build15QuestionExamPrompt + the `!== 15` check in
  // generateExamQuestions), not the old 30-question design some comments
  // elsewhere in this file still describe.
  if (qRes.rows.length !== 15) return null;

  const questions = qRes.rows.map(r => ({
    id:         r.id,
    question:   r.question,
    options:    r.options,
    correct:    r.correct_index,
    difficulty: r.difficulty
  }));

  await pool.query(
    `INSERT INTO batch_exams (batch_id, pool_id, selected_question_ids, is_approved)
     VALUES ($1, $2, $3, false)
     ON CONFLICT (batch_id) DO UPDATE
     SET pool_id = EXCLUDED.pool_id, selected_question_ids = EXCLUDED.selected_question_ids, updated_at = now()`,
    [batch.batchId, poolId, JSON.stringify(questions.map(q => q.id))]
  );

  batch.poolId = poolId;
  return questions;
}
// Applicants take a 10-question exam drawn from the full 15-question pool
// generateExamQuestions() produces (4 easy / 4 medium / 4 hard / 3 expert —
// see build15QuestionExamPrompt). Same concept as
// sampleInterviewQuestionsForCandidate()'s 5→3 draw for interview
// questions, scaled up to 15→10 here.
const EXAM_QUESTIONS_PER_CANDIDATE = 10;

// Builds a candidate's exam by drawing EXAM_QUESTIONS_PER_CANDIDATE
// questions out of the pool, keeping each difficulty bucket's share
// proportional to how it's represented in the pool (largest-remainder
// rounding, so e.g. a 4/4/4/3 pool gives a 3/3/2/2 exam rather than
// dropping a whole difficulty tier). This is computed from whatever's
// actually in the pool rather than hardcoded, so it keeps working if the
// pool's composition or size ever changes. Everything is seeded off
// candidateId (deterministic), so a reload/resume shows the same 10
// questions in the same order rather than reshuffling every request.
function sampleQuestionsForCandidate(poolQuestions, candidateId, targetCount = EXAM_QUESTIONS_PER_CANDIDATE) {
  let seed = 0;
  for (let i = 0; i < candidateId.length; i++) seed = (seed * 31 + candidateId.charCodeAt(i)) >>> 0;
  const rnd = mulberry32(seed || Date.now());

  function shuffle(arr) {
    const out = [];
    const remaining = [...arr];
    while (remaining.length) {
      const idx = Math.floor(rnd() * remaining.length);
      out.push(remaining.splice(idx, 1)[0]);
    }
    return out;
  }

  // Nothing to downsample (pool is already at or under the target) — just
  // shuffle everything, same as the old always-return-all-15 behavior.
  if (poolQuestions.length <= targetCount) {
    return shuffle(poolQuestions);
  }

  const buckets = {};
  const order = [];
  for (const q of poolQuestions) {
    const d = (q.difficulty || "medium").toLowerCase();
    if (!buckets[d]) { buckets[d] = []; order.push(d); }
    buckets[d].push(q);
  }

  // Largest-remainder method: each bucket's proportional share of
  // targetCount, rounded down, then the leftover seats go to the buckets
  // with the largest fractional remainder (order[] gives a stable,
  // deterministic tie-break).
  const raw    = order.map(d => (buckets[d].length / poolQuestions.length) * targetCount);
  const floors = raw.map(Math.floor);
  const seatsLeft = targetCount - floors.reduce((a, b) => a + b, 0);
  const byRemainder = order.map((d, i) => ({ i, rem: raw[i] - floors[i] })).sort((a, b) => b.rem - a.rem);
  for (let k = 0; k < seatsLeft; k++) floors[byRemainder[k % byRemainder.length].i]++;

  function pickFromBucket(bucket, count) {
    const available = [...bucket];
    const chosen = [];
    for (let i = 0; i < count && available.length > 0; i++) {
      const idx = Math.floor(rnd() * available.length);
      chosen.push(available.splice(idx, 1)[0]);
    }
    return chosen;
  }

  const selected = [];
  let stillNeeded = 0;
  order.forEach((d, i) => {
    const need = floors[i];
    const take = Math.min(need, buckets[d].length);
    selected.push(...pickFromBucket(buckets[d], take));
    stillNeeded += need - take;
  });

  // Fill any shortage (a bucket didn't have enough questions for its
  // target share) from whatever's left over in the pool — same fallback
  // sampleInterviewQuestionsForCandidate() uses.
  const remaining = poolQuestions.filter(q => !selected.includes(q));
  while (stillNeeded > 0 && remaining.length > 0) {
    const idx = Math.floor(rnd() * remaining.length);
    selected.push(remaining.splice(idx, 1)[0]);
    stillNeeded--;
  }

  // Final shuffle so the chosen questions aren't grouped by the order
  // difficulty buckets were picked in.
  return shuffle(selected).slice(0, targetCount);
}
app.post("/api/batches/:batchId/generate-exam", async (req, res) => {
  const { batchId } = req.params;
  const { jobTitle } = req.body || {};
  const batch = global.batchesStore[batchId];

  if (!batch) {
    return res.status(404).json({ error: "Batch not found." });
  }

  batch.status = "generating";

  // Streamed NDJSON response: real stage/attempt events as they actually
  // happen (or a single fast "reused" jump to 100% on the pool-reuse path),
  // then a final "result" line.
  res.setHeader("Content-Type", "application/x-ndjson; charset=utf-8");
  res.setHeader("X-Accel-Buffering", "no");
  res.flushHeaders && res.flushHeaders();
  const sendProgress = (obj) => {
    try { res.write(JSON.stringify({ type: "progress", ...obj }) + "\n"); }
    catch (e) { console.warn("[generate-exam stream] write failed:", e.message); }
  };

  try {
    sendProgress({ step: "checking_reuse", percent: 3, message: "Checking for a reusable verified exam…" });
    const reused = await findReusableExamPool(batch);
    if (reused) {
      batch.examQuestions = reused;
      batch.status        = "generated";
      batch.isVerified     = true;
      batch.verifiedAt     = new Date().toISOString();
      batch.verification   = {
        verifiedAt: batch.verifiedAt,
        results:    reused.map(q => ({ id: q.id, verified: true, issue: null, suggestedCorrect: null })),
        issuesFound: 0,
        reused:      true
      };
      await persistBatch(batchId);

      console.log(`[batch-exam] ✓ Reused existing exam pool ${batch.poolId} for ${batchId}`);
      sendProgress({ step: "done", percent: 100, message: "Reused a previously verified exam." });
      res.write(JSON.stringify({ type: "result", payload: {
        success: true,
        message: "Reused a previously generated & verified exam for this job description.",
        questions: reused,
        verification: batch.verification,
        status: batch.status
      } }) + "\n");
      return res.end();
    }

    console.log(`[batch-exam] Generating & auto-verifying exam for ${batchId}...`);
    const { questions, verification } = await generateAndVerifyExam(batch.jdContext, sendProgress);

    batch.examQuestions = questions;
    batch.verification  = verification;
    batch.status = "generated";
    batch.isVerified = true;
    batch.verifiedAt = new Date().toISOString();

    try {
      await persistExamPool(batch, jobTitle);
      console.log(`[batch-exam] ✓ Saved exam pool ${batch.poolId} to database for reuse`);
    } catch (dbErr) {
      console.error(`[batch-exam] Warning: failed to save exam pool to database:`, dbErr.message);
    }
    await persistBatch(batchId);

    console.log(`[batch-exam] ✓ Generation & auto-verification complete for ${batchId} (${verification.issuesFound} still flagged)`);
    res.write(JSON.stringify({ type: "result", payload: {
      success: true,
      message: "Exam successfully generated and verified automatically.",
      questions: batch.examQuestions,
      verification: batch.verification,
      status: batch.status
    } }) + "\n");
    return res.end();
  } catch (error) {
    console.error(`[batch-exam] Error during auto-generation/verification:`, error);
    batch.status = "matched";
    await persistBatch(batchId);
    try {
      res.write(JSON.stringify({ type: "result", success: false, error: `Failed to generate and verify exam with AI: ${error.message}` }) + "\n");
    } catch (e) {}
    return res.end();
  }
});

app.post("/api/batches/:batchId/verify-exam", async (req, res) => {
  const batch = global.batchesStore[req.params.batchId];
  if (!batch) return res.status(404).json({ error: "Batch not found." });
  if (!batch.examQuestions?.length) return res.status(400).json({ error: "No exam generated for this batch yet — generate one first." });

  console.log(`[batch-exam] Retrying verification for ${batch.examQuestions.length} questions, batch: ${batch.batchId}`);
  try {
    // Manual recovery path (only shown when the automatic verification
    // inside "generate-exam" itself failed to complete). Re-verify, and if
    // that turns up flagged questions, still route the feedback back into
    // the generator for a fix pass rather than leaving them for a human to
    // fix by hand.
    let verification = await verifyExamQuestions(batch.examQuestions);
    if (verification.issuesFound > 0) {
      const fixed = await fixFlaggedQuestions(batch.jdContext, batch.examQuestions, verification);
      if (validateExamQuestions(fixed).length === 0) {
        batch.examQuestions = fixed;
        verification = await verifyExamQuestions(fixed);
      }
    }
    batch.verification = verification;
    await persistBatch(batch.batchId);
    console.log(`[batch-exam] ✓ Verification complete for batch ${batch.batchId}: ${batch.verification.issuesFound}/${batch.verification.results.length} flagged`);
    return res.json({ success: true, verification: batch.verification, questions: batch.examQuestions });
  } catch (err) {
    console.error("[batch-exam/verify] Error:", err.message);
    return res.status(500).json({ error: `Failed to verify batch exam: ${err.message}` });
  }
});

app.post("/api/batches/:batchId/approve-exam", async (req, res) => {
  const batch = global.batchesStore[req.params.batchId];
  if (!batch) return res.status(404).json({ error: "Batch not found." });
  if (!batch.examQuestions?.length) return res.status(400).json({ error: "No exam generated for this batch yet." });
  if (!batch.verification) return res.status(400).json({ error: "This exam hasn't been successfully verified yet. Please retry verification before approving/deploying it." });

  batch.isApproved = true;
  batch.approvedAt = new Date().toISOString();
  await persistBatch(batch.batchId);

  try {
    await pool.query(
      `UPDATE batch_exams SET is_approved = true, updated_at = now() WHERE batch_id = $1`,
      [batch.batchId]
    );
  } catch (dbErr) {
    console.error("[batch-exam] DB approval update failed:", dbErr.message);
  }

  // MATCH-GATE: don't deploy to candidates the AI recommended rejecting —
  // see isRejectedCandidate(). Their examStatus is left untouched (stays
  // "pending"), and the exam endpoints below independently re-check
  // eligibility so this can't be bypassed by a stale/tampered examStatus.
  let deployedCount = 0;
  let skippedRejected = 0;
  for (const cand of Object.values(global.candidatesStore)) {
    if (cand.batchId === batch.batchId) {
      if (isRejectedCandidate(cand)) {
        skippedRejected++;
        continue;
      }
      cand.examStatus = "ready_to_take";
      await persistCandidate(cand.id);
      deployedCount++;
    }
  }

  console.log(`[batch-exam] ✓ Approved & deployed batch ${batch.batchId} to ${deployedCount} candidate(s) (${skippedRejected} low-match candidate(s) skipped)`);
  return res.json({
    success: true,
    message: `Exam approved and deployed to ${deployedCount} applicant(s).${skippedRejected ? ` (${skippedRejected} low-match applicant(s) were not given exam access.)` : ""}`,
    deployedCount,
    skippedRejected
  });
});

app.get("/api/batches/:batchId", (req, res) => {
  const batch = global.batchesStore[req.params.batchId];
  if (!batch) return res.status(404).json({ error: "Batch not found." });

  const candidateCount = Object.values(global.candidatesStore).filter(c => c.batchId === batch.batchId).length;

  return res.json({
    success: true,
    batch: {
      batchId:        batch.batchId,
      isApproved:     !!batch.isApproved,
      examQuestions:  batch.examQuestions || null,
      verification:   batch.verification || null,
      candidateCount,
      createdAt:      batch.createdAt,
      approvedAt:     batch.approvedAt
    }
  });
});

app.get("/api/batches/:batchId/exam", (req, res) => {
  const batch = global.batchesStore[req.params.batchId];
  if (!batch) return res.status(404).json({ error: "Batch not found." });

  const { candidateId } = req.query;
  if (!candidateId) return res.status(400).json({ error: "Missing candidateId." });

  const candidate = global.candidatesStore[candidateId];
  if (!candidate) return res.status(404).json({ error: "Candidate not found." });
  if (candidate.batchId !== batch.batchId)
    return res.status(403).json({ error: "This exam is not associated with your application." });

  if (candidate.examStatus === "completed")
    return res.status(409).json({ error: "You have already completed this exam.", alreadyCompleted: true, score: candidate.examScore });

  // MATCH-GATE: re-check eligibility here too, independent of examStatus —
  // examStatus is just a cached convenience flag and shouldn't be the only
  // gate keeping a low-match candidate out of an exam they were never
  // supposed to see (see isRejectedCandidate() and the approve-exam route).
  if (isRejectedCandidate(candidate))
    return res.status(403).json({ error: "This application is not eligible for the skills exam." });

  if (!batch.isApproved || !batch.examQuestions?.length)
    return res.status(403).json({ error: "This exam has not been deployed yet. Please check back once HR has approved it." });

  // Each candidate gets EXAM_QUESTIONS_PER_CANDIDATE (10) questions drawn
  // from the full 15-question pool (see sampleQuestionsForCandidate).
  const poolQuestions = batch.examQuestions;
  if (!Array.isArray(poolQuestions) || poolQuestions.length < 15) {
    return res.status(500).json({ error: "Invalid exam pool (not enough questions)." });
  }

  const chosen = sampleQuestionsForCandidate(poolQuestions, candidateId);

  const clientSafe = chosen.map(q => ({ id: q.id, question: q.question, options: q.options }));
  return res.json({ success: true, batchId: batch.batchId, questions: clientSafe });
});

app.post("/api/batches/:batchId/submit", async (req, res) => {
  const batch = global.batchesStore[req.params.batchId];
  if (!batch) return res.status(404).json({ error: "Batch not found." });

  const { candidateId, answers } = req.body || {};
  if (!candidateId) return res.status(400).json({ error: "Missing candidateId." });

  const candidate = global.candidatesStore[candidateId];
  if (!candidate) return res.status(404).json({ error: "Candidate not found." });
  if (candidate.batchId !== batch.batchId)
    return res.status(403).json({ error: "This exam is not associated with your application." });
  if (candidate.examStatus === "completed")
    return res.status(409).json({ error: "You have already submitted this exam.", alreadyCompleted: true, score: candidate.examScore });
  // MATCH-GATE: same eligibility re-check as the GET /exam route — don't
  // grade/accept a submission from a candidate who was never supposed to
  // have gotten the questions in the first place.
  if (isRejectedCandidate(candidate))
    return res.status(403).json({ error: "This application is not eligible for the skills exam." });
  if (!batch.isApproved || !batch.examQuestions?.length)
    return res.status(400).json({ error: "This exam has not been deployed yet." });

  // Note: applicants only receive EXAM_QUESTIONS_PER_CANDIDATE (10) of the
  // 15 pooled questions (see sampleQuestionsForCandidate), so grading walks
  // the full batch.examQuestions pool but counts only those question IDs
  // actually present in `answers` — i.e. the 10 that candidate was shown.
  // scorePercent below is already out of however many were answered, so
  // this naturally scores out of 10, not 15.
  let correctCount = 0;
  let totalCount = 0;
  const gradedDetails = [];

  // Build a map for quick lookup
  const qById = {};
  for (const q of batch.examQuestions) qById[String(q.id)] = q;

  for (const qid of Object.keys(answers || {})) {
    const q = qById[qid];
    if (!q) continue; // ignore unexpected ids
    const submitted = parseInt(answers?.[qid]);
    const passed    = submitted === q.correct;
    if (passed) correctCount++;
    totalCount++;
    gradedDetails.push({ id: q.id, question: q.question, options: q.options, submitted, correct: q.correct, passed });
  }

  // If for some reason zero answers were submitted, respond with error
  if (totalCount === 0) {
    return res.status(400).json({ error: "No answers submitted." });
  }

  const scorePercent = Math.round((correctCount / totalCount) * 100);

  candidate.examStatus  = "completed";
  candidate.examScore   = scorePercent;
  candidate.examAnswers = answers;
  candidate.examDetails = gradedDetails;
  await persistCandidate(candidateId);

  console.log(`[batch-exam] ✓ ${candidate.name || candidateId} scored ${scorePercent}% (${correctCount}/${totalCount}) on batch ${batch.batchId}`);
  return res.json({ success: true, score: scorePercent, correct: correctCount, total: totalCount, passed: scorePercent >= 60 });
});


// =============================================================================
// GLOBAL ERROR HANDLER & SERVER START
// =============================================================================
app.use((err, req, res, next) => {
  console.error("[global error handler]", err.message);
  if (!res.headersSent)
    res.status(500).json({ error: err.message || "Server error" });
});

// Applies schema.sql against the connected Postgres database on every boot.
// Every statement in schema.sql is written with "IF NOT EXISTS" / "ADD
// COLUMN IF NOT EXISTS", so this is safe to run on a fresh DB, a DB that
// already has some (but not all) tables, or a DB that's fully up to date —
// it only creates what's missing. This removes the need to manually run
// schema.sql via psql/a DB console after every deploy, which is what caused
// "relation exam_drafts does not exist" the first time this table was added.
async function runMigrations() {
  const schemaPath = path.join(__dirname, "schema.sql");
  let sql;
  try {
    sql = fs.readFileSync(schemaPath, "utf8");
  } catch (e) {
    console.error(`[migrations] Could not read schema.sql at ${schemaPath}: ${e.message}`);
    console.error(`[migrations] Skipping migrations — make sure schema.sql is deployed alongside server.js.`);
    return;
  }

  try {
    // A plain pool.query(text) with no params uses Postgres's simple query
    // protocol, which allows multiple ';'-separated statements in one call.
    await pool.query(sql);
    console.log(`[migrations] schema.sql applied successfully.`);
  } catch (e) {
    console.error(`[migrations] Failed to apply schema.sql: ${e.message}`);
    console.error(`[migrations] The app will still start, but queries against missing tables/columns will fail until this is fixed.`);
  }
}

app.listen(PORT, async () => {
  console.log(`\nAI Recruitment Assistant → http://localhost:${PORT}`);
  console.log(`Health check            → http://localhost:${PORT}/api/health`);
  console.log(`PDF parser              → pdf-parse v2 (PDFParse class)`);
  console.log(`Postgres                → ${pool.options.user}@${pool.options.host}:${pool.options.port}/${pool.options.database}\n`);
  await runMigrations();
  await rehydrateStores();
});
