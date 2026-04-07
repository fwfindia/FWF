import { withSentry } from "../lib/sentry.js";

function bad(res, code, message) {
  return res.status(code).json({ ok: false, error: message });
}

function cleanText(v) {
  return String(v || "").trim();
}

function normalizeOption(v) {
  return cleanText(v).replace(/\s+/g, " ");
}

function normalizeQuestionList(input, maxCount) {
  const list = Array.isArray(input) ? input : [];
  const unique = new Set();
  const out = [];

  for (const item of list) {
    if (!item || typeof item.question !== "string" || !Array.isArray(item.options) || item.options.length !== 4) continue;

    const question = cleanText(item.question);
    if (!question) continue;
    const qKey = question.toLowerCase();
    if (unique.has(qKey)) continue;

    const options = item.options.map(normalizeOption);
    if (options.some(o => !o)) continue;
    const optionSet = new Set(options.map(o => o.toLowerCase()));
    if (optionSet.size !== 4) continue;

    let correct = Number.isInteger(item.correct_answer) ? item.correct_answer : 0;

    // If model provides answer text, trust exact match over index.
    const correctText = cleanText(item.correct_answer_text || "");
    if (correctText) {
      const idx = options.findIndex(o => o.toLowerCase() === correctText.toLowerCase());
      if (idx >= 0) correct = idx;
    }

    correct = Math.max(0, Math.min(3, Number(correct) || 0));

    unique.add(qKey);
    out.push({
      q_no: out.length + 1,
      question,
      options,
      correct_answer: correct,
      points: Number(item.points) > 0 ? Number(item.points) : 1
    });

    if (out.length >= maxCount) break;
  }

  return out;
}

async function openAIJson({ apiKey, model, messages, temperature = 0.2, max_tokens = 2400 }) {
  const resp = await fetch("https://api.openai.com/v1/chat/completions", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "Authorization": `Bearer ${apiKey}`
    },
    body: JSON.stringify({ model, messages, temperature, max_tokens })
  });

  const data = await resp.json();
  if (!resp.ok || data?.error) {
    throw new Error(data?.error?.message || "AI generation failed");
  }

  let raw = data?.choices?.[0]?.message?.content || "";
  raw = raw.replace(/```json/gi, "").replace(/```/g, "").trim();
  return JSON.parse(raw);
}

export default withSentry(async function handler(req, res) {
  if (req.method !== "POST") return bad(res, 405, "Method not allowed");

  const apiKey = process.env.OPENAI_API_KEY;
  if (!apiKey) return bad(res, 500, "OPENAI_API_KEY not configured");

  const {
    difficulty = "medium",
    count = 10,
    language = "hi"
  } = req.body || {};

  const safeCount = Math.min(20, Math.max(5, Number(count) || 10));
  const langHint = language === "en" ? "English" : "Hindi";
  const minRelationship = Math.max(3, Math.floor(safeCount * 0.35));

  const generationPrompt = `Create ${safeCount} high-quality multiple-choice quiz questions.\nDifficulty: ${difficulty}.\nLanguage: ${langHint}.\n\nAllowed categories only:\n1) General Knowledge (India/world GK, civics, history, geography, basic current affairs)\n2) Relationship Logic (blood relation and family relation reasoning)\n\nMandatory distribution:\n- At least ${minRelationship} questions must be Relationship Logic.\n- Remaining can be GK only.\n- Do not include math-only, physics-only, coding, or unrelated aptitude categories.\n\nRules:\n1) Exactly 4 options per question.\n2) Exactly one option must be unquestionably correct.\n3) Avoid ambiguous or partially-correct options.\n4) Keep questions practical and exam-like for scholarship quizzes.\nReturn strict JSON only in this format:\n{"questions":[{"question":"...","options":["A","B","C","D"],"correct_answer":1,"correct_answer_text":"B","points":1}]}`;

  try {
    const model = process.env.OPENAI_MODEL || "gpt-4o-mini";

    const firstPass = await openAIJson({
      apiKey,
      model,
      messages: [
        { role: "system", content: "You are a quiz setter. Return valid JSON only." },
        { role: "user", content: generationPrompt }
      ],
      temperature: 0.5,
      max_tokens: 2400
    });

    let questions = normalizeQuestionList(firstPass?.questions, safeCount);
    if (!questions.length) return bad(res, 502, "AI did not return usable questions");

    // Second pass: verify answer tags and fix ambiguous/wrongly keyed items.
    const verifierPrompt = `You are a strict quiz auditor. Validate each question and correct wrong answer index if needed.\nIf a question is ambiguous or has no clearly correct option, rewrite that question so exactly one option is correct.\nKeep language: ${langHint}. Keep difficulty: ${difficulty}.\nReturn strict JSON only in this format:\n{"questions":[{"question":"...","options":["A","B","C","D"],"correct_answer":1,"correct_answer_text":"B","points":1}]}`;

    try {
      const verified = await openAIJson({
        apiKey,
        model,
        messages: [
          { role: "system", content: "You validate objective correctness and return JSON only." },
          { role: "user", content: verifierPrompt },
          { role: "user", content: JSON.stringify({ questions }) }
        ],
        temperature: 0.1,
        max_tokens: 2600
      });

      const verifiedQuestions = normalizeQuestionList(verified?.questions, safeCount);
      if (verifiedQuestions.length >= Math.max(5, Math.floor(safeCount * 0.7))) {
        questions = verifiedQuestions;
      }
    } catch {
      // Keep first-pass output if verifier fails.
    }

    if (questions.length < Math.min(5, safeCount)) {
      return bad(res, 502, "AI did not return enough valid questions. Please retry.");
    }

    return res.status(200).json({ ok: true, questions: questions.slice(0, safeCount) });
  } catch (err) {
    console.error("quiz-ai-generate error:", err);
    return bad(res, 500, "Failed to generate AI quiz questions");
  }
});
