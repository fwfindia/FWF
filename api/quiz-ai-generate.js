import { withSentry } from "../lib/sentry.js";

function bad(res, code, message) {
  return res.status(code).json({ ok: false, error: message });
}

export default withSentry(async function handler(req, res) {
  if (req.method !== "POST") return bad(res, 405, "Method not allowed");

  const apiKey = process.env.OPENAI_API_KEY;
  if (!apiKey) return bad(res, 500, "OPENAI_API_KEY not configured");

  const {
    topic = "Scholarship aptitude and reasoning",
    difficulty = "medium",
    count = 10,
    includeRelationshipLogic = false,
    language = "hi"
  } = req.body || {};

  const safeCount = Math.min(20, Math.max(5, Number(count) || 10));
  const langHint = language === "en" ? "English" : "Hindi";
  const relationHint = includeRelationshipLogic
    ? "Include at least 2 relationship/blood-relation logic questions."
    : "Relationship-logic questions are optional.";

  const prompt = `Create ${safeCount} multiple-choice quiz questions for: ${topic}.\nDifficulty: ${difficulty}.\nLanguage: ${langHint}.\n${relationHint}\nEach question must have exactly 4 options and one correct option index (0-3).\nReturn strict JSON only in this format:\n{"questions":[{"question":"...","options":["A","B","C","D"],"correct_answer":1,"points":1}]}`;

  try {
    const aiRes = await fetch("https://api.openai.com/v1/chat/completions", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "Authorization": `Bearer ${apiKey}`
      },
      body: JSON.stringify({
        model: process.env.OPENAI_MODEL || "gpt-4o-mini",
        messages: [
          { role: "system", content: "You are a quiz setter. Return valid JSON only." },
          { role: "user", content: prompt }
        ],
        temperature: 0.7,
        max_tokens: 2200
      })
    });

    const aiData = await aiRes.json();
    if (!aiRes.ok || aiData?.error) {
      return bad(res, 502, aiData?.error?.message || "AI generation failed");
    }

    let raw = aiData?.choices?.[0]?.message?.content || "";
    raw = raw.replace(/```json/gi, "").replace(/```/g, "").trim();

    let parsed;
    try {
      parsed = JSON.parse(raw);
    } catch {
      return bad(res, 502, "AI returned invalid JSON. Try again.");
    }

    const generated = Array.isArray(parsed?.questions) ? parsed.questions : [];
    const questions = generated
      .filter(q => q && typeof q.question === "string" && Array.isArray(q.options) && q.options.length === 4)
      .slice(0, safeCount)
      .map((q, idx) => ({
        q_no: idx + 1,
        question: String(q.question).trim(),
        options: q.options.map(o => String(o).trim()),
        correct_answer: Number.isInteger(q.correct_answer) ? Math.max(0, Math.min(3, q.correct_answer)) : 0,
        points: Number(q.points) > 0 ? Number(q.points) : 1
      }));

    if (!questions.length) return bad(res, 502, "AI did not return usable questions");

    return res.status(200).json({ ok: true, questions });
  } catch (err) {
    console.error("quiz-ai-generate error:", err);
    return bad(res, 500, "Failed to generate AI quiz questions");
  }
});
