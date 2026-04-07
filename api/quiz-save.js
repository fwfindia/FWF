import { withSentry } from "../lib/sentry.js";
import { connectDB } from "../lib/db.js";
import mongoose from "mongoose";

const quizQuestionSchema = new mongoose.Schema(
  {
    q_no: Number,
    question: String,
    options: [String],
    correct_answer: Number,
    points: { type: Number, default: 1 }
  },
  { _id: false }
);

const quizSchema = new mongoose.Schema(
  {
    quiz_id: { type: String, unique: true, required: true },
    title: { type: String, required: true },
    game_type: {
      type: String,
      enum: ["mcq", "true_false", "picture", "speed", "puzzle", "general"],
      default: "mcq"
    },
    entry_fee: { type: Number, required: true },
    questions: [quizQuestionSchema]
  },
  { strict: false }
);

const Quiz = mongoose.models.Quiz || mongoose.model("Quiz", quizSchema);

function send(res, code, ok, payload) {
  return res.status(code).json(ok ? { ok: true, ...payload } : { ok: false, error: payload.error });
}

function normalizeQuestions(input) {
  if (!Array.isArray(input)) return [];
  return input
    .filter(q => q && typeof q.question === "string" && Array.isArray(q.options) && q.options.length === 4)
    .map((q, idx) => ({
      q_no: idx + 1,
      question: String(q.question).trim(),
      options: q.options.map(o => String(o).trim()),
      correct_answer: Number.isInteger(q.correct_answer) ? Math.max(0, Math.min(3, q.correct_answer)) : 0,
      points: Number(q.points) > 0 ? Number(q.points) : 1
    }));
}

async function verifyAdminByCookie(cookieHeader) {
  if (!cookieHeader) return false;
  try {
    const probe = await fetch("https://fwf-production.up.railway.app/api/admin/overview", {
      method: "GET",
      headers: { Cookie: cookieHeader }
    });
    return probe.ok;
  } catch {
    return false;
  }
}

export default withSentry(async function handler(req, res) {
  if (req.method !== "POST") return send(res, 405, false, { error: "Method not allowed" });

  const isAdmin = await verifyAdminByCookie(req.headers.cookie || "");
  if (!isAdmin) return send(res, 401, false, { error: "Unauthorized" });

  const { quizId, title, game_type, entry_fee, questions } = req.body || {};
  if (!quizId) return send(res, 400, false, { error: "quizId is required" });

  const normalizedQuestions = normalizeQuestions(questions);
  if (!normalizedQuestions.length) {
    return send(res, 400, false, { error: "Questions must contain valid MCQ items" });
  }

  try {
    await connectDB();
    const quiz = await Quiz.findOne({ quiz_id: String(quizId) });
    if (!quiz) return send(res, 404, false, { error: "Quiz not found" });

    if (typeof title === "string") quiz.title = title.trim();
    if (typeof game_type === "string") quiz.game_type = game_type;
    if (entry_fee !== undefined && Number(entry_fee) >= 0) quiz.entry_fee = Number(entry_fee);
    quiz.questions = normalizedQuestions;

    await quiz.save();
    return send(res, 200, true, { quiz });
  } catch (err) {
    console.error("quiz-save error:", err);
    return send(res, 500, false, { error: `Failed to save quiz: ${err.message}` });
  }
});
