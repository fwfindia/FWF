// Temporary one-time endpoint to fix quiz winner via Vercel (bypasses Railway)
// DELETE this file after use
import { connectDB } from '../../lib/db.js';
import mongoose from 'mongoose';

export default async function handler(req, res) {
  if (req.method !== 'POST') return res.status(405).json({ error: 'POST only' });

  // Simple secret guard — pass as ?secret=ADMIN_FIX_2026 in query
  if (req.query.secret !== 'ADMIN_FIX_2026') {
    return res.status(403).json({ error: 'Forbidden' });
  }

  const { quizId, enrollmentNumber } = req.body || {};
  if (!quizId || !enrollmentNumber) {
    return res.status(400).json({ error: 'quizId and enrollmentNumber required' });
  }

  try {
    await connectDB();

    const db = mongoose.connection.db;

    // Find the quiz
    const quiz = await db.collection('quizzes').findOne({ quiz_id: quizId });
    if (!quiz) return res.status(404).json({ error: 'Quiz not found' });

    // Find the new winner's participation
    const newWinnerPart = await db.collection('quizparticipations').findOne({ enrollment_number: enrollmentNumber });
    if (!newWinnerPart) return res.status(404).json({ error: 'Enrollment not found: ' + enrollmentNumber });
    if (newWinnerPart.quiz_ref !== quizId) return res.status(400).json({ error: 'Enrollment belongs to different quiz' });

    const prizeAmount = quiz.prizes?.first || 0;

    // Find user details
    const newWinnerUser = await db.collection('users').findOne({ _id: newWinnerPart.user_id });

    // Reverse old winner wallet
    const oldWinner = quiz.winners?.[0];
    if (oldWinner?.user_id) {
      await db.collection('users').updateOne(
        { _id: oldWinner.user_id },
        { $inc: { 'wallet.balance_inr': -prizeAmount, 'wallet.lifetime_earned_inr': -prizeAmount } }
      );
      await db.collection('pointsledgers').insertOne({
        user_id: oldWinner.user_id,
        type: 'adjustment',
        points: -prizeAmount,
        description: `🔄 Winner overridden — ${quiz.title} (Admin Fix)`,
        reference_id: String(quizId),
        created_at: new Date()
      });
    }

    // Reset old winner participation status
    await db.collection('quizparticipations').updateMany(
      { quiz_ref: quizId, status: 'won' },
      { $set: { status: 'lost', prize_won: 0 } }
    );

    // Credit new winner wallet
    if (prizeAmount > 0 && newWinnerUser) {
      await db.collection('users').updateOne(
        { _id: newWinnerUser._id },
        { $inc: { 'wallet.balance_inr': prizeAmount, 'wallet.lifetime_earned_inr': prizeAmount } }
      );
      await db.collection('pointsledgers').insertOne({
        user_id: newWinnerUser._id,
        type: 'quiz_prize',
        points: prizeAmount,
        description: `🎉 Lucky Draw Winner (Admin Override) — ${quiz.title}`,
        reference_id: String(quizId),
        created_at: new Date()
      });
    }

    // Mark new winner participation
    await db.collection('quizparticipations').updateOne(
      { enrollment_number: enrollmentNumber },
      { $set: { status: 'won', prize_won: prizeAmount } }
    );

    // Update quiz winners array
    const newWinner = {
      rank: 1,
      user_id: newWinnerPart.user_id,
      member_id: newWinnerUser?.member_id || newWinnerPart.member_id || '',
      name: newWinnerUser?.name || newWinnerPart.name || 'Unknown',
      enrollment_number: newWinnerPart.enrollment_number,
      prize_amount: prizeAmount,
      score: newWinnerPart.score || 0
    };

    await db.collection('quizzes').updateOne(
      { quiz_id: quizId },
      { $set: { winners: [newWinner] } }
    );

    console.log(`✅ Winner fixed: ${quizId} → ${newWinner.name} (${newWinner.member_id})`);

    return res.json({
      ok: true,
      message: `Winner changed to ${newWinner.name} (${newWinner.member_id}) for quiz ${quizId}`,
      winner: newWinner,
      prizeAmount
    });
  } catch (err) {
    console.error('fix-winner error:', err);
    return res.status(500).json({ error: err.message });
  }
}
