import mongoose from 'mongoose';

const linkSchema = new mongoose.Schema({
  label: { type: String, required: true },
  url:   { type: String, required: true },
  type:  { type: String, default: 'youtube' }   // 'youtube' | 'article' | 'pdf' | etc.
}, { _id: false });

const chapterSchema = new mongoose.Schema({
  title: { type: String, required: true },
  links: [linkSchema]
}, { _id: false });

const courseSchema = new mongoose.Schema({
  courseId: { type: String, required: true, unique: true },
  title:    { type: String, required: true },
  desc:     { type: String, default: '' },
  icon:     { type: String, default: 'fa-book' },     // FontAwesome icon class
  color:    { type: String, default: '#666666' },      // Hex color
  weeks:    { type: Number, default: 4 },
  active:   { type: Boolean, default: true },
  order:    { type: Number, default: 0 },
  chapters: [chapterSchema],
  created_at: { type: Date, default: Date.now },
  updated_at: { type: Date, default: Date.now }
});

courseSchema.index({ active: 1, order: 1 });

export default mongoose.models.Course || mongoose.model('Course', courseSchema);
