import express from 'express';
import multer from 'multer';
import { uploadMaintenancePhotos } from '../controllers/maintenancePhotoController.js';
import { authenticate } from '../middleware/auth.js';
import { requirePolicy } from '../middleware/requirePolicy.js';
import { userLimiter } from '../middleware/rateLimiter.js';

const router = express.Router();

// Photos only — the controller re-checks the actual bytes, but rejecting on
// the declared type here avoids buffering 8MB of non-image content first.
// Keep this list aligned with the controller's ALLOWED_PHOTO_MIME_TYPES
// (JPEG/PNG only). Do NOT derive it from ALLOWED_DOCUMENT_MIME_TYPES: that
// shared list may grow to include webp/heic/pdf, which the controller
// rejects, and deriving would silently re-introduce the buffering-then-422
// gap (see #10961).
const ALLOWED_PHOTO_MIME_TYPES = Object.freeze(['image/jpeg', 'image/png']);

const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 8 * 1024 * 1024 },
  fileFilter: (_req, file, cb) => {
    // Reject disallowed types with a real MulterError so the client gets a
    // clear "unsupported type" message and the bytes are never buffered.
    // cb(null, false) would silently drop the file and let the controller
    // return the misleading "At least one photo file is required" (#10961).
    if (!ALLOWED_PHOTO_MIME_TYPES.includes(file.mimetype)) {
      const allowed = ALLOWED_PHOTO_MIME_TYPES.join(', ');
      const error = new multer.MulterError('LIMIT_UNEXPECTED_FILE', file.fieldname);
      error.message = `Unsupported photo type: ${file.mimetype}. Only ${allowed} are accepted.`;
      return cb(error);
    }
    cb(null, true);
  },
});

// POST /api/maintenance/:ticketId/photos
router.post(
  '/:ticketId/photos',
  authenticate,
  userLimiter,
  requirePolicy('maintenance:upload-photos'),
  upload.array('photos', 3),
  uploadMaintenancePhotos,
);

export default router;
