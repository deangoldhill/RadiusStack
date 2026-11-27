const fs = require('node:fs/promises');
const os = require('node:os');
const path = require('node:path');
const multer = require('multer');

// Decimal MB for the manual JSON upload restore ceiling.
const MAX_BACKUP_BYTES = 700000000;
const RESTORE_TIMEOUT_MS = 60 * 60 * 1000;

function createRestoreUpload({maxBytes = MAX_BACKUP_BYTES} = {}) {
    const storage = multer.diskStorage({
        destination(req, file, callback) {
            fs.mkdtemp(path.join(os.tmpdir(), 'radiusstack-upload-')).then(directory => {
                req.backupUploadDirectory = directory;
                callback(null, directory);
            }, callback);
        },
        filename(req, file, callback) { callback(null, 'backup.json'); }
    });
    // Busboy signals its limit at equality; allow one sentinel byte, then check size.
    const upload = multer({storage, limits: {fileSize: maxBytes + 1, files: 1, fields: 0}}).single('backup');
    return (req, res, next) => {
        req.setTimeout?.(RESTORE_TIMEOUT_MS);
        res.setTimeout?.(RESTORE_TIMEOUT_MS);
        const cleanup = () => {
            if (req.backupUploadDirectory) {
                fs.rm(req.backupUploadDirectory, {recursive: true, force: true})
                    .catch(error => console.error('[Restore] Upload cleanup failed:', error.code));
            }
        };
        res.once('finish', cleanup);
        res.once('close', cleanup);
        upload(req, res, error => {
            if (error) {
                cleanup();
                const tooLarge = error.code === 'LIMIT_FILE_SIZE';
                return res.status(tooLarge ? 413 : 400).json({error: tooLarge
                    ? `Backup exceeds the ${maxBytes} byte upload limit (700 MB maximum).`
                    : 'Invalid backup upload: upload one JSON file in the backup field.'});
            }
            next();
        });
    };
}
module.exports = {createRestoreUpload, MAX_BACKUP_BYTES, RESTORE_TIMEOUT_MS};
