#include "../networking/cJSON.h"

vfs_drive_t *fs_get_root_drive (void);
vfs_drive_t *fs_get_sd_drive (void);
vfs_drive_t *fs_get_flash_drive (void);
const char *fs_action_handler (http_request_t *request, vfs_drive_t *drive);
const char *fs_download_handler (http_request_t *request, vfs_drive_t *drive);
const char *fs_upload_handler (http_request_t *request, vfs_drive_t *drive);
bool fs_ls (cJSON *root, char *path, char *status, vfs_drive_t *drive);
